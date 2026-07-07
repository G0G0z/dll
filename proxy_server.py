#!/usr/bin/env python3
"""
proxy_server.py — PointBlank Gerçek Zamanlı Proxy Sunucusu
============================================================
DLL'den gelen şifreli paketleri anlık çözer, tarayıcıda gösterir.
Tarayıcıdan özel paket gönderilebilir (inject).

Kullanım:
  python proxy_server.py [--crypto pb_crypto.log] [--port 5000]
"""
import asyncio, json, struct, re, time, argparse, glob
from aiohttp import web
import aiohttp

# ─── Blowfish (PointBlank özel varyant: per-round swap YOK) ──────────────────

def _bf_enc(P, S, L, R):
    for i in range(16):
        L ^= P[i]
        a=(L>>24)&0xFF; b=(L>>16)&0xFF; c=(L>>8)&0xFF; d=L&0xFF
        t=((S[0][a]+S[1][b])&0xFFFFFFFF)^S[2][c]
        t=(t+S[3][d])&0xFFFFFFFF
        R ^= t                          # per-round swap YOK
    L, R = R, L                         # sonda tek swap
    return (L^P[16])&0xFFFFFFFF, (R^P[17])&0xFFFFFFFF

def _cfb64(P, S, data, iv_bytes, encrypt, n_in=0):
    iv = bytearray(iv_bytes)
    out = bytearray(len(data))
    n = n_in
    for i, byte in enumerate(data):
        if n == 0:
            v0 = struct.unpack_from('<I', iv, 0)[0]
            v1 = struct.unpack_from('<I', iv, 4)[0]
            e0, e1 = _bf_enc(P, S, v0, v1)
            struct.pack_into('<I', iv, 0, e0)
            struct.pack_into('<I', iv, 4, e1)
        if encrypt:
            ct = iv[n] ^ byte; iv[n] = ct; out[i] = ct
        else:
            out[i] = iv[n] ^ byte; iv[n] = byte
        n = (n + 1) & 7
    return bytes(out), bytes(iv), n

def cfb64_dec(P, S, cipher, iv_bytes):
    plain, _, _ = _cfb64(P, S, cipher, iv_bytes, encrypt=False)
    return plain

def cfb64_enc(P, S, plain, iv_bytes):
    cipher, _, _ = _cfb64(P, S, plain, iv_bytes, encrypt=True)
    return cipher

# ─── Anahtar yükleme ─────────────────────────────────────────────────────────

CONFIRMED_SIG = (0xc87bf7d2, 0x64215ab6, 0x4108fddb, 0x5e2ee03f)

def load_key(crypto_log, target_sig=CONFIRMED_SIG):
    """pb_crypto.log'dan BF_KEY yükle."""
    cur_p, cur_s = None, []
    try:
        with open(crypto_log, encoding='utf-8', errors='replace') as f:
            for line in f:
                s = line.strip()
                if 'BF_KEY ADAYI' in s:
                    cur_p, cur_s = None, []
                    continue
                m = re.search(r'\[72 bytes\]:\s*([0-9a-fA-F]{144})', s)
                if m:
                    cur_p = list(struct.unpack('<18I', bytes.fromhex(m.group(1))))
                    continue
                m = re.search(r'S\[\d\] \(1024B\).*?\[1024 bytes\]:\s*([0-9a-fA-F]{2048})', s)
                if m:
                    cur_s.append(list(struct.unpack('<256I', bytes.fromhex(m.group(1)))))
                    continue
                m = re.search(
                    r'\[SIG\]\s+S0_0=([0-9a-f]+)\s+S1_0=([0-9a-f]+)'
                    r'\s+S2_0=([0-9a-f]+)\s+S3_0=([0-9a-f]+)', s)
                if m:
                    sig = tuple(int(x, 16) for x in m.groups())
                    if sig == target_sig and cur_p and len(cur_s) == 4:
                        return cur_p, cur_s
    except OSError:
        pass
    return None, None

# ─── Oturum durumu ────────────────────────────────────────────────────────────

class Session:
    def __init__(self):
        self.P   = None         # Blowfish P-array
        self.S   = None         # Blowfish S-boxes
        self.iv  = None         # bytes[8] — challenge[3:11]
        self.dll_ws    = None   # DLL WebSocket bağlantısı
        self.ui_clients = set() # Tarayıcı WebSocket bağlantıları
        self.packets   = []     # Son 500 paket
        self.seq       = 0      # Paket sıra numarası

    def has_key(self): return self.P is not None
    def has_iv(self):  return self.iv is not None

    def try_challenge(self, raw):
        """202-byte challenge → IV çıkar."""
        if len(raw) >= 11 and raw[0] == 0xc5:
            self.iv = bytes(raw[3:11])
            return True
        return False

    def decrypt(self, cipher):
        if not self.has_key() or not self.has_iv(): return None
        return cfb64_dec(self.P, self.S, cipher, self.iv)

    def encrypt(self, plain):
        if not self.has_key() or not self.has_iv(): return None
        return cfb64_enc(self.P, self.S, plain, self.iv)

session = Session()

# ─── Paket formatlama ─────────────────────────────────────────────────────────

def fmt_packet(seq, direction, raw, plain, ts=None):
    ts   = ts or time.strftime('%H:%M:%S')
    size = len(raw)
    base = {
        'seq': seq, 'ts': ts, 'dir': direction, 'size': size,
        'raw_hex': raw.hex(), 'plain_hex': None,
        'opcode': None, 'proto': None, 'len_field': None,
        'payload_hex': '', 'status': 'encrypted', 'note': '',
    }
    if plain is None:
        if size == 202 and raw[0] == 0xc5:
            base['status'] = 'challenge'
        return base

    base['plain_hex']   = plain.hex()
    base['len_field']   = plain[0] if plain else None
    base['proto']       = plain[1] if len(plain) > 1 else None
    base['opcode']      = plain[2] if len(plain) > 2 else None
    base['payload_hex'] = plain[3:67].hex() if len(plain) > 3 else ''

    expected = (size - 3) & 0xFF
    len_ok   = (base['len_field'] == expected and size <= 258)
    proto_ok = (base['proto'] == 0x0D)

    if len_ok and proto_ok:         base['status'] = 'ok'
    elif proto_ok and not len_ok:   base['status'] = 'large'    # multi-frame
    elif len_ok and not proto_ok:   base['status'] = 'proto?'
    else:                           base['status'] = 'mismatch'

    # Human-readable
    if base['opcode'] is not None:
        base['opcode'] = f"0x{base['opcode']:02x}"
    if base['proto'] is not None:
        base['proto'] = f"0x{base['proto']:02x}"
    return base

# ─── WebSocket: DLL bağlantısı (/dll) ────────────────────────────────────────

async def dll_handler(request):
    ws = web.WebSocketResponse(max_msg_size=8 * 1024 * 1024)
    await ws.prepare(request)

    peer = request.remote or '?'
    print(f'[DLL] Bağlandı: {peer}')
    # Eski bağlantıyı kapat (yeni bağlantı geldi)
    if session.dll_ws is not None and not session.dll_ws.closed:
        await session.dll_ws.close()
    session.dll_ws = ws

    await broadcast({'type': 'dll_connected', 'peer': peer})

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.BINARY:
                await on_dll_frame(msg.data)
            elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                break
    finally:
        # Sadece BU bağlantı hâlâ aktifse sıfırla; yeni bağlantı geçtiyse dokunma
        if session.dll_ws is ws:
            session.dll_ws = None
            print(f'[DLL] Bağlantı kesildi: {peer}')
            await broadcast({'type': 'dll_disconnected'})
        else:
            print(f'[DLL] Eski bağlantı kapandı (yeni bağlantı devrede): {peer}')

    return ws

async def on_dll_frame(data: bytes):
    """DLL'den gelen binary frame: [1B type][1B dir][4B len LE][...data...]"""
    if len(data) < 6:
        return
    pkt_type  = data[0]      # 'P' = 0x50
    direction = chr(data[1]) # 'R' or 'S'
    data_len  = struct.unpack_from('<I', data, 2)[0]

    if data_len > len(data) - 6:
        return
    raw = data[6: 6 + data_len]
    ts  = time.strftime('%H:%M:%S')

    # Challenge tespiti (202B, 0xc5 ile başlar)
    if direction == 'R' and session.try_challenge(raw):
        ev = fmt_packet(session.seq, 'R', raw, None, ts)
        ev['status'] = 'challenge'
        ev['note']   = f'IV={session.iv.hex()}'
        session.seq += 1
        _store(ev)
        await broadcast({'type': 'packet', 'pkt': ev})
        lvl = 'ok' if session.has_key() else 'warn'
        msg = (f'Challenge alındı — IV={session.iv.hex()}' if session.has_key()
               else 'Challenge alındı — anahtar YOK, decrypt yapılamıyor!')
        await broadcast({'type': 'status', 'msg': msg, 'level': lvl})
        return

    plain = session.decrypt(raw)
    ev    = fmt_packet(session.seq, direction, raw, plain, ts)
    session.seq += 1
    _store(ev)
    await broadcast({'type': 'packet', 'pkt': ev})

def _store(ev):
    session.packets.append(ev)
    if len(session.packets) > 500:
        session.packets = session.packets[-500:]

# ─── WebSocket: Tarayıcı bağlantısı (/ui) ────────────────────────────────────

async def ui_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    session.ui_clients.add(ws)

    # İlk bağlantıda geçmiş + durumu gönder
    await ws.send_json({
        'type':       'init',
        'dll_status': 'connected' if session.dll_ws else 'disconnected',
        'has_key':    session.has_key(),
        'has_iv':     session.has_iv(),
        'iv':         session.iv.hex() if session.iv else None,
        'history':    session.packets[-200:],
    })

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                try:
                    await on_ui_cmd(ws, json.loads(msg.data))
                except (json.JSONDecodeError, KeyError):
                    pass
            elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                break
    finally:
        session.ui_clients.discard(ws)
    return ws

async def on_ui_cmd(ws, cmd):
    t = cmd.get('type')

    if t == 'inject':
        # Hex string → bytes → encrypt → DLL'e gönder
        hex_raw = cmd.get('hex', '').replace(' ', '').replace('0x', '').replace('\n', '')
        try:
            plain = bytes.fromhex(hex_raw)
        except ValueError as e:
            await ws.send_json({'type': 'inject_error', 'msg': f'Geçersiz hex: {e}'})
            return

        if not session.dll_ws:
            await ws.send_json({'type': 'inject_error', 'msg': 'DLL bağlı değil'})
            return
        if not session.has_key() or not session.has_iv():
            await ws.send_json({'type': 'inject_error', 'msg': 'Anahtar veya IV yok'})
            return

        cipher = session.encrypt(plain)
        # DLL inject frame: 'I'(0x49) + 0x00 + [4B len LE] + cipher
        frame = bytes([0x49, 0x00]) + struct.pack('<I', len(cipher)) + cipher
        try:
            await session.dll_ws.send_bytes(frame)
            await ws.send_json({
                'type':       'inject_ok',
                'plain_hex':  plain.hex(),
                'cipher_hex': cipher.hex(),
                'size':       len(cipher),
            })
        except Exception as e:
            await ws.send_json({'type': 'inject_error', 'msg': str(e)})

    elif t == 'inject_raw':
        # Zaten şifrelenmiş ham baytları gönder (gelişmiş mod)
        hex_raw = cmd.get('hex', '').replace(' ', '').replace('\n', '')
        try:
            cipher = bytes.fromhex(hex_raw)
        except ValueError as e:
            await ws.send_json({'type': 'inject_error', 'msg': f'Geçersiz hex: {e}'})
            return
        if not session.dll_ws:
            await ws.send_json({'type': 'inject_error', 'msg': 'DLL bağlı değil'})
            return
        frame = bytes([0x49, 0x00]) + struct.pack('<I', len(cipher)) + cipher
        try:
            await session.dll_ws.send_bytes(frame)
            await ws.send_json({'type': 'inject_ok', 'cipher_hex': cipher.hex(), 'size': len(cipher)})
        except Exception as e:
            await ws.send_json({'type': 'inject_error', 'msg': str(e)})

    elif t == 'clear':
        session.packets.clear()
        session.seq = 0
        await broadcast({'type': 'cleared'})

    elif t == 'load_key':
        path = cmd.get('path', 'log_data/pb_crypto.log')
        P, S = load_key(path)
        if P and S:
            session.P, session.S = P, S
            await ws.send_json({'type': 'status', 'msg': f'Anahtar yüklendi: {path}', 'level': 'ok'})
        else:
            await ws.send_json({'type': 'status', 'msg': f'Anahtar bulunamadı: {path}', 'level': 'error'})

async def broadcast(event):
    dead = set()
    for ws in session.ui_clients:
        try:
            await ws.send_json(event)
        except Exception:
            dead.add(ws)
    session.ui_clients -= dead

# ─── HTTP: Ana sayfa ──────────────────────────────────────────────────────────

async def index_handler(request):
    return web.Response(text=_HTML, content_type='text/html')

async def status_handler(request):
    return web.json_response({
        'dll_connected': session.dll_ws is not None,
        'has_key':       session.has_key(),
        'has_iv':        session.has_iv(),
        'iv':            session.iv.hex() if session.iv else None,
        'pkt_count':     session.seq,
    })

# ─── Web UI (HTML + JS + CSS) ─────────────────────────────────────────────────

_HTML = r"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PointBlank Proxy</title>
<style>
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;
  --green:#3fb950;--blue:#58a6ff;--red:#f85149;
  --yellow:#e3b341;--gray:#8b949e;--border:#30363d;
  --text:#e6edf3;--mono:'Consolas','Courier New',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:13px;
     height:100vh;display:flex;flex-direction:column;overflow:hidden}

/* Header */
#hdr{background:var(--bg2);border-bottom:1px solid var(--border);
     padding:8px 16px;display:flex;align-items:center;gap:14px;flex-shrink:0}
#hdr h1{font-size:13px;color:var(--blue);letter-spacing:3px;text-transform:uppercase}
.led{width:9px;height:9px;border-radius:50%;background:var(--red);flex-shrink:0;transition:background .3s}
.led.on{background:var(--green);box-shadow:0 0 6px var(--green)}
#hdr-status{color:var(--gray);font-size:11px;flex:1}
.badge{font-size:10px;padding:2px 7px;border-radius:10px;background:var(--bg3);color:var(--gray)}
.badge.ok{color:var(--green);border:1px solid var(--green)22}
#pkt-cnt{font-size:10px;color:var(--gray)}

/* Layout */
#main{display:flex;flex:1;overflow:hidden}

/* Left: packet table */
#left{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}

/* Filter bar */
#fbar{background:var(--bg2);border-bottom:1px solid var(--border);
      padding:5px 12px;display:flex;gap:8px;align-items:center;flex-shrink:0;flex-wrap:wrap}
#fbar label{color:var(--gray);font-size:10px;text-transform:uppercase}
#fbar select,#fbar input{background:var(--bg3);border:1px solid var(--border);
  color:var(--text);padding:2px 6px;border-radius:4px;font-size:11px;font-family:var(--mono)}
#btn-clear{margin-left:auto;background:transparent;border:1px solid var(--red)55;
  color:var(--red);padding:2px 10px;border-radius:4px;cursor:pointer;font-size:11px}
#btn-clear:hover{background:var(--red);color:#000}
#btn-scroll{background:transparent;border:1px solid var(--border);
  color:var(--gray);padding:2px 8px;border-radius:4px;cursor:pointer;font-size:11px}
#btn-scroll.on{border-color:var(--green);color:var(--green)}

/* Table */
#tbl-wrap{flex:1;overflow-y:auto}
table{width:100%;border-collapse:collapse;table-layout:fixed}
thead th{background:var(--bg2);padding:4px 8px;text-align:left;font-size:10px;
  color:var(--gray);border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:1;text-transform:uppercase;letter-spacing:1px}
tbody td{padding:3px 8px;border-bottom:1px solid #161b22;cursor:pointer;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tbody tr:hover td{background:var(--bg2)}
tbody tr.sel td{background:#1c2333!important}
.c-seq{width:46px}.c-ts{width:82px}.c-dir{width:46px}
.c-sz{width:62px}.c-st{width:76px}.c-op{width:70px}.c-pay{width:auto}

.dR{color:var(--green)}.dS{color:var(--blue)}
.s-ok{color:var(--green)}.s-large{color:#7ee787}
.s-challenge{color:var(--yellow);font-weight:700}
.s-proto{color:#7dcfff}.s-mismatch{color:var(--gray)}.s-encrypted{color:#3a3f4a}

/* Right panel */
#right{width:350px;display:flex;flex-direction:column;border-left:1px solid var(--border);overflow:hidden;flex-shrink:0}

/* Detail */
#detail{flex:1;overflow-y:auto;padding:10px 12px}
#detail-hd{background:var(--bg2);border-bottom:1px solid var(--border);
  padding:6px 12px;font-size:11px;color:var(--blue);flex-shrink:0}
.df{margin-bottom:7px}.df .dk{color:var(--gray);font-size:9px;text-transform:uppercase;
  letter-spacing:1.5px}.df .dv{margin-top:2px;word-break:break-all}
.hdump{font-size:11px;line-height:1.65;color:#7ee787;background:var(--bg3);
  padding:7px 8px;border-radius:4px;overflow-x:auto;white-space:pre;margin-top:3px;
  max-height:180px;overflow-y:auto}
.copy-btn{font-size:10px;background:var(--bg3);border:1px solid var(--border);
  color:var(--gray);padding:2px 8px;border-radius:3px;cursor:pointer;margin-top:6px}
.copy-btn:hover{color:var(--text)}

/* Inject */
#inj{background:var(--bg2);border-top:1px solid var(--border);padding:10px 12px;flex-shrink:0}
#inj h3{font-size:10px;color:var(--blue);letter-spacing:2px;text-transform:uppercase;margin-bottom:8px}
.inj-tabs{display:flex;gap:4px;margin-bottom:8px}
.itab{font-size:10px;padding:2px 8px;border-radius:3px;cursor:pointer;
  background:var(--bg3);border:1px solid var(--border);color:var(--gray)}
.itab.on{border-color:var(--blue);color:var(--blue)}
#inj-hex{width:100%;background:var(--bg3);border:1px solid var(--border);
  color:var(--green);padding:6px 8px;border-radius:4px;font-family:var(--mono);
  font-size:12px;resize:vertical;min-height:58px}
#inj-row{display:flex;gap:6px;margin-top:6px;align-items:center}
#inj-hint{flex:1;font-size:10px;color:var(--gray)}
#inj-btn{background:var(--blue);border:none;color:#000;padding:4px 16px;
  border-radius:4px;cursor:pointer;font-family:var(--mono);font-size:12px;font-weight:700}
#inj-btn:hover{opacity:.85}
#inj-btn:disabled{opacity:.35;cursor:not-allowed}
#inj-st{font-size:10px;margin-top:4px;color:var(--gray);min-height:16px}
#inj-st.ok{color:var(--green)}.inj-st.err{color:var(--red)}

/* Scrollbar */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
</style>
</head>
<body>

<div id="hdr">
  <div class="led" id="dll-led"></div>
  <h1>PointBlank Proxy</h1>
  <span id="hdr-status">DLL bekleniyor…</span>
  <span class="badge" id="key-b">Anahtar: yok</span>
  <span class="badge" id="iv-b" style="display:none"></span>
  <span id="pkt-cnt">0 paket</span>
</div>

<div id="main">
  <!-- Sol: paket tablosu -->
  <div id="left">
    <div id="fbar">
      <label>Yön</label>
      <select id="f-dir">
        <option value="">Hepsi</option>
        <option value="R">← RECV</option>
        <option value="S">→ SEND</option>
      </select>
      <label>Durum</label>
      <select id="f-st">
        <option value="">Hepsi</option>
        <option value="ok">OK</option>
        <option value="large">Large</option>
        <option value="challenge">Challenge</option>
        <option value="mismatch">Mismatch</option>
      </select>
      <label>Opcode</label>
      <input id="f-op" type="text" placeholder="0x.." style="width:68px">
      <button id="btn-scroll" class="on" title="Otomatik kaydır">↓ Auto</button>
      <button id="btn-clear">Temizle</button>
    </div>
    <div id="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th class="c-seq">#</th>
            <th class="c-ts">Saat</th>
            <th class="c-dir">Yön</th>
            <th class="c-sz">Boyut</th>
            <th class="c-st">Durum</th>
            <th class="c-op">Opcode</th>
            <th class="c-pay">Payload</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- Sağ: detay + inject -->
  <div id="right">
    <div id="detail-hd">Paket Detayı</div>
    <div id="detail"><p style="color:var(--gray);font-size:11px;margin-top:8px">Bir satıra tıklayın…</p></div>

    <div id="inj">
      <h3>▶ Paket Gönder (Inject)</h3>
      <div class="inj-tabs">
        <div class="itab on" data-mode="plain">Plaintext (otom. şifrele)</div>
        <div class="itab"    data-mode="raw">Raw Cipher (ham)</div>
      </div>
      <textarea id="inj-hex" placeholder="Plaintext hex örn: 10 0d 4d 01 02&#10;[0] payload_len = toplam-3&#10;[1] proto = 0x0d&#10;[2] opcode&#10;[3…] payload"></textarea>
      <div id="inj-row">
        <span id="inj-hint">Ctrl+Enter ile gönder</span>
        <button id="inj-btn" disabled>Gönder</button>
      </div>
      <div id="inj-st"></div>
    </div>
  </div>
</div>

<script>
// ── WebSocket ────────────────────────────────────────────────────────────────
const WS_URL = `${location.protocol.replace('http','ws')}//${location.host}/ui`;
let ws, packets = [], selSeq = -1, autoScroll = true, injectMode = 'plain';

function connect() {
  ws = new WebSocket(WS_URL);
  ws.onmessage = e => handle(JSON.parse(e.data));
  ws.onclose = () => setTimeout(connect, 2000);
  ws.onerror = () => ws.close();
}
connect();

// ── Messages ─────────────────────────────────────────────────────────────────
function handle(m) {
  if (m.type === 'init') {
    packets = m.history || [];
    setDll(m.dll_status === 'connected');
    setKey(m.has_key, m.iv);
    renderAll();
  }
  else if (m.type === 'packet') {
    packets.push(m.pkt);
    if (packets.length > 500) packets.shift();
    appendRow(m.pkt);
    updCnt();
  }
  else if (m.type === 'dll_connected') { setDll(true, m.peer); }
  else if (m.type === 'dll_disconnected') { setDll(false); }
  else if (m.type === 'status') { showStatus(m.msg, m.level); }
  else if (m.type === 'cleared') {
    packets = []; document.getElementById('tbody').innerHTML = '';
    document.getElementById('detail').innerHTML = '<p style="color:var(--gray);font-size:11px;margin-top:8px">Bir satıra tıklayın…</p>';
    updCnt();
  }
  else if (m.type === 'inject_ok') {
    const el = document.getElementById('inj-st');
    el.textContent = `✓ Gönderildi ${m.size}B → ${(m.cipher_hex||'').slice(0,20)}…`;
    el.className = 'ok';
  }
  else if (m.type === 'inject_error') {
    const el = document.getElementById('inj-st');
    el.textContent = `✗ ${m.msg}`;
    el.className = 'err';
  }
}

// ── Header state ─────────────────────────────────────────────────────────────
function setDll(on, peer) {
  document.getElementById('dll-led').className = 'led' + (on ? ' on' : '');
  document.getElementById('hdr-status').textContent =
    on ? `DLL bağlı${peer ? ' · '+peer : ''}` : 'DLL bekleniyor…';
  document.getElementById('inj-btn').disabled = !on;
}
function setKey(ok, iv) {
  const b = document.getElementById('key-b');
  b.textContent = ok ? '✓ Anahtar' : 'Anahtar: yok';
  b.className = ok ? 'badge ok' : 'badge';
  const ib = document.getElementById('iv-b');
  if (iv) { ib.textContent = 'IV: ' + iv; ib.style.display = ''; }
}
function showStatus(msg, lv) {
  const el = document.getElementById('hdr-status');
  el.textContent = msg;
  el.style.color = lv==='ok' ? 'var(--green)' : lv==='warn' ? 'var(--yellow)' : 'var(--red)';
  setTimeout(() => { el.style.color = ''; }, 5000);
}
function updCnt() { document.getElementById('pkt-cnt').textContent = packets.length + ' paket'; }

// ── Table ────────────────────────────────────────────────────────────────────
const FDIR = () => document.getElementById('f-dir').value;
const FST  = () => document.getElementById('f-st').value;
const FOP  = () => document.getElementById('f-op').value.trim().toLowerCase().replace('0x','');

function passes(p) {
  const fd = FDIR(), fs = FST(), fo = FOP();
  if (fd && p.dir !== fd) return false;
  if (fs && p.status !== fs) return false;
  if (fo) {
    const op = (p.opcode||'').replace('0x','').toLowerCase();
    if (!op.includes(fo)) return false;
  }
  return true;
}

function mkRow(p) {
  if (!passes(p)) return null;
  const tr = document.createElement('tr');
  tr.dataset.seq = p.seq;
  if (p.seq === selSeq) tr.className = 'sel';
  tr.innerHTML = `
    <td class="c-seq">${p.seq}</td>
    <td class="c-ts">${p.ts}</td>
    <td class="c-dir d${p.dir}">${p.dir==='R'?'←':'→'}</td>
    <td class="c-sz">${p.size}B</td>
    <td class="c-st s-${p.status}">${p.status}</td>
    <td class="c-op">${p.opcode||'—'}</td>
    <td class="c-pay" style="color:var(--gray);font-size:11px">${p.payload_hex?p.payload_hex.slice(0,36):''}</td>
  `;
  tr.onclick = () => selectPkt(p.seq);
  return tr;
}

function renderAll() {
  const tb = document.getElementById('tbody');
  tb.innerHTML = '';
  const frag = document.createDocumentFragment();
  packets.forEach(p => { const r = mkRow(p); if (r) frag.appendChild(r); });
  tb.appendChild(frag);
  if (autoScroll) scrollBot();
  updCnt();
}

function appendRow(p) {
  const r = mkRow(p); if (!r) return;
  document.getElementById('tbody').appendChild(r);
  if (autoScroll) scrollBot();
}

function scrollBot() {
  const w = document.getElementById('tbl-wrap');
  w.scrollTop = w.scrollHeight;
}

document.getElementById('tbl-wrap').addEventListener('scroll', e => {
  const el = e.target;
  autoScroll = el.scrollTop + el.clientHeight >= el.scrollHeight - 24;
  document.getElementById('btn-scroll').className = autoScroll ? 'on' : '';
});
document.getElementById('btn-scroll').addEventListener('click', () => {
  autoScroll = !autoScroll;
  document.getElementById('btn-scroll').className = autoScroll ? 'on' : '';
  if (autoScroll) scrollBot();
});

['f-dir','f-st','f-op'].forEach(id =>
  document.getElementById(id).addEventListener('input', renderAll));

document.getElementById('btn-clear').addEventListener('click', () =>
  ws && ws.send(JSON.stringify({type:'clear'})));

// ── Detail ───────────────────────────────────────────────────────────────────
function selectPkt(seq) {
  selSeq = seq;
  document.querySelectorAll('#tbody tr').forEach(r =>
    r.className = +r.dataset.seq === seq ? 'sel' : '');
  const p = packets.find(x => x.seq === seq);
  if (p) showDetail(p);
}

function hexDump(h) {
  if (!h) return '';
  const bytes = h.match(/.{2}/g) || [];
  let out = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.slice(i, i+16);
    const addr = i.toString(16).padStart(4,'0');
    const hex  = row.map((b,j) => b+(j===7?' ':'')).join(' ');
    const asc  = row.map(b => { const c = parseInt(b,16); return (c>=32&&c<127)?String.fromCharCode(c):'.'; }).join('');
    out += `${addr}  ${hex.padEnd(49)}  ${asc}\n`;
  }
  return out.trimEnd();
}

function df(k, v) { return `<div class="df"><div class="dk">${k}</div><div class="dv">${v}</div></div>`; }

function showDetail(p) {
  const d = document.getElementById('detail');
  let h = '';
  const dir_lbl = p.dir==='R' ? '<span class="dR">← RECV (sunucu→istemci)</span>' : '<span class="dS">→ SEND (istemci→sunucu)</span>';
  h += df('Sıra / Yön', `#${p.seq} &nbsp; ${dir_lbl}`);
  h += df('Saat', p.ts);
  h += df('Boyut', `${p.size} B`);
  const st_cls = 's-'+(p.status||'');
  h += df('Durum', `<span class="${st_cls}">${p.status}</span>${p.note?' — '+p.note:''}`);
  if (p.opcode)     h += df('Opcode', `<b>${p.opcode}</b>`);
  if (p.proto)      h += df('Proto', p.proto);
  if (p.len_field != null) h += df('Len field', `${p.len_field} &nbsp; (beklenen: ${(p.size-3)&0xFF})`);

  if (p.plain_hex) {
    h += df('Plaintext', `<div class="hdump">${hexDump(p.plain_hex)}</div>`);
    h += `<button class="copy-btn" onclick="fillInject('${p.plain_hex}')">↓ Inject kutusuna kopyala</button>`;
  }
  h += df('Raw (şifreli)', `<div class="hdump">${hexDump(p.raw_hex)}</div>`);
  d.innerHTML = h;
}

function fillInject(hex) {
  document.getElementById('inj-hex').value = (hex.match(/.{2}/g)||[]).join(' ');
  document.getElementById('inj-hex').focus();
}

// ── Inject tabs ───────────────────────────────────────────────────────────────
document.querySelectorAll('.itab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.itab').forEach(t => t.className = 'itab');
    tab.className = 'itab on';
    injectMode = tab.dataset.mode;
    const ph = document.getElementById('inj-hex');
    const hint = document.getElementById('inj-hint');
    if (injectMode === 'raw') {
      ph.placeholder = 'Ham şifreli hex (DLL doğrudan gönderir)';
      ph.style.color = 'var(--blue)';
      hint.textContent = 'Şifrelenmez, olduğu gibi gönderilir';
    } else {
      ph.placeholder = 'Plaintext hex örn: 10 0d 4d 01 02\n[0] payload_len=toplam-3  [1] 0x0d  [2] opcode';
      ph.style.color = 'var(--green)';
      hint.textContent = 'Otomatik CFB64 şifrelenir';
    }
  });
});

// ── Inject send ───────────────────────────────────────────────────────────────
document.getElementById('inj-btn').addEventListener('click', doInject);
document.getElementById('inj-hex').addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') { e.preventDefault(); doInject(); }
});

function doInject() {
  const raw = document.getElementById('inj-hex').value
              .replace(/\s+/g,'').replace(/0x/gi,'');
  if (!raw) return;
  const st = document.getElementById('inj-st');
  st.textContent = 'Gönderiliyor…'; st.className = '';
  const type = injectMode === 'raw' ? 'inject_raw' : 'inject';
  ws && ws.send(JSON.stringify({type, hex: raw}));
}
</script>
</body>
</html>"""

# ─── App ─────────────────────────────────────────────────────────────────────

def make_app():
    app = web.Application()
    app.router.add_get('/',             index_handler)
    app.router.add_get('/api/status',  status_handler)
    app.router.add_get('/dll',         dll_handler)
    app.router.add_get('/ui',          ui_handler)
    app.router.add_get('/favicon.ico', lambda r: web.Response(status=204))
    return app

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='PointBlank Proxy Sunucusu')
    ap.add_argument('--crypto', default=None, help='pb_crypto.log yolu')
    ap.add_argument('--port',   type=int, default=5000)
    ap.add_argument('--host',   default='0.0.0.0')
    ap.add_argument('--sig',    default='c87bf7d2 64215ab6 4108fddb 5e2ee03f')
    args = ap.parse_args()

    target_sig = tuple(int(x, 16) for x in args.sig.split())

    # Anahtar yükleme sırası
    candidates = [
        args.crypto,
        'log_data/pb_crypto.log',
        'pb_crypto.log',
    ] + sorted(glob.glob('attached_assets/pb_crypto_*.log'), reverse=True)

    for path in candidates:
        if not path:
            continue
        P, S = load_key(path, target_sig)
        if P and S:
            session.P, session.S = P, S
            print(f'[KEY] ✓ Anahtar yüklendi: {path}')
            print(f'[KEY]   SIG={" ".join(f"{x:08x}" for x in target_sig)}')
            break
    else:
        print('[KEY] ✗ Anahtar bulunamadı — tarayıcıdan yüklenebilir.')

    app = make_app()

    print(f'\n[SERVER] Çalışıyor → http://{args.host}:{args.port}')
    print(f'[SERVER] DLL bağlantısı → ws://HOST:{args.port}/dll')
    print(f'[SERVER] Web UI        → http://HOST:{args.port}/')
    print(f'[SERVER] Durum API     → http://HOST:{args.port}/api/status\n')

    web.run_app(app, host=args.host, port=args.port, print=lambda *a: None)

if __name__ == '__main__':
    main()
