#!/usr/bin/env python3
"""
proxy_server.py — PointBlank Gerçek Zamanlı Proxy Sunucusu
============================================================
DLL'den gelen şifreli paketleri anlık çözer, tarayıcıda gösterir.
Tarayıcıdan özel paket gönderilebilir (inject).

Kullanım:
  python proxy_server.py [--crypto pb_crypto.log] [--port 5000]
"""
import asyncio, json, struct, re, time, argparse, glob, os
from aiohttp import web
import aiohttp

# ── Yetkili DLL token — SESSION_SECRET env değişkeninden okunur ──────────────
PROXY_TOKEN: str = os.environ.get('SESSION_SECRET', '')

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

# ─── Anahtar + IV yükleme ────────────────────────────────────────────────────

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

# pb_net.log'daki her TCP/UDP satırını eşler
def load_key_any(crypto_log):
    """pb_crypto.log'dan son geçerli BF_KEY adayını yükle — SIG filtresi yok."""
    cur_p, cur_s = None, []
    last_p, last_s = None, None
    try:
        with open(crypto_log, encoding='utf-8', errors='replace') as f:
            for line in f:
                s = line.strip()
                if 'BF_KEY ADAYI' in s:
                    if cur_p and len(cur_s) == 4:
                        last_p, last_s = cur_p, list(cur_s)
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
    except OSError:
        pass
    if cur_p and len(cur_s) == 4:
        last_p, last_s = cur_p, list(cur_s)
    return last_p, last_s

def load_all_candidates(crypto_log):
    """pb_crypto.log'dan TÜM benzersiz BF_KEY adaylarını yükle.
    Döndürür: list of (sig_tuple, P_list, S_lists)"""
    candidates = {}   # sig → (P, S)
    cur_p, cur_s, cur_sig = None, [], None
    try:
        with open(crypto_log, encoding='utf-8', errors='replace') as f:
            for line in f:
                s = line.strip()
                if 'BF_KEY ADAYI' in s:
                    if cur_p and len(cur_s) == 4:
                        sig = cur_sig or (cur_s[0][0], cur_s[1][0], cur_s[2][0], cur_s[3][0])
                        if sig not in candidates:
                            candidates[sig] = (cur_p, list(cur_s))
                    cur_p, cur_s, cur_sig = None, [], None
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
                    cur_sig = tuple(int(x, 16) for x in m.groups())
    except OSError:
        pass
    if cur_p and len(cur_s) == 4:
        sig = cur_sig or (cur_s[0][0], cur_s[1][0], cur_s[2][0], cur_s[3][0])
        if sig not in candidates:
            candidates[sig] = (cur_p, list(cur_s))
    return list(candidates.values())   # [(P, S), ...]

def crack_key(candidates, iv_bytes, test_packets, min_hits=2):
    """Aday listesinden doğru anahtarı bul.
    test_packets: list of (cipher_bytes, size) — RECV paketleri

    Protokol notu: header (cipher[0:3]) DÜZ METİN olduğundan
    key bağımsız doğrulanır. Payload (cipher[3:]) Blowfish şifreli;
    doğru key heuristic ile tespit edilir (kesin değil, DLL key frame
    geldikten sonra otomatik güncellenir).

    Doğrulama kriterleri:
      1. Header: flag byte MSB set VE boyut eşleşmesi (key'den bağımsız)
      2. Payload heuristic: PointBlank payload'larında genellikle
         ilk byte küçük (<0x40) veya payload içinde 3 ardışık sıfır byte
         bulunur — tamamen rastgele byte'lar yanlış key'i gösterir."""
    best_p, best_s, best_hits = None, None, -1
    for P, S in candidates:
        hits = 0
        for cipher, size in test_packets:
            if len(cipher) < 4:
                continue
            # Adım 1: header geçerliliği — key'den bağımsız
            flag = cipher[1]
            payload_len = cipher[0] | ((flag & 0x7F) << 8)
            if not (flag & 0x80) or 3 + payload_len != size:
                continue   # geçersiz boyut → bu paketi atla
            enc_payload = cipher[3:]
            if not enc_payload:
                hits += 1  # payload yok → her key geçer
                continue
            # Adım 2: payload heuristic — doğru key ile okunabilir veri
            plain_payload, _, _ = _cfb64(P, S, enc_payload, iv_bytes,
                                         encrypt=False, n_in=0)
            small_first = bool(plain_payload) and plain_payload[0] < 0x40
            zero_run    = any(plain_payload[i:i+3] == b'\x00\x00\x00'
                              for i in range(min(len(plain_payload) - 2, 20)))
            if small_first or zero_run:
                hits += 1
        if hits > best_hits:
            best_hits, best_p, best_s = hits, P, S
    if best_hits >= min_hits:
        return best_p, best_s
    if best_hits >= 1:
        return best_p, best_s
    return None, None

_NET_PKT_RE = re.compile(
    r'TCP\s+(RECV|SEND)\s+[←→].*?\[(\d+)\s+bytes\]:\s*([0-9a-fA-F]+)',
    re.IGNORECASE
)

def load_iv_from_net_log(path):
    """pb_net.log'dan IV çıkar: 0xc5 ile başlayan ilk RECV paketi challenge[3:11]"""
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                m = _NET_PKT_RE.search(line)
                if not m:
                    continue
                if m.group(1).upper() != 'RECV':
                    continue
                try:
                    raw = bytes.fromhex(m.group(3))
                except ValueError:
                    continue
                if len(raw) >= 11 and raw[0] == 0xc5:
                    return bytes(raw[3:11])
    except OSError:
        pass
    return None

def auto_load_session(crypto_path=None, net_path=None, sig=CONFIRMED_SIG):
    """Mevcut log dosyalarından anahtar ve IV'i sessizce yükle. Değişen alanları döndür."""
    changed = {}
    if crypto_path:
        P, S = load_key(crypto_path, sig)
        if P and S:
            session.set_key(P, S)
            changed['key'] = crypto_path
    if net_path:
        iv = load_iv_from_net_log(net_path)
        if iv:
            session.set_iv(iv)
            changed['iv'] = iv.hex()
    return changed

# ─── Anahtar önbelleği (disk) ─────────────────────────────────────────────────

KEY_CACHE_PATH = 'bf_key.bin'

def save_key_cache(P, S):
    """Anahtarı diske kaydet — sunucu yeniden başlatılınca tekrar yüklenebilsin."""
    try:
        data = struct.pack('<18I', *P)
        for sbox in S:
            data += struct.pack('<256I', *sbox)
        with open(KEY_CACHE_PATH, 'wb') as f:
            f.write(data)
    except OSError as e:
        print(f'[KEY] Önbellek yazma hatası: {e}')

def load_key_cache():
    """Daha önce kaydedilmiş anahtarı yükle."""
    try:
        with open(KEY_CACHE_PATH, 'rb') as f:
            data = f.read()
        expected = (18 + 4 * 256) * 4   # 4168 bytes
        if len(data) < expected:
            return None, None
        P = list(struct.unpack_from('<18I', data, 0))
        S = [list(struct.unpack_from('<256I', data, (18 + i * 256) * 4)) for i in range(4)]
        return P, S
    except OSError:
        return None, None

# ─── Oturum durumu ────────────────────────────────────────────────────────────

class Session:
    def __init__(self):
        self.P   = None         # Blowfish P-array
        self.S   = None         # Blowfish S-boxes
        self.iv  = None         # bytes[8] — challenge[3:11] (başlangıç IV)
        # CFB-64 STREAMING durumu — RECV ve SEND bağımsız akışlardır
        self.iv_recv = None     # RECV akışının mevcut CFB IV'i
        self.n_recv  = 0        # RECV akışının blok içi ofseti (0-7)
        self.iv_send = None     # SEND akışının mevcut CFB IV'i
        self.n_send  = 0        # SEND akışının blok içi ofseti (0-7)
        # DLL bağlantıları — birden fazla instance aynı anda bağlı olabilir
        self.dll_clients: set = set()   # tüm aktif DLL WebSocket'leri
        self._dll_ws_latest = None      # injection için en son bağlanan DLL
        self.ui_clients = set()
        self.packets   = []
        self.seq       = 0
        # ── Intercept modu ──────────────────────────────────────────────────
        self.intercept_mode: bool = False
        self.intercept_dir_mask: int = 3   # bit0=SEND bit1=RECV
        self.pending_intercepts: dict[int, asyncio.Future] = {}

    @property
    def dll_ws(self):
        """Injection için en son bağlanan DLL WebSocket'ini döndür."""
        if self._dll_ws_latest and not self._dll_ws_latest.closed:
            return self._dll_ws_latest
        # latest kapanmışsa set'ten açık olanı seç
        for ws in self.dll_clients:
            if not ws.closed:
                self._dll_ws_latest = ws
                return ws
        return None

    def has_key(self): return self.P is not None
    def has_iv(self):  return self.iv is not None

    def _reset_streams(self):
        """IV veya anahtar değiştiğinde her iki yönün CFB durumunu başa al."""
        if self.iv:
            self.iv_recv, self.n_recv = self.iv, 0
            self.iv_send, self.n_send = self.iv, 0

    def set_iv(self, iv_bytes):
        """IV'i dışarıdan ata (log yükleme, startup) ve akışları sıfırla."""
        self.iv = iv_bytes
        self._reset_streams()

    def set_key(self, P, S, save_cache=True):
        """Anahtarı ata ve IV mevcutsa akışları sıfırla.
        save_cache=True → bf_key.bin güncelle (sadece doğrulanmış anahtarlar için)."""
        self.P, self.S = P, S
        self._reset_streams()
        if save_cache:
            save_key_cache(P, S)

    def try_challenge(self, raw):
        """202-byte challenge → IV çıkar, CFB akışlarını sıfırla."""
        if len(raw) >= 11 and raw[0] == 0xc5:
            self.set_iv(bytes(raw[3:11]))
            return True
        return False

    def score_iv(self, candidate_iv: bytes, n_pkts: int = 8) -> int:
        """Son RECV paketlerini candidate_iv ile çözüp doğrulayan paket sayısını döndür.

        Protokol: cipher[0:3] düz metin, cipher[3:] CFB-64 şifreli payload.
        Geçerli çözümde sub-paket flag byte'ı (dec[1]) MSB=1 taşımalı.
        Bu test IV'e duyarlıdır çünkü payload şifreli — yanlış IV rastgele
        baytlar üretir ve MSB=1 testi ~%50 oranında geçer.
        Doğru IV → tüm paketler geçer; yanlış IV → yaklaşık yarısı geçer."""
        if not self.has_key() or not candidate_iv:
            return 0
        score = 0
        test_pkts = [
            p for p in self.packets[-40:]
            if p.get('raw_hex') and p.get('dir') == 'R' and p.get('size', 0) > 3
        ][-n_pkts:]
        for p in test_pkts:
            try:
                raw = bytes.fromhex(p['raw_hex'])
                if len(raw) <= 3:
                    continue
                dec, _, _ = _cfb64(self.P, self.S, raw[3:], candidate_iv,
                                   encrypt=False, n_in=0)
                # Sub-paket flag byte MSB=1 testi
                if len(dec) >= 2 and (dec[1] & 0x80):
                    score += 1
            except Exception:
                pass
        return score

    def apply_iv_if_better(self, candidate_iv: bytes) -> bool:
        """IV adayını mevcut IV ile karşılaştır.

        Politika:
          - IV yoksa → her zaman kabul et.
          - Aynı IV → değişiklik yok.
          - Son paketler tutarsız (hepsi mismatch/encrypted) → mevcut IV bozuk;
            yeni challenge gelmiş demektir (reconnect) → kabul et.
          - score_iv > mevcut → daha iyi IV → kabul et.
          - Aksi hâlde mevcut IV çalışıyorsa koru."""
        if self.iv is None:
            self.set_iv(candidate_iv)
            return True
        if self.iv == candidate_iv:
            return False  # değişiklik yok

        # Reconnect tespiti: son 5+ paket hepsi başarısız → IV değişti
        recent = self.packets[-8:] if self.packets else []
        iv_failing = (len(recent) >= 5 and
                      all(p.get('status') in ('mismatch', 'encrypted', None)
                          for p in recent))
        if iv_failing:
            print(f'[IV] Reconnect: son {len(recent)} paket başarısız → yeni IV kabul edildi')
            self.set_iv(candidate_iv)
            return True

        new_score = self.score_iv(candidate_iv)
        old_score = self.score_iv(self.iv)

        has_ok = any(p.get('status') == 'ok' for p in self.packets[-20:])
        if has_ok:
            if new_score > old_score:
                self.set_iv(candidate_iv)
                return True
            ok_count = sum(1 for p in self.packets[-20:] if p.get('status') == 'ok')
            print(f'[IV] Reddedildi — mevcut IV çalışıyor ({ok_count} ok), '
                  f'yeni={candidate_iv.hex()} skor={new_score} eski={old_score}')
            return False

        # OK paket yok → eşit skor yeterli
        if new_score >= old_score:
            self.set_iv(candidate_iv)
            return True
        print(f'[IV] Reddedildi — skor {new_score} < mevcut {old_score}')
        return False

    def decrypt(self, cipher, direction='R'):
        """Per-buffer CFB-64 decrypt.

        Protokol formatı (wire capture ile doğrulandı):
          cipher[0]  = len_lo          (DÜZ METİN — Blowfish dışı)
          cipher[1]  = 0x80|len_hi     (DÜZ METİN — Blowfish dışı)
          cipher[2]  = opcode          (DÜZ METİN — Blowfish dışı)
          cipher[3:] = Blowfish CFB-64 şifreli payload

        Döndürülen değer: cipher[0:3] + BF_dec(cipher[3:])
        Böylece plain[2] = opcode, plain[3:] = çözülmüş payload."""
        if not self.has_key() or not self.has_iv():
            return None
        if len(cipher) < 3:
            return bytes(cipher)
        header = cipher[:3]          # düz metin — olduğu gibi geç
        enc_payload = cipher[3:]
        if not enc_payload:
            return bytes(cipher)
        plain_payload, _, _ = _cfb64(self.P, self.S, enc_payload, self.iv,
                                     encrypt=False, n_in=0)
        return header + plain_payload

    def decrypt_subpkt(self, raw_subpkt: bytes) -> bytes | None:
        """Tek bir alt paketin payload'ını bağımsız olarak çöz (walk_subpackets için)."""
        if not self.has_key() or not self.has_iv() or len(raw_subpkt) < 3:
            return None
        header = raw_subpkt[:3]
        enc_payload = raw_subpkt[3:]
        if not enc_payload:
            return bytes(raw_subpkt)
        plain_payload, _, _ = _cfb64(self.P, self.S, enc_payload, self.iv,
                                     encrypt=False, n_in=0)
        return header + plain_payload

    def encrypt(self, plain):
        """Per-buffer CFB-64 encrypt — sadece payload (plain[3:]) şifrelenir.
        plain[0:3] (header) düz metin olarak bırakılır."""
        if not self.has_key() or not self.has_iv():
            return None
        if len(plain) < 3:
            return bytes(plain)
        header = plain[:3]
        payload = plain[3:]
        if not payload:
            return bytes(plain)
        cipher_payload, _, _ = _cfb64(self.P, self.S, payload, self.iv,
                                      encrypt=True, n_in=0)
        return header + cipher_payload

session = Session()

# ─── Protocol Decoder ────────────────────────────────────────────────────────
#
# Opcode tablosu: 0xNN → (kısa_ad, yön_ipucu, açıklama)
# yön_ipucu: 'C→S' = client→server, 'S→C' = server→client, '?' = bilinmiyor
# Yeni opcode eklemek için buraya satır ekle; proxy yeniden başlatmaya gerek yok
# (sunucu yeniden başlatılınca tablo güncellenir).
_OPCODES: dict[int, tuple[str, str, str]] = {
    # ══════════════════════════════════════════════════════════════
    # Opcode tablosu: (kısa_ad, yön, açıklama)
    # Yön: 'C→S' istemci→sunucu · 'S→C' sunucu→istemci · 'both' her iki yön
    # Güven seviyesi notları:
    #   [✓] Gerçek trafik verisiyle doğrulanmış (decrypt=ok, payload incelendi)
    #   [~] Protokol akışından / DLL kayıt düzeninden güçlü çıkarım
    #   [?] Bilinmiyor / spekülatif — ham hex görüldü ama içerik net değil
    # ══════════════════════════════════════════════════════════════

    # ── 0x01–0x13 · Bağlantı / Oturum ─────────────────────────────────────────
    0x01: ('CONNECT',        'C→S',  'İstemci bağlantı isteği — TCP kurulduktan sonra sunucuya ilk gönderilen paket [~]'),
    0x02: ('PING',           'both', 'Canlı tutma ping — her iki yönde, 4 B timestamp payload [~]'),
    0x03: ('PONG',           'both', 'Canlı tutma pong — PING yanıtı, 4 B timestamp [~]'),
    0x04: ('DISCONNECT',     'both', 'Bağlantı kesme bildirimi — istemci veya sunucu tarafından [~]'),
    0x05: ('HANDSHAKE',      'both', 'El sıkışma / kriptografi başlatma — BF oturum anahtarı müzakeresi [~]'),
    0x06: ('SESSION_OK',     'S→C',  'Oturum onayı — sunucu bağlantıyı kabul etti, session ID döner [~]'),
    0x07: ('RECONNECT',      'C→S',  'Yeniden bağlantı isteği — önceki session ID ile devam et [~]'),
    0x08: ('ECHO',           'both', 'Bağlantı test echo — RTT / latency ölçümü [~]'),
    0x09: ('VERSION',        'C→S',  'İstemci sürüm bilgisi — build no, patch sürümü [?]'),
    0x0a: ('SERVER_LIST',    'S→C',  'Sunucu / bölge listesi — adres, yük, durum [?]'),
    0x0b: ('SELECT_SERVER',  'C→S',  'Sunucu seçimi isteği — sunucu ID [?]'),
    0x0c: ('NAT_INFO',       'both', 'NAT / harici IP bilgisi — P2P bağlantı kurulumunda kullanılır [?]'),
    0x0e: ('SESSION_PING',   'both', 'Oturum seviyesi ping — kalp atışı, uzun inaktivite koruması [?]'),
    0x0f: ('SESSION_CLOSE',  'both', 'Oturum kapatma talebi — graceful disconnect [?]'),
    0x10: ('NOTICE',         'S→C',  'Sunucu bildirimi / duyuru — tek seferlik metin mesajı [?]'),
    0x11: ('TIME_SYNC',      'both', 'Zaman senkronizasyonu — istemci / sunucu saat farkı [?]'),
    0x12: ('ERROR_MSG',      'S→C',  'Hata bildirimi — hata kodu + açıklama string [?]'),
    0x13: ('HEARTBEAT_ACK',  'S→C',  'Heartbeat onayı — sunucu canlılık yanıtı [?]'),

    # ── 0x14–0x1d · Giriş / Kimlik Doğrulama ──────────────────────────────────
    0x14: ('LOGIN_REQ',      'C→S',  'Login isteği — Pascal-string kullanıcı adı + MD5/SHA1 şifre hash [~]'),
    0x15: ('LOGIN_ACK',      'S→C',  'Login yanıtı — 1 B sonuç kodu (0=OK, 1=yanlış şifre, …) + 4 B kullanıcı ID [~]'),
    0x16: ('AUTH_TOKEN',     'C→S',  'Kimlik doğrulama token — session token / MAC challenge yanıtı [~]'),
    0x17: ('USER_INFO',      'S→C',  'Kullanıcı profil verisi — seviye, deneyim, rütbe, VIP durumu [~]'),
    0x18: ('CHAR_SELECT',    'C→S',  'Karakter / görünüm seçimi — slot ID [~]'),
    0x19: ('CHAR_LIST',      'S→C',  'Karakter listesi — mevcut görünüm/slot verileri [?]'),
    0x1a: ('CHAR_CREATE',    'C→S',  'Yeni karakter oluşturma — isim + görünüm seçimi [?]'),
    0x1b: ('CHAR_CREATE_ACK','S→C',  'Karakter oluşturma yanıtı — sonuç kodu [?]'),
    0x1c: ('CHAR_DELETE',    'C→S',  'Karakter silme isteği — slot ID [?]'),
    0x1d: ('CHAR_DELETE_ACK','S→C',  'Karakter silme yanıtı — sonuç kodu [?]'),

    # ── 0x1e–0x27 · Lobi / Kanal ───────────────────────────────────────────────
    0x1e: ('LOBBY_LIST',     'S→C',  'Lobi / kanal listesi — kanal adları, oyuncu sayıları, kapasite [~]'),
    0x1f: ('CHANNEL_JOIN',   'C→S',  'Kanala giriş isteği — kanal ID [~]'),
    0x20: ('CHANNEL_ACK',    'S→C',  'Kanal giriş yanıtı — kabul/red kodu [~]'),
    0x21: ('PLAYER_LIST',    'S→C',  'Kanaldaki oyuncu listesi — toplu snapshot [~]'),
    0x22: ('PLAYER_ENTER',   'S→C',  'Kanala yeni oyuncu girdi — oyuncu adı, seviye, rütbe [~]'),
    0x23: ('PLAYER_LEAVE',   'S→C',  'Kanaldan oyuncu ayrıldı — oyuncu ID [~]'),
    0x24: ('CHANNEL_INFO',   'S→C',  'Kanal detay verisi — moderatör, kural, açıklama [?]'),
    0x25: ('CHANNEL_CHAT',   'both', 'Kanal sohbet mesajı — gönderen + metin [?]'),
    0x26: ('PLAYER_UPDATE',  'S→C',  'Oyuncu bilgisi güncellendi — seviye veya rütbe değişimi [?]'),
    0x27: ('CHANNEL_LEAVE',  'C→S',  'Kanaldan çıkış — lobi bekleme ekranına dön [?]'),

    # ── 0x28–0x3b · Oda ────────────────────────────────────────────────────────
    0x28: ('ROOM_LIST',      'S→C',  'Oda listesi — lobi odaları snapshot [~]'),
    0x29: ('ROOM_CREATE',    'C→S',  'Oda oluşturma isteği — harita, mod, şifre, maksimum oyuncu [~]'),
    0x2a: ('ROOM_JOIN',      'C→S',  'Odaya katılma isteği — oda ID + şifre [~]'),
    0x2b: ('ROOM_LEAVE',     'C→S',  'Odadan ayrılma [~]'),
    0x2c: ('ROOM_ACK',       'S→C',  'Oda işlemi yanıtı — oluşturma / katılma sonuç kodu [~]'),
    0x2d: ('ROOM_INFO',      'S→C',  'Oda bilgisi paketi — harita, mod, lider, oyuncu listesi, ayarlar [~]'),
    0x2e: ('ROOM_READY',     'C→S',  'Hazır butonu — hazır / hazır değil toggle [~]'),
    0x2f: ('ROOM_KICK',      'S→C',  'Odadan atılma bildirimi — neden kodu (kick / oda kapandı) [~]'),
    0x30: ('ROOM_LEAD_CHG',  'S→C',  'Oda liderliği değişti — yeni lider oyuncu ID [?]'),
    0x31: ('ROOM_PLAYER_LIST','S→C', 'Oda oyuncu listesi snapshotu — tüm slotlar, hazır durumları [?]'),
    0x32: ('GAME_START',     'S→C',  'Oyun başlıyor — harita ID, oyun modu, takım atamaları [~]'),
    0x33: ('GAME_END',       'S→C',  'Oyun bitti — kazanan takım + skor tablosu [~]'),
    0x34: ('ROUND_START',    'S→C',  'Tur başladı — kalan süre, takım bilgisi [~]'),
    0x35: ('ROUND_END',      'S→C',  'Tur bitti — tur kazananı, puan [~]'),
    0x36: ('MAP_DATA',       'S→C',  'Harita verisi — spawn noktaları, sınırlar, nesne pozisyonları [~]'),
    0x37: ('GAME_TIMER',     'S→C',  'Oyun sayacı — kalan süre güncellemesi (geri sayım) [?]'),
    0x38: ('SPECTATE',       'both', 'İzleyici (spectator) modu — istek / onay / geçiş bildirimi [?]'),
    0x39: ('ROOM_SETTINGS',  'C→S',  'Oda ayarı değiştirme — oda lideri gönderir: harita, mod, süre [~]'),
    0x3a: ('MAP_CHANGE',     'both', 'Harita değişim isteği / sonucu — oyun sonu veya lider komutu [?]'),
    0x3b: ('GAME_INIT',      'S→C',  'Oyun başlamadan önce gönderilen init paketi — kaynak, kural seti [?]'),

    # ── 0x3c–0x4f · Oyuncu Konumu / Savaş ─────────────────────────────────────
    0x3c: ('SPAWN',          'S→C',  'Spawn noktası — konum (x,y,z float LE) + takım byte; 15 B payload [~]'),
    0x3d: ('MOVE',           'both', 'Hareket paketi — konum (x,y,z float LE) + yaw u16; min 14 B [~]'),
    0x3e: ('JUMP',           'C→S',  'Zıplama bildirimi — atış anındaki konum veya sadece flag [~]'),
    0x3f: ('CROUCH',         'C→S',  'Çömelme / ayağa kalkma toggle [~]'),
    0x40: ('STANCE',         'both', 'Duruş / hareket durumu paketi — animasyon kodu; login akışında 291 B (proto=0x0C) [✓]'),
    0x41: ('STANCE_EX',      'both', 'Genişletilmiş duruş verisi — ek animasyon, yükleme durumu [~]'),
    0x42: ('DAMAGE_NOTIF',   'S→C',  'Hasar bildirimi — aldığı hasar miktarı, kalan HP [~]'),
    0x43: ('BATCH_DATA',     'S→C',  'Toplu veri çerçevesi — birden fazla alt paketi tek buffer\'da taşır [~]'),
    0x44: ('PLAYER_DATA',    'S→C',  'Oyuncu temel verisi — isim, seviye, takım ID [~]'),
    0x45: ('CHAR_DATA',      'S→C',  'Karakter profil verisi — login sonrası S→C; 163 B toplam, 160 B payload; [0:4]=oyuncu_id? [✓]'),
    0x46: ('SHOOT',          'C→S',  'Ateş paketi — silah slot ID + hedef koordinatı (x,y,z) [~]'),
    0x47: ('HIT',            'S→C',  'Vurma bildirimi — [0:2]=alan_A [2:4]=alan_B [4:6]=hasar/alan_C; 35 B (32 B payload); login akışında alan anlamı farklı [✓]'),
    0x48: ('ITEM_ACTION',    'C→S',  'Eşya kullanma / bırakma — eşya slot ID + aksiyon kodu [~]'),
    0x49: ('RELOAD',         'C→S',  'Şarjör doldurma bildirimi — silah slot ID [~]'),
    0x4a: ('WEAPON_SWITCH',  'C→S',  'Silah değiştirme — yeni silah slot ID [~]'),
    0x4b: ('PLAYER_DEAD',    'S→C',  'Ölüm bildirimi — [0:2]=öldüren_ID [2:4]=ölen_ID [4]=silah_kodu [~]'),
    0x4c: ('CHAT',           'both', 'Sohbet mesajı — Pascal-string gönderen + metin; login akışında 19 B (16 B payload) binary token [✓]'),
    0x4d: ('SERVER_REDIR',   'S→C',  'Sunucu yönlendirme — oyun sunucusu IPv4 (4 B) + port (2 B LE) [~]'),
    0x4e: ('GRENADE',        'C→S',  'El bombası fırlatma — bomba tipi + başlangıç koordinatı (x,y,z) [~]'),
    0x4f: ('EXPLOSION',      'S→C',  'Patlama efekti bildirimi — merkez koordinatı + yarıçap + hasar tipi [~]'),

    # ── 0x50–0x61 · Skor / Envanter / Mağaza ──────────────────────────────────
    0x50: ('SCORE',          'S→C',  'Skor güncellemesi — [0:2]=takım_A [2:4]=takım_B puan (u16 LE) [~]'),
    0x51: ('KILL_FEED',      'S→C',  'Kill özeti — öldüren ID + ölen ID + silah kodu [~]'),
    0x52: ('STATS',          'S→C',  'Oyun sonu istatistikleri — tüm oyuncuların skor tablosu [~]'),
    0x53: ('MAP_INFO_EX',    'S→C',  'Harita genişletilmiş bilgi — çevresel parametreler, ek spawn [~]'),
    0x54: ('TEAM_INFO',      'S→C',  'Takım atama / bilgisi — üye listesi, renk, isim [~]'),
    # UYARI: 0x55 ve 0x57 — gerçek trafik verisiyle C→S doğrulandı (19 B, 16 B payload) ──
    0x55: ('SESSION_REQ',    'C→S',  'Oturum isteği / istemci onay token — login akışında C→S; 19 B toplam, 16 B payload; [0:4]=token_id? [✓]'),
    0x56: ('XP_UPDATE',      'S→C',  'Deneyim / seviye güncellemesi — yeni XP (u32) + yeni seviye (u16) [~]'),
    0x57: ('DATA_ACK',       'C→S',  'Sunucu verisi onayı / ikinci token paketi — login akışında C→S; 19 B toplam, 16 B payload [✓]'),
    0x58: ('SERVER_CFG',     'S→C',  'Sunucu yapılandırma parametreleri — max oyuncu, mod kısıtlamaları [~]'),
    0x59: ('CHAT_CHANNEL',   'S→C',  'Sohbet kanalı bilgisi / başlatma — kanal ID, mod [~]'),
    0x5a: ('SHOP_BUY',       'C→S',  'Satın alma isteği — ürün ID + miktar + para birimi tipi [~]'),
    0x5b: ('SYSTEM_MSG',     'S→C',  'Sistem mesajı / sunucu duyurusu — Pascal-string metin [~]'),
    0x5c: ('INVENTORY',      'S→C',  'Envanter listesi — sahip olunan silah, zırh, eşya verileri [~]'),
    0x5d: ('EQUIP',          'C→S',  'Eşya / silah donatma — ekipman slot ID + eşya ID [~]'),
    0x5e: ('ROOM_STATE',     'S→C',  'Oda üye durum güncellemesi — oyuncu ID + hazır/değil bayrağı [~]'),
    0x5f: ('RANK_INFO',      'S→C',  'Rütbe / VIP bilgisi — mevcut rütbe ID + puan + sonraki eşik [~]'),
    0x60: ('SHOP_INFO',      'S→C',  'Mağaza katalogu / öne çıkan ürünler — ürün ID listesi [?]'),
    0x61: ('PURCHASE_ACK',   'S→C',  'Satın alma sonucu — sonuç kodu + yeni bakiye [?]'),

    # ── 0x62–0x6f · Oyun İçi Genişletilmiş Veri ─────────────────────────────
    0x62: ('PLAYER_STATS',   'S→C',  'Oyuncu istatistik paketi — K/D oranı, isabet yüzdesi, toplam kill [~]'),
    0x63: ('KILL_STREAK',    'S→C',  'Kill serisi / combo bildirimi — seri sayısı + ödül tipi [~]'),
    0x64: ('HEARTBEAT',      'both', 'Uygulama seviyesi kalp atışı — 4 B zaman damgası [~]'),
    0x65: ('ACHIEVEMENT',    'S→C',  'Başarım / rozet kazanıldı — başarım ID + açıklama [~]'),
    0x66: ('DAILY_MISSION',  'S→C',  'Günlük görev verisi — görev listesi + ilerleme yüzdeleri [?]'),
    0x67: ('BADGE_UNLOCK',   'S→C',  'Yeni rozet açıldı — rozet ID + tooltip metni [?]'),
    0x68: ('WORLD_DATA',     'S→C',  'Oyun dünyası / dinamik harita olayları — kapı, araç, tetikleyici [~]'),
    0x69: ('OBJECTIVE',      'S→C',  'Hedef bilgisi — bomba / bayrak konumu, sayaç, durum [~]'),
    0x6a: ('LOBBY_INFO',     'S→C',  'Lobi toplu veri paketi — kanal + oda listeleri birleşik [~]'),
    0x6b: ('ROOM_ENTER_ACK', 'S→C',  'Odaya giriş onayı — oyuncu slot numarası [~]'),
    0x6c: ('GAME_EVENT',     'S→C',  'Oyun içi olay bildirimi — kapı açıldı, araç binildi, nesne alındı [~]'),
    0x6d: ('POS_BATCH',      'S→C',  'Toplu konum paketi — tüm oyuncuların (x,y,z) konumları [~]'),
    0x6e: ('SERVER_INFO',    'S→C',  'Sunucu bilgisi — IPv4 (4 B) + port (2 B LE) + bölge kodu [~]'),
    0x6f: ('SESSION_DATA',   'S→C',  'Oturum verisi — session token + parametre seti [~]'),

    # ── 0x70–0x7f · Toplu Durum / Sosyal ─────────────────────────────────────
    # Not: büyük buffer'lar (>258 B) _walk_subpackets ile sub-paket olarak ayrıştırılır
    0x70: ('STATE_BATCH',    'S→C',  'Oyuncu durum toplu paketi — anlık snapshot; alt paket olarak gelir [~]'),
    0x71: ('MAP_OBJECTS',    'S→C',  'Harita nesne listesi — pickup, silah, bomba spawn noktaları [~]'),
    0x72: ('EQUIP_INFO',     'S→C',  'Ekipman bilgisi — oyuncunun donanımlı silah + zırh listesi [~]'),
    0x73: ('GAME_RULES',     'S→C',  'Oyun kuralları / mod ayarları — FF, sınır süre, puan hedefi [~]'),
    0x74: ('MISSION',        'S→C',  'Görev bilgisi / ilerleme — aktif görev ID + yüzde [~]'),
    0x75: ('VOTE',           'both', 'Oylama — kick vote, harita değişimi, erken bitiş [~]'),
    0x76: ('NOTICE_BOARD',   'S→C',  'Sunucu ilan panosu / scroll duyurusu — zaman damgalı metin [?]'),
    0x77: ('PLAYER_ACTION',  'both', 'Oyuncu eylem paketi — animasyon / aksiyon kodu (iyileştirme, eğil, vs.) [~]'),
    0x78: ('CLAN_INFO',      'S→C',  'Klan bilgisi — klan adı, üye sayısı, sembol ID, rütbe [~]'),
    0x79: ('CLAN_RANK',      'S→C',  'Klan rütbe / puan güncellemesi [~]'),
    0x7a: ('BROADCAST',      'S→C',  'Sunucu geniş yayın duyurusu — tüm kanallara giden sistem mesajı [~]'),
    0x7b: ('FRIEND_LIST',    'S→C',  'Arkadaş listesi — login sonrası S→C; 91 B (88 B payload) kısa veya 755 B (752 B, proto=0x0F) uzun; [0:2]=giriş_sayısı? [✓]'),
    0x7c: ('FRIEND_STATUS',  'S→C',  'Arkadaş çevrimiçi durum güncellemesi — arkadaş ID + durum kodu [~]'),
    0x7d: ('SOCIAL_DATA',    'S→C',  'Sosyal / topluluk verisi — guild, arkadaş grubu, davet listesi [~]'),
    0x7e: ('EVENT_BATCH',    'S→C',  'Oyun olay toplu paketi — sunucu tarafından gruplanmış olaylar [~]'),
    0x7f: ('CHANNEL_UPDATE', 'S→C',  'Kanal durumu toplu güncellemesi — oyuncu sayısı değişimi [?]'),

    # ── 0x80–0x8f · Genişletilmiş Özellikler ─────────────────────────────────
    0x80: ('SHOP_CATALOG',   'S→C',  'Mağaza tam katalogu — tüm ürünler, fiyatlar, süre seçenekleri [?]'),
    0x81: ('ITEM_EXPIRE',    'S→C',  'Eşya süresi doldu bildirimi — eşya ID + kalan süre [?]'),
    0x82: ('CLAN_INVITE',    'both', 'Klan daveti — gönderen klan ID + davet edilen oyuncu [?]'),
    0x83: ('FRIEND_REQ',     'both', 'Arkadaşlık isteği — gönderen oyuncu ID + isim [?]'),
    0x84: ('FRIEND_ACK',     'both', 'Arkadaşlık isteği yanıtı — kabul / red [?]'),
    0x85: ('PRIVATE_MSG',    'both', 'Özel mesaj (whisper) — alıcı ID + metin [?]'),
    0x86: ('BLOCK_LIST',     'S→C',  'Engellenen oyuncular listesi [?]'),
    0x87: ('REPORT_ACK',     'S→C',  'Şikâyet / rapor sonucu — işlem kodu [?]'),
    0x88: ('HOTKEY_SYNC',    'C→S',  'İstemci kısayol / ayar senkronizasyonu [?]'),
    0x89: ('ROOM_PASS_CHG',  'C→S',  'Oda şifresi değiştirme isteği — yeni şifre string [?]'),
    0x8a: ('TEAM_BALANCE',   'S→C',  'Takım dengeleme bildirimi — yeni takım atamaları [?]'),
    0x8b: ('GAME_PAUSE',     'both', 'Oyun duraklatma / devam — nedeni + zaman damgası [?]'),
    0x8c: ('ANTI_CHEAT',     'C→S',  'Anti-hile veri paketi — VMProtect / oyun bütünlük verisi [?]'),
    0x8d: ('PERM_UPDATE',    'S→C',  'Hesap izin / kısıtlama güncellemesi — ban bilgisi [?]'),
    0x8e: ('CHANNEL_PASS',   'C→S',  'Kanala şifreli giriş — VIP kanal şifresi [?]'),
    0x8f: ('EVENT_NOTIF',    'S→C',  'Sunucu etkinliği bildirimi — özel mod başladı / bitti [?]'),
}

# Geçerli proto byte değerleri (PointBlank varyantı):
#   0x0D → standart paket (≤258 B), her iki yön
#   0x0C → büyük istemci paketi (>258 B) — gerçek trafik verisiyle doğrulandı
#   0x0F → büyük sunucu paketi (>258 B) — gerçek trafik verisiyle doğrulandı
# Protokol formatı (confirmed, wire capture analizi):
#   [1B len_lo][1B 0x80|len_hi][1B opcode]  ← DÜZ METİN header (Blowfish DIŞI)
#   [payload bytes …]                        ← Blowfish CFB-64 şifreli
# "proto" alanı artık header'ın flag byte'ı (0x80 | len_hi):
#   her zaman MSB=1 → valid flag check: byte & 0x80 == 0x80
# Eski _VALID_PROTO {0x0C,0x0D,0x0F} tamamen kaldırıldı.
_VALID_FLAG_MASK: int = 0x80   # flag byte'ın MSB daima set olmalı

def _ascii_safe(b: bytes) -> str:
    return ''.join(chr(x) if 0x20 <= x < 0x7f else '.' for x in b)

def _try_string(data: bytes, offset: int) -> tuple[str | None, int]:
    """[1B len][bytes] Pascal string okur.

    Başarılı → (metin, yeni_offset)
    Başarısız → (None, orijinal_offset)  — çağıran hex dump'a düşer.

    Başarısızlık koşulları:
      • slen == 0 veya slen > 64  (makul kullanıcı adı / mesaj uzunluğu dışı)
      • buffer'dan taşıyor
      • baskılanamaz karakter oranı > %25 (ikili / şifreli veri belirtisi)
    """
    if offset >= len(data):
        return None, offset
    slen = data[offset]
    # slen=0: boş string — bu protokolde boş alan başlığı genellikle binary header
    # belirtisidir; None dönderek çağıranın hex fallback'e düşmesini sağla.
    if slen == 0:
        return None, offset
    end = offset + 1 + slen
    if end > len(data):                       # buffer'dan taşıyor → kesinlikle çöp
        return None, offset
    raw = data[offset + 1 : end]
    try:
        text = raw.decode('utf-8', errors='replace')
    except Exception:
        return None, offset
    # Baskılanamaz veya replacement-char (U+FFFD) oranı >%25 ise ikili / şifreli veri.
    # Not: slen > 64 hard limit kaldırıldı — uzun chat mesajları geçerli olabilir;
    # gerçek koruma printability check'tedir (ikili veri %75'in altında kalır).
    printable = sum(1 for c in text if c.isprintable() and c != '\ufffd')
    if printable / len(text) < 0.75:         # len(text)==slen>0 burada garantili
        return None, offset
    return text, end

def _decode_fields(opcode_byte: int, payload: bytes, direction: str) -> list[dict]:
    """Opcode'a göre payload alanlarını ayrıştır. Bilinmeyen → sadece hex dump."""
    fields: list[dict] = []

    def f(name, value, kind='val'):
        fields.append({'n': name, 'v': str(value), 'k': kind})

    # Oyun modu adları (GAME_START / MAP_CHANGE vs. için ortak tablo)
    _GAME_MODES = {
        0x00: 'Deathmatch',
        0x01: 'Team Deathmatch',
        0x02: 'Bomba Modu',
        0x03: 'Bayrak Yarışı (CTF)',
        0x04: 'Survival',
        0x05: 'Keskin Nişancı',
        0x06: 'Zombi Modu',
        0x07: 'AI / Bot Modu',
    }

    # Silah kodu → isim (PLAYER_DEAD / KILL_FEED için)
    _WEAPONS = {
        0x00: 'Bilinmiyor/Çevre',
        0x01: 'Tabanca',
        0x02: 'Pompalı Tüfek',
        0x03: 'SMG',
        0x04: 'Tüfek (Rifle)',
        0x05: 'Keskin Nişancı Tüfeği',
        0x06: 'Makineli Tüfek',
        0x07: 'El Bombası',
        0x08: 'RPG / Roket',
        0x09: 'Bıçak',
        0x0a: 'C4 / Bomba',
        0x0b: 'Özel Silah',
    }

    # Login ACK sonuç kodları
    _LOGIN_RESULTS = {
        0x00: 'Başarılı',
        0x01: 'Hatalı şifre',
        0x02: 'Hesap bulunamadı',
        0x03: 'Zaten giriş yapıldı',
        0x04: 'Sunucu dolu',
        0x05: 'Hesap askıya alındı (ban)',
        0x06: 'Bakım / sunucu kapalı',
        0x07: 'Coğrafi kısıtlama',
        0x08: 'Yaş kısıtlaması',
        0x09: 'İstemci sürümü eski',
        0x0a: 'Güvenlik doğrulama hatası',
    }

    try:
        # ── 0x02 PING / 0x03 PONG ────────────────────────────────────────────
        if opcode_byte in (0x02, 0x03) and len(payload) >= 4:
            ts = struct.unpack_from('<I', payload)[0]
            f('Timestamp (u32 LE)', ts, 'u32')

        # ── 0x04 DISCONNECT ───────────────────────────────────────────────────
        elif opcode_byte == 0x04 and len(payload) >= 1:
            code = payload[0]
            reasons = {0:'Normal', 1:'Zaman aşımı', 2:'Kick', 3:'Sunucu bakımı'}
            f('Neden', f"0x{code:02x} — {reasons.get(code, 'Bilinmiyor')}", 'status')

        # ── 0x06 SESSION_OK ───────────────────────────────────────────────────
        elif opcode_byte == 0x06 and len(payload) >= 4:
            sid = struct.unpack_from('<I', payload)[0]
            f('Session ID', f'0x{sid:08x}', 'hex')

        # ── 0x14 LOGIN_REQ ────────────────────────────────────────────────────
        elif opcode_byte == 0x14 and len(payload) >= 1:
            uname, off = _try_string(payload, 0)
            if uname is not None:
                f('Kullanıcı adı', uname, 'str')
                if off < len(payload):
                    hash_bytes = payload[off:off+32]
                    f('Şifre hash (hex)', hash_bytes.hex(), 'hex')
                    if off + 32 < len(payload):
                        f('Ek veri (hex)', payload[off+32:].hex(), 'hex')
            else:
                # Pascal string okunamadı → tüm payload'ı ham hex olarak göster
                f('Payload (ham hex — format belirsiz)', payload[:80].hex(), 'hex')

        # ── 0x15 LOGIN_ACK ────────────────────────────────────────────────────
        elif opcode_byte == 0x15 and len(payload) >= 1:
            code = payload[0]
            f('Sonuç', f"0x{code:02x} — {_LOGIN_RESULTS.get(code, 'Bilinmiyor')}", 'status')
            if code == 0x00:
                if len(payload) >= 5:
                    uid = struct.unpack_from('<I', payload, 1)[0]
                    f('Kullanıcı ID (u32)', uid, 'u32')
                if len(payload) >= 7:
                    level = struct.unpack_from('<H', payload, 5)[0]
                    f('Seviye', level, 'u16')

        # ── 0x17 USER_INFO ────────────────────────────────────────────────────
        elif opcode_byte == 0x17 and len(payload) >= 4:
            uid = struct.unpack_from('<I', payload, 0)[0]
            f('Kullanıcı ID', uid, 'u32')
            if len(payload) >= 6:
                level = struct.unpack_from('<H', payload, 4)[0]
                f('Seviye', level, 'u16')
            if len(payload) >= 10:
                xp = struct.unpack_from('<I', payload, 6)[0]
                f('Deneyim (XP)', xp, 'u32')

        # ── 0x32 GAME_START ───────────────────────────────────────────────────
        elif opcode_byte == 0x32 and len(payload) >= 2:
            map_id = struct.unpack_from('<H', payload, 0)[0]
            f('Harita ID', f'{map_id} (0x{map_id:04x})', 'u16')
            if len(payload) >= 3:
                mode = payload[2]
                f('Oyun modu', f"0x{mode:02x} — {_GAME_MODES.get(mode, 'Bilinmiyor')}", 'val')
            if len(payload) >= 4:
                teams = payload[3]
                f('Takım sayısı', teams, 'u32')

        # ── 0x33 GAME_END ─────────────────────────────────────────────────────
        elif opcode_byte == 0x33 and len(payload) >= 1:
            winner = payload[0]
            f('Kazanan takım', 'Mavi' if winner == 0 else ('Kırmızı' if winner == 1 else f'0x{winner:02x}'), 'val')
            if len(payload) >= 5:
                score_a = struct.unpack_from('<H', payload, 1)[0]
                score_b = struct.unpack_from('<H', payload, 3)[0]
                f('Takım A skoru', score_a, 'u16')
                f('Takım B skoru', score_b, 'u16')

        # ── 0x3c SPAWN ────────────────────────────────────────────────────────
        elif opcode_byte == 0x3c and len(payload) >= 12:
            x, y, z = struct.unpack_from('<fff', payload, 0)
            f('Spawn X', f'{x:.2f}', 'float')
            f('Spawn Y', f'{y:.2f}', 'float')
            f('Spawn Z', f'{z:.2f}', 'float')
            if len(payload) >= 13:
                team = payload[12]
                f('Takım', 'Mavi (0)' if team == 0 else (f'Kırmızı (1)' if team == 1 else f'0x{team:02x}'), 'val')
            if len(payload) >= 14:
                f('Spawn flag@13', f'0x{payload[13]:02x}', 'hex')

        # ── 0x3d MOVE ─────────────────────────────────────────────────────────
        elif opcode_byte == 0x3d and len(payload) >= 12:
            x, y, z = struct.unpack_from('<fff', payload, 0)
            f('X', f'{x:.3f}', 'float')
            f('Y', f'{y:.3f}', 'float')
            f('Z', f'{z:.3f}', 'float')
            if len(payload) >= 14:
                yaw = struct.unpack_from('<H', payload, 12)[0]
                f('Yaw açısı', f'{yaw} ({yaw / 65535 * 360:.1f}°)', 'u16')
            if len(payload) >= 15:
                flags = payload[14]
                f('Hareket bayrakları@14', f'0x{flags:02x}', 'hex')

        # ── 0x3e JUMP ─────────────────────────────────────────────────────────
        elif opcode_byte == 0x3e and len(payload) >= 12:
            x, y, z = struct.unpack_from('<fff', payload, 0)
            f('Konum X', f'{x:.2f}', 'float')
            f('Konum Y', f'{y:.2f}', 'float')
            f('Konum Z', f'{z:.2f}', 'float')

        # ── 0x40 STANCE (büyük binary; login akışında 288 B payload) ─────────
        elif opcode_byte == 0x40 and len(payload) >= 4:
            maybe_id = struct.unpack_from('<I', payload, 0)[0]
            f('Alan@0 (u32, olası oyuncu ID)', f'0x{maybe_id:08x}', 'hex')
            f('Payload boyutu', len(payload), 'u32')
            if len(payload) >= 8:
                second = struct.unpack_from('<I', payload, 4)[0]
                f('Alan@4 (u32)', f'0x{second:08x}', 'hex')

        # ── 0x42 DAMAGE_NOTIF ─────────────────────────────────────────────────
        elif opcode_byte == 0x42 and len(payload) >= 4:
            damage = struct.unpack_from('<H', payload, 0)[0]
            hp_rem = struct.unpack_from('<H', payload, 2)[0]
            f('Hasar miktarı', damage, 'u16')
            f('Kalan HP', hp_rem, 'u16')

        # ── 0x45 CHAR_DATA (160 B payload) ───────────────────────────────────
        elif opcode_byte == 0x45 and len(payload) >= 4:
            # İlk u32: büyük olasılıkla oyuncu/session ID
            maybe_id = struct.unpack_from('<I', payload, 0)[0]
            f('Alan@0 (u32, olası oyuncu ID)', f'0x{maybe_id:08x}', 'hex')
            f('Payload boyutu', len(payload), 'u32')
            if len(payload) >= 8:
                second = struct.unpack_from('<I', payload, 4)[0]
                f('Alan@4 (u32)', f'0x{second:08x}', 'hex')

        # ── 0x46 SHOOT ────────────────────────────────────────────────────────
        elif opcode_byte == 0x46 and len(payload) >= 1:
            slot = payload[0]
            f('Silah slot', f'0x{slot:02x}', 'hex')
            if len(payload) >= 13:
                x, y, z = struct.unpack_from('<fff', payload, 1)
                f('Hedef X', f'{x:.2f}', 'float')
                f('Hedef Y', f'{y:.2f}', 'float')
                f('Hedef Z', f'{z:.2f}', 'float')

        # ── 0x47 HIT (32 B payload) ───────────────────────────────────────────
        elif opcode_byte == 0x47 and len(payload) >= 6:
            # Uyarı: oyun içi HIT semantiği varsayılıyor.
            # Login fazında (35 B buffer) alan anlamları farklı olabilir.
            v0 = struct.unpack_from('<H', payload, 0)[0]
            v2 = struct.unpack_from('<H', payload, 2)[0]
            v4 = struct.unpack_from('<H', payload, 4)[0]
            f('Alan@0 (u16)', f'0x{v0:04x} ({v0})', 'hex')
            f('Alan@2 (u16)', f'0x{v2:04x} ({v2})', 'hex')
            f('Alan@4 (u16, olası hasar)', f'0x{v4:04x} ({v4})', 'hex')
            if len(payload) >= 7:
                zone = payload[6]
                f('Alan@6 (u8, olası vurulan bölge)', f'0x{zone:02x}', 'hex')

        # ── 0x4b PLAYER_DEAD ─────────────────────────────────────────────────
        elif opcode_byte == 0x4b and len(payload) >= 4:
            killer = struct.unpack_from('<H', payload, 0)[0]
            victim = struct.unpack_from('<H', payload, 2)[0]
            f('Öldüren oyuncu ID', f'{killer} (0x{killer:04x})', 'u16')
            f('Ölen oyuncu ID',    f'{victim} (0x{victim:04x})', 'u16')
            if len(payload) >= 5:
                wcode = payload[4]
                f('Silah kodu', f"0x{wcode:02x} — {_WEAPONS.get(wcode, 'Bilinmiyor')}", 'val')
            if len(payload) >= 6:
                f('Ek bayt@5', f'0x{payload[5]:02x}', 'hex')

        # ── 0x4c CHAT ─────────────────────────────────────────────────────────
        elif opcode_byte == 0x4c and len(payload) >= 2:
            # Oyun içi: [1B len][string gönderen][1B len][string mesaj]
            # Login fazı: 16 B binary token — Pascal string parse başarısız olursa hex
            sender, off = _try_string(payload, 0)
            if sender is not None:
                f('Gönderen', sender, 'str')
                if off < len(payload):
                    msg, _ = _try_string(payload, off)
                    if msg is not None:
                        f('Mesaj', msg, 'str')
                    else:
                        f('Mesaj (ham hex)', payload[off:].hex(), 'hex')
            else:
                f('Token / Binary (ham hex)', payload.hex(), 'hex')

        # ── 0x4d SERVER_REDIR ─────────────────────────────────────────────────
        elif opcode_byte == 0x4d and len(payload) >= 6:
            ip_bytes = payload[0:4]
            ip_str   = '.'.join(str(b) for b in ip_bytes)
            port     = struct.unpack_from('<H', payload, 4)[0]
            f('Hedef IP', ip_str, 'str')
            f('Port', port, 'u16')

        # ── 0x4e GRENADE ─────────────────────────────────────────────────────
        elif opcode_byte == 0x4e and len(payload) >= 1:
            gtype = payload[0]
            f('Bomba tipi', f'0x{gtype:02x}', 'hex')
            if len(payload) >= 13:
                x, y, z = struct.unpack_from('<fff', payload, 1)
                f('Başlangıç X', f'{x:.2f}', 'float')
                f('Başlangıç Y', f'{y:.2f}', 'float')
                f('Başlangıç Z', f'{z:.2f}', 'float')

        # ── 0x50 SCORE ────────────────────────────────────────────────────────
        elif opcode_byte == 0x50 and len(payload) >= 4:
            team_a = struct.unpack_from('<H', payload, 0)[0]
            team_b = struct.unpack_from('<H', payload, 2)[0]
            f('Takım A (Mavi)', team_a, 'u16')
            f('Takım B (Kırmızı)', team_b, 'u16')
            if len(payload) >= 6:
                f('Alan@4 (u16)', struct.unpack_from('<H', payload, 4)[0], 'u16')

        # ── 0x51 KILL_FEED ────────────────────────────────────────────────────
        elif opcode_byte == 0x51 and len(payload) >= 4:
            killer = struct.unpack_from('<H', payload, 0)[0]
            victim = struct.unpack_from('<H', payload, 2)[0]
            f('Öldüren ID', f'{killer} (0x{killer:04x})', 'u16')
            f('Ölen ID',    f'{victim} (0x{victim:04x})', 'u16')
            if len(payload) >= 5:
                wcode = payload[4]
                f('Silah', f"0x{wcode:02x} — {_WEAPONS.get(wcode, 'Bilinmiyor')}", 'val')

        # ── 0x55 SESSION_REQ / 0x57 DATA_ACK (16 B payload) ─────────────────
        elif opcode_byte in (0x55, 0x57) and len(payload) >= 2:
            # Binary token — gerçek trafik verisiyle C→S doğrulandı [✓]
            tok = payload[:16].hex() if len(payload) >= 16 else payload.hex()
            f('Token (hex)', tok, 'hex')
            if len(payload) >= 4:
                maybe_id = struct.unpack_from('<I', payload, 0)[0]
                f('Alan@0 (u32, olası token ID)', f'0x{maybe_id:08x}', 'hex')
            if len(payload) >= 8:
                second   = struct.unpack_from('<I', payload, 4)[0]
                f('Alan@4 (u32)', f'0x{second:08x}', 'hex')

        # ── 0x56 XP_UPDATE ────────────────────────────────────────────────────
        elif opcode_byte == 0x56 and len(payload) >= 4:
            xp = struct.unpack_from('<I', payload, 0)[0]
            f('Yeni XP (u32)', xp, 'u32')
            if len(payload) >= 6:
                level = struct.unpack_from('<H', payload, 4)[0]
                f('Yeni seviye', level, 'u16')

        # ── 0x64 HEARTBEAT ────────────────────────────────────────────────────
        elif opcode_byte == 0x64 and len(payload) >= 4:
            ts = struct.unpack_from('<I', payload)[0]
            f('Timestamp (u32 LE)', ts, 'u32')

        # ── 0x6e SERVER_INFO ─────────────────────────────────────────────────
        elif opcode_byte == 0x6e and len(payload) >= 6:
            ip_bytes = payload[0:4]
            ip_str   = '.'.join(str(b) for b in ip_bytes)
            port     = struct.unpack_from('<H', payload, 4)[0]
            f('Sunucu IP', ip_str, 'str')
            f('Port', port, 'u16')
            if len(payload) >= 7:
                region = payload[6]
                f('Bölge kodu', f'0x{region:02x}', 'hex')

        # ── 0x7b FRIEND_LIST (88 B veya 752 B payload) ───────────────────────
        elif opcode_byte == 0x7b and len(payload) >= 2:
            f('Payload boyutu', len(payload), 'u32')
            if len(payload) >= 2:
                maybe_count = struct.unpack_from('<H', payload, 0)[0]
                f('Alan@0 (u16, olası arkadaş sayısı)', f'{maybe_count} (0x{maybe_count:04x})', 'hex')
            if len(payload) >= 4:
                second = struct.unpack_from('<H', payload, 2)[0]
                f('Alan@2 (u16)', f'{second} (0x{second:04x})', 'hex')
            if len(payload) >= 6:
                third = struct.unpack_from('<H', payload, 4)[0]
                f('Alan@4 (u16)', f'{third} (0x{third:04x})', 'hex')

    except Exception:
        pass  # parse hatası → sadece hex dump göster

    return fields

def decode_packet(opcode_byte: int, payload: bytes, direction: str,
                  parse_fields: bool = True) -> dict:
    """Paketi ayrıştır: isim + açıklama + alanlar + hex dump döndür.

    parse_fields=False → sadece isim/açıklama + hex dump; _decode_fields çalışmaz.
    Şifre çözme yanlış olan (mismatch / proto?) paketlerde çöp field göstermemek için
    fmt_packet bu parametreyi status'e göre geçirir.
    """
    entry = _OPCODES.get(opcode_byte)
    name  = entry[0] if entry else f'UNK_{opcode_byte:02X}'
    hint  = entry[1] if entry else '?'
    desc  = entry[2] if entry else 'Bilinmeyen opcode — ham veri gösteriliyor'

    fields = _decode_fields(opcode_byte, payload, direction) if parse_fields else []

    # Hex dump (her zaman eklenir)
    dump_rows = []
    for i in range(0, len(payload), 16):
        chunk = payload[i:i+16]
        dump_rows.append({
            'off': f'{i:04x}',
            'hex': ' '.join(f'{b:02x}' for b in chunk),
            'asc': _ascii_safe(chunk),
        })

    return {
        'name':   name,
        'hint':   hint,
        'desc':   desc,
        'fields': fields,
        'dump':   dump_rows,
        'pay_len': len(payload),
    }

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
    # Yeni protokol formatı: header (plain[0:3]) düz metin
    #   plain[0] = len_lo
    #   plain[1] = 0x80 | len_hi  (flag byte, MSB daima 1)
    #   plain[2] = opcode (düz metin)
    #   plain[3:] = Blowfish çözülmüş payload
    base['len_field']   = plain[0] if plain else None
    base['proto']       = plain[1] if len(plain) > 1 else None   # flag byte
    base['payload_hex'] = plain[3:67].hex() if len(plain) > 3 else ''

    op_byte = plain[2] if len(plain) > 2 else None
    base['opcode'] = op_byte

    # Geçerlilik kontrolü — header düz metin olduğundan plain[0:2] == raw[0:2]
    flag_byte   = plain[1] if len(plain) > 1 else 0
    flag_ok     = bool(flag_byte & _VALID_FLAG_MASK)          # MSB = 1
    payload_len = plain[0] | ((flag_byte & 0x7F) << 8)        # 2-byte uzunluk
    len_ok      = (3 + payload_len == size)

    if len_ok and flag_ok:
        base['status'] = 'ok'
    elif flag_ok and not len_ok:
        base['status'] = 'large'
    elif len_ok and not flag_ok:
        base['status'] = 'proto?'
    else:
        base['status'] = 'mismatch'

    # Decode packet fields
    # parse_fields sadece şifre çözme güvenilirken açık — mismatch/proto? durumunda
    # ikili çöp üzerinde field parser çalıştırmak yanıltıcı sonuçlar üretir.
    _good_status = base['status'] in ('ok', 'large')
    if op_byte is not None:
        payload = plain[3:]
        dec = decode_packet(op_byte, payload, direction, parse_fields=_good_status)
        base['decoded'] = dec
        base['pkt_name'] = dec['name']
        base['opcode'] = f"0x{op_byte:02x}"
    else:
        base['decoded'] = None
        base['pkt_name'] = ''
        base['opcode'] = None

    if base['proto'] is not None:
        base['proto'] = f"0x{base['proto']:02x}"
    return base


def _walk_subpackets(raw: bytes) -> list[dict]:
    """Büyük TCP tamponunu bağımsız PointBlank alt paketlerine ayır.

    Protokol formatı (her alt paket için):
      raw[i+0] = len_lo          (DÜZ METİN)
      raw[i+1] = 0x80|len_hi    (DÜZ METİN, MSB daima 1)
      raw[i+2] = opcode          (DÜZ METİN)
      raw[i+3 : i+total]         = Blowfish şifreli payload

    Her alt paketin payload'ı bağımsız olarak n=0'dan çözülür;
    session.decrypt_subpkt() bunu yapar.

    Geçerlilik kuralı (veri kaybı olmadan):
      • buffer tamamen tüketildi (leftover == 0), VEYA
      • kalan bayt sayısı < 3 (geçerli bir paket için minimum — padding sayılır).
    Herhangi bir anlamlı artık varsa (leftover >= 3) split yapılmaz."""
    pkts = []
    i    = 0
    while i + 3 <= len(raw):
        len_lo  = raw[i]
        flag    = raw[i + 1]
        opcode  = raw[i + 2]
        if not (flag & _VALID_FLAG_MASK):
            break                           # flag byte geçersiz → framing bozuk
        payload_len = len_lo | ((flag & 0x7F) << 8)
        total       = 3 + payload_len
        if i + total > len(raw):
            break                           # buffer taşıyor → tamamlanmamış
        sub_raw = raw[i: i + total]
        pkts.append({
            'offset':  i,
            'total':   total,
            'op':      opcode,
            'len':     payload_len,
            'sub_raw': sub_raw,
            # sub_plain: on_dll_frame / _redecrypt_session içinde dekript edilir
        })
        i += total

    if not pkts:
        return []

    leftover = len(raw) - i
    # Split yalnızca buffer tamamen tüketildiyse VEYA kalan < 3B (padding)
    if leftover == 0 or (len(pkts) >= 2 and leftover < 3):
        return pkts
    return []   # anlamlı artık var → split yapılmaz, orijinal event korunur

# ─── WebSocket: DLL bağlantısı (/dll) ────────────────────────────────────────

def _clear_log_data():
    """Eski oturumun log dosyalarını sil — yeni oturum taze başlasın."""
    log_dir = 'log_data'
    if not os.path.isdir(log_dir):
        return
    deleted = []
    for fname in os.listdir(log_dir):
        if fname.endswith('.log'):
            try:
                os.remove(os.path.join(log_dir, fname))
                deleted.append(fname)
            except OSError:
                pass
    if deleted:
        print(f'[SESSION] Eski log dosyaları silindi: {", ".join(deleted)}')

async def dll_handler(request):
    # ── Token doğrulama (SESSION_SECRET) ──────────────────────────────────
    if PROXY_TOKEN:
        auth = request.headers.get('Authorization', '')
        token = auth.removeprefix('Bearer ').strip()
        if token != PROXY_TOKEN:
            return web.Response(status=401, text='Unauthorized')

    # heartbeat=None — WinHTTP PING/PONG'u protokol seviyesinde kendisi yönetir;
    # sunucu taraflı heartbeat WinHttpWebSocketReceive'i bozup bağlantıyı kesebilir.
    # Replit proxy idle timeout için uygulama seviyesinde keepalive kullanıyoruz.
    ws = web.WebSocketResponse(max_msg_size=8 * 1024 * 1024, heartbeat=None)
    await ws.prepare(request)

    peer = request.remote or '?'
    session.dll_clients.add(ws)
    session._dll_ws_latest = ws
    dll_count = len(session.dll_clients)
    print(f'[DLL] Bağlandı: {peer}  (aktif={dll_count})')

    # NOT: Eski bağlantılar zorla kapatılmıyor — DLL yeniden bağlanma döngüsüne
    # girmeden kendi kapanmasını bekle. Yeni oyun oturumu challenge frame'iyle tespit edilir.
    await broadcast({'type': 'dll_connected', 'peer': peer,
                     'count': dll_count})

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.BINARY:
                await on_dll_frame(ws, msg.data)
            elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                break
    finally:
        session.dll_clients.discard(ws)
        if session._dll_ws_latest is ws:
            session._dll_ws_latest = None
        remaining = len(session.dll_clients)
        print(f'[DLL] Bağlantı kesildi: {peer}  (kalan={remaining})')
        if remaining == 0:
            await broadcast({'type': 'dll_disconnected'})
        else:
            await broadcast({'type': 'dll_connected',
                             'peer': '(diğer bağlantı devrede)',
                             'count': remaining})

    return ws

# BF_KEY boyutu: P-array (18 × 4B) + S-box'lar (4 × 256 × 4B) = 4168 byte
BF_KEY_SIZE = (18 + 4 * 256) * 4

async def _handle_key_frame(raw: bytes):
    """DLL'den gelen KEY frame (0x4B): BF_KEY yükle.
    Doğrulanmamış DLL bellek taraması anahtarı bf_key.bin'e yazılmaz —
    önbellekteki onaylı anahtar korunur; yalnızca OpenSSL hook / crack
    ile doğrulanan anahtarlar bf_key.bin'i günceller."""
    if len(raw) < BF_KEY_SIZE:
        return
    P = list(struct.unpack_from('<18I', raw, 0))
    S = [list(struct.unpack_from('<256I', raw, (18 + i * 256) * 4)) for i in range(4)]
    sig = (S[0][0], S[1][0], S[2][0], S[3][0])
    is_confirmed = sig == CONFIRMED_SIG
    # Doğrulanmamış DLL key frame: bf_key.bin'i KORUMA — yanlış key önbelleği kirletmesin
    session.set_key(P, S, save_cache=is_confirmed)
    confirmed = '✓ ONAYLANDI' if is_confirmed else '(doğrulanmadı — önbelleksiz)'
    sig_str   = ' '.join(f'{x:08x}' for x in sig)
    msg = f'Anahtar DLL\'den otomatik yüklendi {confirmed} — SIG={sig_str}'
    print(f'[KEY] {msg}')
    await broadcast({'type': 'key_loaded', 'iv': session.iv.hex() if session.iv else None})
    await broadcast({'type': 'status', 'msg': msg, 'level': 'ok'})
    await _redecrypt_session()  # önceden encrypted gelen paketleri yeniden çöz

async def _redecrypt_session():
    """Tüm paketleri per-buffer modda yeniden çöz.
    - Büyük buffer'lar (>258B): sub-paketlere ayrılır, her biri bağımsız event olarak kaydedilir.
    - Küçük paketler: şifre açılır, status/opcode güncellenir.
    - Seq numaraları expansion sonrası yeniden atanır."""
    if not session.has_key() or not session.has_iv():
        return
    new_packets = []
    changed = 0
    for ev in session.packets:
        status = ev.get('status')
        raw    = bytes.fromhex(ev.get('raw_hex', ''))

        if status == 'challenge' or not raw:
            new_packets.append(ev)
            continue

        # Büyük buffer: sub-paket ayrıştırması dene (raw üzerinden — header düz metin)
        if ev.get('size', 0) > 258 and status in ('encrypted', 'mismatch', 'proto?', 'large'):
            subs = _walk_subpackets(raw)
            if subs:
                for sub in subs:
                    sub_plain = session.decrypt_subpkt(sub['sub_raw'])
                    sub_ev = fmt_packet(0, ev['dir'],
                                        sub['sub_raw'], sub_plain, ev['ts'])
                    sub_ev['note'] = f'buf:{len(raw)}B @{sub["offset"]} (retro)'
                    new_packets.append(sub_ev)
                changed += len(subs)
                continue  # orijinal büyük event yerine sub-event'ler kullanılır

        # Küçük / ayrıştırılamayan paket — yeniden çöz ve yerinde güncelle
        if status in ('encrypted', 'mismatch', 'proto?'):
            plain = session.decrypt(raw, ev.get('dir', 'R'))
            if plain is None:
                new_packets.append(ev)
                continue
            ev['plain_hex']   = plain.hex()
            ev['len_field']   = plain[0] if plain else None
            ev['payload_hex'] = plain[3:67].hex() if len(plain) > 3 else ''
            op_byte           = plain[2] if len(plain) > 2 else None
            sz        = ev['size']
            flag_byte = plain[1] if len(plain) > 1 else 0
            ev['proto'] = flag_byte
            flag_ok   = bool(flag_byte & _VALID_FLAG_MASK)
            pay_len   = plain[0] | ((flag_byte & 0x7F) << 8)
            len_ok    = (3 + pay_len == sz)
            if len_ok and flag_ok:      ev['status'] = 'ok'
            elif flag_ok:               ev['status'] = 'large'
            elif len_ok:                ev['status'] = 'proto?'
            else:                       ev['status'] = 'mismatch'
            if op_byte is not None:
                _good = ev['status'] in ('ok', 'large')
                dec = decode_packet(op_byte, plain[3:], ev.get('dir', 'R'),
                                    parse_fields=_good)
                ev['decoded']   = dec
                ev['pkt_name']  = dec['name']
                ev['opcode']    = f"0x{op_byte:02x}"
            if ev['proto'] is not None: ev['proto'] = f"0x{ev['proto']:02x}"
            ev['note'] = 'retroaktif çözüldü'
            if ev['status'] != status:
                changed += 1

        new_packets.append(ev)

    if changed:
        # Seq numaralarını yeniden ata (expansion sonrası sıra bozulabilir)
        for i, ev in enumerate(new_packets):
            ev['seq'] = i
        session.packets = new_packets
        session.seq     = len(new_packets)
        print(f'[REDECRYPT] {changed} event güncellendi → toplam {len(new_packets)} event')
        await broadcast({'type': 'redecrypted', 'packets': session.packets[-500:]})
        await broadcast({'type': 'status',
                         'msg':   f'✓ Retroaktif çözüm: {changed} event güncellendi',
                         'level': 'ok'})

async def on_dll_frame(dll_ws, data: bytes):
    """DLL'den gelen binary frame: [1B type][1B dir][4B len LE][...data...]
    dll_ws: isteği gönderen spesifik DLL WebSocket'i (ACK yanıtı buraya gider)."""
    if len(data) < 6:
        return
    pkt_type  = data[0]      # 'P'=0x50 'K'=0x4B 'C'=0x43
    direction = chr(data[1]) # 'R' or 'S'
    data_len  = struct.unpack_from('<I', data, 2)[0]

    if data_len > len(data) - 6:
        return

    # KEY frame: DLL bellek taramasında anahtar bulunca otomatik gönderir
    if pkt_type == 0x4B:
        await _handle_key_frame(data[6: 6 + data_len])
        return

    # INTERCEPT_REQ frame: [0x58][dir][4B seq LE][4B data_len LE][data…]
    # DLL hook_send/hook_recv'den gelir; proxy onaylayana kadar DLL bekler (≤25 ms).
    if pkt_type == 0x58:
        if len(data) < 10:
            return
        seq      = struct.unpack_from('<I', data, 2)[0]
        icpt_len = struct.unpack_from('<I', data, 6)[0]
        payload  = data[10: 10 + icpt_len]

        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        session.pending_intercepts[seq] = fut

        await broadcast({
            'type':    'intercept_req',
            'seq':     seq,
            'dir':     direction,
            'size':    icpt_len,
            'raw_hex': payload.hex(),
        })

        # 25 ms timeout — DLL'in timeout'u ile eşleşir
        try:
            modified_hex: str | None = await asyncio.wait_for(
                asyncio.shield(fut), timeout=0.025)
        except asyncio.TimeoutError:
            modified_hex = None
        finally:
            session.pending_intercepts.pop(seq, None)

        # ICPT_ACK frame: [0x41][dir][4B seq LE][4B data_len LE][data…]
        # data_len==0 → pass-through (DLL orijinal veriyi kullanır)
        if modified_hex:
            try:
                mod_bytes = bytes.fromhex(modified_hex)
            except ValueError:
                mod_bytes = b''
        else:
            mod_bytes = b''
        ack = (bytes([0x41, data[1]])
               + struct.pack('<I', seq)
               + struct.pack('<I', len(mod_bytes))
               + mod_bytes)
        # ACK'yi isteği gönderen spesifik DLL bağlantısına yolla
        if dll_ws and not dll_ws.closed:
            await dll_ws.send_bytes(ack)
        return

    # CHALLENGE frame: DLL kayıtlı challenge'ı bağlantıda otomatik gönderir
    if pkt_type == 0x43:
        raw = data[6: 6 + data_len]
        if len(raw) >= 11 and raw[0] == 0xc5:
            new_iv = bytes(raw[3:11])
            iv_changed = (session.iv != new_iv)

            # Mevcut paketler varsa skora göre karar ver — çalışan IV'i ezmemek için
            if session.packets and session.has_key():
                accepted = session.apply_iv_if_better(new_iv)
                is_new_session = accepted and iv_changed
            else:
                # Henüz paket yok: IV'i doğrudan ata
                session.try_challenge(raw)
                is_new_session = iv_changed

            if is_new_session:
                # Yeni oyun oturumu: eski paketler ve log_data temizle
                print(f'[SESSION] Yeni oyun oturumu tespit edildi (IV değişti) — temizleniyor')
                _clear_log_data()
                session.packets.clear()
                session.seq = 0
                await broadcast({'type': 'cleared'})

            lvl = 'ok' if session.has_key() else 'warn'
            msg = (f'Challenge (DLL geçmişi) — IV={session.iv.hex()}' if session.has_key()
                   else f'Challenge (DLL geçmişi) — IV={session.iv.hex()} — anahtar bekleniyor')
            print(f'[CHG] {msg}')
            await broadcast({'type': 'key_loaded', 'iv': session.iv.hex()})
            await broadcast({'type': 'status', 'msg': msg, 'level': lvl})
            await _redecrypt_session()
        return

    raw = data[6: 6 + data_len]
    ts  = time.strftime('%H:%M:%S')

    # Challenge tespiti (tam 202B, 0xc5 ile başlar)
    # ÖNEMLI: boyut kontrolü zorunlu — rastgele şifreli paket 0xc5 ile başlarsa
    # yanlış IV atanır ve tüm akış bozulur (mismatch).
    if direction == 'R' and len(raw) == 202 and len(raw) >= 11 and raw[0] == 0xc5:
        new_iv = bytes(raw[3:11])
        session.apply_iv_if_better(new_iv)   # apply_iv_if_better: çalışan IV'i ezmez
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
        await _redecrypt_session()  # anahtar varsa mevcut encrypted paketleri çöz
        return

    # Büyük buffer: birden fazla game sub-paketi içerebilir
    # Header (raw[0:3]) düz metin olduğundan raw üzerinden walk edilir;
    # her alt paketin payload'ı bağımsız olarak decrypt_subpkt ile çözülür.
    if len(raw) > 258 and session.has_key() and session.has_iv():
        subs = _walk_subpackets(raw)
        if subs:
            for sub in subs:
                sub_plain = session.decrypt_subpkt(sub['sub_raw'])
                ev = fmt_packet(session.seq, direction,
                                sub['sub_raw'], sub_plain, ts)
                ev['note'] = f'buf:{len(raw)}B @{sub["offset"]}'
                session.seq += 1
                _store(ev)
                await broadcast({'type': 'packet', 'pkt': ev})
            return

    plain = session.decrypt(raw, direction)

    ev = fmt_packet(session.seq, direction, raw, plain, ts)
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

    elif t == 'intercept_mode':
        # UI intercept modunu aç/kapat; DLL'e ICPT_CFG frame gönderir.
        # {'type':'intercept_mode', 'enabled': bool, 'dir_mask': int (1=S 2=R 3=both)}
        enabled   = bool(cmd.get('enabled', False))
        dir_mask  = int(cmd.get('dir_mask', 3)) & 0xFF
        session.intercept_mode    = enabled
        session.intercept_dir_mask = dir_mask
        # ICPT_CFG: [0x46][dir_mask:1][enabled:1]
        cfg_frame = bytes([0x46, dir_mask, 1 if enabled else 0])
        dll = session.dll_ws
        if dll and not dll.closed:
            await dll.send_bytes(cfg_frame)
        await broadcast({'type': 'intercept_status',
                         'enabled': enabled, 'dir_mask': dir_mask})

    elif t == 'intercept_ack':
        # UI paketi onayladı/değiştirdi.
        # {'type':'intercept_ack', 'seq': int, 'hex': str}  (hex=='' → pass-through)
        seq = cmd.get('seq')
        hex_mod = cmd.get('hex', '')
        fut = session.pending_intercepts.get(seq)
        if fut and not fut.done():
            fut.set_result(hex_mod if hex_mod else None)
        else:
            await ws.send_json({'type': 'status', 'msg': 'intercept seq bulunamadı', 'level': 'warn'})

    elif t == 'intercept_pass':
        # UI paketi değiştirmeden geçirdi.
        seq = cmd.get('seq')
        fut = session.pending_intercepts.get(seq)
        if fut and not fut.done():
            fut.set_result(None)

    elif t == 'clear':
        session.packets.clear()
        session.seq = 0
        await broadcast({'type': 'cleared'})

    elif t == 'load_key':
        path = cmd.get('path', 'log_data/pb_crypto.log')
        P, S = load_key(path)
        if P and S:
            session.set_key(P, S)
            await ws.send_json({'type': 'status', 'msg': f'Anahtar yüklendi: {path}', 'level': 'ok'})
        else:
            await ws.send_json({'type': 'status', 'msg': f'Anahtar bulunamadı: {path}', 'level': 'error'})

    elif t == 'set_key_hex':
        # Manuel anahtar girişi: P+S hex (4168B = 8336 hex kar.)
        # ya da sadece P-array hex (72B = 144 hex kar.) — crypto log'dan kopyalanabilir
        hex_raw = cmd.get('hex', '').replace(' ', '').replace('\n', '').lower()
        try:
            raw = bytes.fromhex(hex_raw)
        except ValueError as e:
            await ws.send_json({'type': 'status', 'msg': f'Geçersiz hex: {e}', 'level': 'error'})
            return
        expected = (18 + 4 * 256) * 4   # 4168 bytes tam anahtar
        if len(raw) < expected:
            await ws.send_json({'type': 'status',
                                'msg': f'Anahtar çok kısa: {len(raw)}B (beklenen {expected}B)',
                                'level': 'error'})
            return
        P = list(struct.unpack_from('<18I', raw, 0))
        S = [list(struct.unpack_from('<256I', raw, (18 + i * 256) * 4)) for i in range(4)]
        session.set_key(P, S)
        sig = (S[0][0], S[1][0], S[2][0], S[3][0])
        confirmed = '✓ ONAYLANDI' if sig == CONFIRMED_SIG else '(doğrulanmadı)'
        msg = f'Manuel anahtar yüklendi {confirmed} — SIG={" ".join(f"{x:08x}" for x in sig)}'
        print(f'[KEY] {msg}')
        await broadcast({'type': 'key_loaded', 'iv': session.iv.hex() if session.iv else None})
        await broadcast({'type': 'status', 'msg': msg, 'level': 'ok'})
        await _redecrypt_session()

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
.c-seq{width:40px}.c-ts{width:72px}.c-dir{width:36px}
.c-sz{width:52px}.c-st{width:66px}.c-op{width:56px}
.c-nm{width:110px}.c-pay{width:auto}

.dR{color:var(--green)}.dS{color:var(--blue)}
.s-ok{color:var(--green)}.s-large{color:#7ee787}
.s-challenge{color:var(--yellow);font-weight:700}
.s-proto{color:#7dcfff}.s-mismatch{color:var(--gray)}.s-encrypted{color:#3a3f4a}
.s-truncated{color:#555e6a}

/* Right panel */
#right{width:440px;display:flex;flex-direction:column;border-left:1px solid var(--border);overflow:hidden;flex-shrink:0}

/* Detail */
#detail{flex:1;overflow-y:auto;padding:0}
#detail-hd{background:var(--bg2);border-bottom:1px solid var(--border);
  padding:6px 12px;font-size:11px;color:var(--blue);flex-shrink:0}

/* Packet name hero */
.pkt-hero{padding:10px 12px 6px;border-bottom:1px solid var(--border)}
.pkt-hero-name{font-size:15px;font-weight:700;color:var(--text);letter-spacing:1px}
.pkt-hero-name.unk{color:var(--gray)}
.pkt-hero-desc{font-size:10px;color:var(--gray);margin-top:3px}
.pkt-badges{display:flex;gap:5px;margin-top:6px;flex-wrap:wrap}
.pb{font-size:10px;padding:1px 7px;border-radius:10px;border:1px solid;background:transparent}
.pb-recv{color:var(--green);border-color:var(--green)44}
.pb-send{color:var(--blue);border-color:var(--blue)44}
.pb-both{color:var(--yellow);border-color:var(--yellow)44}
.pb-unk{color:var(--gray);border-color:var(--border)}
.pb-st-ok{color:var(--green);border-color:var(--green)44}
.pb-st-large{color:#7ee787;border-color:#7ee78744}
.pb-st-mismatch,.pb-st-encrypted{color:var(--gray);border-color:var(--border)}
.pb-st-challenge{color:var(--yellow);border-color:var(--yellow)44}
.pb-st-proto{color:#7dcfff;border-color:#7dcfff44}

/* Meta row */
.pkt-meta{padding:6px 12px;border-bottom:1px solid var(--border);display:flex;gap:12px;flex-wrap:wrap}
.pm{font-size:10px;color:var(--gray)}.pm b{color:var(--text)}

/* Decoded fields */
.sec-hd{padding:5px 12px;font-size:9px;color:var(--gray);text-transform:uppercase;
  letter-spacing:1.5px;background:var(--bg2);border-bottom:1px solid var(--border);
  border-top:1px solid var(--border);margin-top:4px}
.field-tbl{width:100%;border-collapse:collapse}
.field-tbl td{padding:3px 12px;font-size:11px;vertical-align:top;
  border-bottom:1px solid #1a1f27}
.field-tbl .fk{color:var(--gray);width:38%;white-space:nowrap}
.field-tbl .fv{color:var(--text);word-break:break-all}
.fv.str{color:#79c0ff}.fv.hex{color:#7ee787;font-size:10px}
.fv.u32,.fv.u16{color:#e3b341}.fv.float{color:#ffa657}
.fv.status{color:var(--green)}

/* Hex dump */
.hdump-wrap{padding:6px 12px}
.hdump{font-size:10.5px;line-height:1.7;background:var(--bg3);
  border-radius:4px;overflow-x:auto;white-space:pre;padding:6px 8px;
  max-height:200px;overflow-y:auto;border:1px solid var(--border)}
.hdump .off{color:#444c56}.hdump .hx{color:#7ee787}.hdump .as{color:#8b949e}

.copy-btn{font-size:10px;background:var(--bg3);border:1px solid var(--border);
  color:var(--gray);padding:2px 8px;border-radius:3px;cursor:pointer;margin:4px 12px}
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
#icpt-panel{background:var(--bg2);border-top:1px solid var(--border);padding:10px 12px;flex-shrink:0}
#icpt-panel h3{font-size:10px;color:var(--red);letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;display:flex;align-items:center;gap:6px}
#icpt-toggle{font-size:9px;padding:2px 8px;border:1px solid var(--red);background:transparent;color:var(--red);border-radius:3px;cursor:pointer}
#icpt-queue{max-height:180px;overflow-y:auto;display:flex;flex-direction:column;gap:4px}
.icpt-item{background:var(--bg3);border:1px solid var(--red)55;border-radius:4px;padding:6px 8px;font-size:10px}
.icpt-item .icpt-hex{font-family:monospace;word-break:break-all;color:var(--fg);margin:4px 0;font-size:9px;max-height:40px;overflow:hidden}
.icpt-item .icpt-acts{display:flex;gap:4px;margin-top:4px}
.icpt-item .icpt-mod{flex:1;background:var(--bg3);border:1px solid var(--border);color:var(--fg);font-family:monospace;font-size:9px;padding:2px 4px}
.icpt-pass{background:transparent;border:1px solid var(--green);color:var(--green);font-size:9px;padding:2px 8px;cursor:pointer;border-radius:2px}
.icpt-pass:hover{background:var(--green);color:#000}
.icpt-send{background:transparent;border:1px solid var(--blue);color:var(--blue);font-size:9px;padding:2px 8px;cursor:pointer;border-radius:2px}
.icpt-send:hover{background:var(--blue);color:#000}

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
  <span class="badge" id="key-b" title="Anahtara tıkla → manuel giriş" style="cursor:pointer" onclick="toggleKeyInput()">Anahtar: yok</span>
  <span class="badge" id="iv-b" style="display:none"></span>
  <span id="pkt-cnt">0 paket</span>
</div>
<div id="key-input-bar" style="display:none;background:var(--bg2);border-bottom:1px solid var(--border);padding:6px 14px;align-items:center;gap:8px;flex-shrink:0">
  <span style="color:var(--gray);font-size:10px;white-space:nowrap">BF KEY HEX (4168B):</span>
  <input id="key-hex-input" type="text" placeholder="P+S tam anahtar hex — pb_crypto.log'dan veya bf_key.bin'den kopyala"
    style="flex:1;background:var(--bg3);border:1px solid var(--border);color:var(--green);padding:3px 8px;border-radius:4px;font-family:var(--mono);font-size:11px">
  <button onclick="submitKeyHex()" style="background:var(--blue);border:none;color:#000;padding:3px 12px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:700">Yükle</button>
  <button onclick="toggleKeyInput()" style="background:transparent;border:1px solid var(--border);color:var(--gray);padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px">✕</button>
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
      <button id="btn-replay">📂 Log Oynat</button>
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
            <th class="c-nm">Paket</th>
            <th class="c-pay">İçerik önizleme</th>
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
      <textarea id="inj-hex" placeholder="Plaintext hex örn: 10 80 4d 01 02&#10;[0] len_lo (toplam-3 &amp; 0xFF)&#10;[1] 0x80|(len_hi) — flag byte&#10;[2] opcode&#10;[3…] payload (Blowfish şifrelenir)"></textarea>
      <div id="inj-row">
        <span id="inj-hint">Ctrl+Enter ile gönder</span>
        <button id="inj-btn" disabled>Gönder</button>
      </div>
      <div id="inj-st"></div>
    </div>

    <div id="icpt-panel">
      <h3>⚡ Intercept Modu
        <button id="icpt-toggle" onclick="toggleIntercept()" title="Intercept modu aç/kapat">OFF</button>
        <label style="font-size:10px;margin-left:8px">
          <input type="checkbox" id="icpt-dir-s" checked> SEND
        </label>
        <label style="font-size:10px;margin-left:4px">
          <input type="checkbox" id="icpt-dir-r" checked> RECV
        </label>
      </h3>
      <p style="font-size:10px;color:var(--gray);margin:2px 0 6px">
        Aktifken DLL her paketi onay için bekler (≤25 ms).
      </p>
      <div id="icpt-queue"></div>
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
  else if (m.type === 'key_loaded') { setKey(true, m.iv); }
  else if (m.type === 'status') { showStatus(m.msg, m.level); }
  else if (m.type === 'redecrypted') {
    // Retroaktif çözüm: tüm paket listesini güncelle ve tabloyu yenile
    packets = m.packets || [];
    renderAll();
    updCnt();
  }
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
  else if (m.type === 'intercept_req') { addIcptItem(m); }
  else if (m.type === 'intercept_status') {
    const btn = document.getElementById('icpt-toggle');
    btn.textContent = m.enabled ? 'ON' : 'OFF';
    btn.style.background = m.enabled ? 'var(--red)' : '';
    btn.style.color = m.enabled ? '#000' : '';
  }
}

// ── Intercept ────────────────────────────────────────────────────────────────
let icptEnabled = false;

function toggleIntercept() {
  icptEnabled = !icptEnabled;
  const s = document.getElementById('icpt-dir-s').checked;
  const r = document.getElementById('icpt-dir-r').checked;
  const mask = (s ? 1 : 0) | (r ? 2 : 0);
  ws && ws.send(JSON.stringify({type:'intercept_mode', enabled:icptEnabled, dir_mask:mask}));
}

function addIcptItem(m) {
  const q = document.getElementById('icpt-queue');
  const div = document.createElement('div');
  div.className = 'icpt-item';
  div.id = 'icpt-' + m.seq;
  const dirLabel = m.dir === 'S' ? '↑ SEND' : '↓ RECV';
  div.innerHTML = `
    <b>${dirLabel}</b> seq=${m.seq} size=${m.size}
    <div class="icpt-hex">${(m.raw_hex||'').slice(0,128)}${m.raw_hex&&m.raw_hex.length>128?'…':''}</div>
    <div class="icpt-acts">
      <input class="icpt-mod" id="icpt-mod-${m.seq}" placeholder="modifiye hex (boş=orijinal)">
      <button class="icpt-pass" onclick="icptResolve(${m.seq},false)">▶ Geçir</button>
      <button class="icpt-send" onclick="icptResolve(${m.seq},true)">✎ Gönder</button>
    </div>`;
  q.appendChild(div);
  q.scrollTop = q.scrollHeight;
}

function icptResolve(seq, useModified) {
  const inp = document.getElementById('icpt-mod-' + seq);
  const hex = useModified && inp ? inp.value.replace(/\s/g,'') : '';
  ws && ws.send(JSON.stringify({type: hex ? 'intercept_ack' : 'intercept_pass', seq, hex}));
  const el = document.getElementById('icpt-' + seq);
  if (el) el.style.opacity = '0.4';
  setTimeout(() => el && el.remove(), 1200);
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

// ── Manuel anahtar girişi ─────────────────────────────────────────────────────
function toggleKeyInput() {
  const bar = document.getElementById('key-input-bar');
  const visible = bar.style.display === 'flex';
  bar.style.display = visible ? 'none' : 'flex';
  if (!visible) document.getElementById('key-hex-input').focus();
}
function submitKeyHex() {
  const hex = document.getElementById('key-hex-input').value.trim();
  if (!hex) return;
  ws && ws.send(JSON.stringify({type: 'set_key_hex', hex}));
  document.getElementById('key-input-bar').style.display = 'none';
}
document.getElementById('key-hex-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); submitKeyHex(); }
  if (e.key === 'Escape') toggleKeyInput();
});

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
  const nm = p.pkt_name || '';
  const nmCls = nm.startsWith('UNK') ? 'style="color:var(--gray)"' : 'style="color:#cba6f7"';
  // preview: decoded field values or raw payload hex
  let preview = '';
  if (p.decoded && p.decoded.fields && p.decoded.fields.length > 0) {
    const strFields = p.decoded.fields.filter(f => f.k === 'str' && f.v);
    if (strFields.length > 0) preview = strFields.map(f => f.v).join(' · ').slice(0, 40);
  }
  if (!preview) preview = p.payload_hex ? p.payload_hex.slice(0,32) : '';
  tr.innerHTML = `
    <td class="c-seq">${p.seq}</td>
    <td class="c-ts">${p.ts}</td>
    <td class="c-dir d${p.dir}">${p.dir==='R'?'←':'→'}</td>
    <td class="c-sz">${p.size}B</td>
    <td class="c-st s-${p.status}">${p.status}</td>
    <td class="c-op">${p.opcode||'—'}</td>
    <td class="c-nm" ${nmCls}>${nm}</td>
    <td class="c-pay" style="color:var(--gray);font-size:10px">${preview}</td>
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

document.getElementById('btn-replay').addEventListener('click', () => {
  const btn = document.getElementById('btn-replay');
  btn.disabled = true; btn.textContent = '⏳ Yükleniyor…';
  fetch('/api/replay').then(r => r.json()).then(d => {
    btn.disabled = false; btn.textContent = '📂 Log Oynat';
    if (d.error) showStatus('Log hatası: ' + d.error, 'error');
    else showStatus(`✓ Log yüklendi: ${d.count} paket  IV=${d.iv||'—'}  (${d.path.split('/').pop()})`, 'ok');
  }).catch(e => { btn.disabled=false; btn.textContent='📂 Log Oynat'; showStatus('Log yüklenemedi: '+e,'error'); });
});

// ── Detail ───────────────────────────────────────────────────────────────────
function selectPkt(seq) {
  selSeq = seq;
  document.querySelectorAll('#tbody tr').forEach(r =>
    r.className = +r.dataset.seq === seq ? 'sel' : '');
  const p = packets.find(x => x.seq === seq);
  if (p) showDetail(p);
}

function hexDumpStr(hexStr) {
  if (!hexStr) return '';
  const bytes = hexStr.match(/.{2}/g) || [];
  let out = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.slice(i, i+16);
    const addr = i.toString(16).padStart(4,'0');
    const hex  = row.map((b,j) => b + (j===7?'  ':' ')).join('').trimEnd();
    const asc  = row.map(b => { const c=parseInt(b,16); return (c>=32&&c<127)?String.fromCharCode(c):'.'; }).join('');
    out += `<span class="off">${addr}</span>  <span class="hx">${hex.padEnd(50)}</span>  <span class="as">${asc}</span>\n`;
  }
  return out.trimEnd();
}

function badgeCls(hint) {
  if (hint==='S→C') return 'pb-recv';
  if (hint==='C→S') return 'pb-send';
  if (hint==='both') return 'pb-both';
  return 'pb-unk';
}

function showDetail(p) {
  const d = document.getElementById('detail');
  let h = '';

  // ── Hero: packet name ────────────────────────────────────────────────────
  const dec = p.decoded;
  const name = dec ? dec.name : (p.pkt_name || (p.status==='challenge'?'CHALLENGE':''));
  const desc = dec ? dec.desc : '';
  const hint = dec ? dec.hint : '?';
  const isUnk = name.startsWith('UNK') || !name;

  h += `<div class="pkt-hero">`;
  h += `<div class="pkt-hero-name${isUnk?' unk':''}">${name||'—'}</div>`;
  if (desc) h += `<div class="pkt-hero-desc">${desc}</div>`;

  // badges
  h += `<div class="pkt-badges">`;
  if (p.dir==='R')       h += `<span class="pb pb-recv">← S→C</span>`;
  else if (p.dir==='S')  h += `<span class="pb pb-send">→ C→S</span>`;
  const hintCls = badgeCls(hint);
  if (hint && hint!=='?') h += `<span class="pb ${hintCls}">${hint}</span>`;
  h += `<span class="pb pb-st-${p.status}">${p.status}</span>`;
  if (p.opcode) h += `<span class="pb pb-unk">${p.opcode}</span>`;
  if (dec && dec.pay_len != null) h += `<span class="pb pb-unk">payload ${dec.pay_len}B</span>`;
  h += `</div></div>`;

  // ── Meta ─────────────────────────────────────────────────────────────────
  h += `<div class="pkt-meta">`;
  h += `<span class="pm">#<b>${p.seq}</b></span>`;
  h += `<span class="pm">⏱ <b>${p.ts}</b></span>`;
  h += `<span class="pm">📦 <b>${p.size}B</b></span>`;
  if (p.proto) h += `<span class="pm">proto <b>${p.proto}</b></span>`;
  if (p.len_field != null) {
    const exp = (p.size-3)&0xFF;
    const match = p.len_field===exp ? '✓' : `≠${exp}`;
    h += `<span class="pm">len_field <b>${p.len_field}</b> ${match}</span>`;
  }
  if (p.note) h += `<span class="pm" style="color:var(--yellow)">${p.note}</span>`;
  h += `</div>`;

  // ── Decoded fields ────────────────────────────────────────────────────────
  if (dec && dec.fields && dec.fields.length > 0) {
    h += `<div class="sec-hd">Çözümlenen Alanlar</div>`;
    h += `<table class="field-tbl">`;
    for (const f of dec.fields) {
      h += `<tr><td class="fk">${f.n}</td><td class="fv ${f.k}">${f.v}</td></tr>`;
    }
    h += `</table>`;
  }

  // ── Plaintext hex dump ────────────────────────────────────────────────────
  if (p.plain_hex) {
    h += `<div class="sec-hd">Plaintext (${p.plain_hex.length/2}B)</div>`;
    h += `<div class="hdump-wrap"><div class="hdump">${hexDumpStr(p.plain_hex)}</div>`;
    h += `<button class="copy-btn" onclick="fillInject('${p.plain_hex}')">↓ Inject kutusuna kopyala</button>`;
    h += `<button class="copy-btn" onclick="copyHex('${p.plain_hex}')">📋 Kopyala</button></div>`;
  }

  // ── Raw (cipher) hex dump ─────────────────────────────────────────────────
  if (p.raw_hex && p.status !== 'challenge') {
    h += `<div class="sec-hd">Raw / Şifreli (${p.raw_hex.length/2}B)</div>`;
    h += `<div class="hdump-wrap"><div class="hdump">${hexDumpStr(p.raw_hex)}</div></div>`;
  } else if (p.raw_hex && p.status === 'challenge') {
    h += `<div class="sec-hd">Challenge Ham Veri (${p.raw_hex.length/2}B)</div>`;
    h += `<div class="hdump-wrap"><div class="hdump">${hexDumpStr(p.raw_hex)}</div></div>`;
  }

  d.innerHTML = h;
  document.getElementById('detail-hd').textContent = name ? `Paket: ${name}` : 'Paket Detayı';
}

function fillInject(hex) {
  document.getElementById('inj-hex').value = (hex.match(/.{2}/g)||[]).join(' ');
  document.getElementById('inj-hex').focus();
}

function copyHex(hex) {
  const txt = (hex.match(/.{2}/g)||[]).join(' ');
  navigator.clipboard && navigator.clipboard.writeText(txt);
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
      ph.placeholder = 'Plaintext hex örn: 10 80 4d 01 02\n[0] len_lo  [1] 0x80|len_hi  [2] opcode  [3…] payload';
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

# ─── Log replay ──────────────────────────────────────────────────────────────

_NET_LINE = re.compile(
    r'(?:\[(\d{2}:\d{2}:\d{2})[^\]]*\]\s+)?'   # timestamp — opsiyonel (bazı satırlarda eksik)
    r'TCP\s+'
    r'(RECV|SEND)\s+[←→]\s+'
    r'(\S+)\s+'                                  # IP:port
    r'bf_calls=\d+\s+'
    r'\[(\d+)\s+bytes\]:\s*'
    r'([0-9a-fA-F]+)'                            # hex (truncated olabilir)
)
_GAME_PORT = '39190'

def parse_netlog(path: str):
    """pb_net.log'dan port 39190 paketlerini çıkar (hex truncated olabilir)."""
    pkts = []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                m = _NET_LINE.search(line)
                if not m:
                    continue
                ts, direction, peer, size_str, hex_data = m.groups()
                if not peer.endswith(f':{_GAME_PORT}'):
                    continue
                size = int(size_str)
                raw  = bytes.fromhex(hex_data)
                pkts.append({
                    'ts':   ts or '',             # ts opsiyonel — yoksa boş string
                    'dir':  'R' if direction == 'RECV' else 'S',
                    'size': size,
                    'raw':  raw,                  # first ≤128 bytes (log kısaltıyor)
                    'full': len(raw) >= size,     # truncation yok mu?
                })
    except OSError:
        pass
    return pkts

async def replay_handler(request):
    """GET /api/replay — attached_assets/pb_net_*.log'dan paketleri yükle ve şifrele."""
    files = sorted(glob.glob('attached_assets/pb_net_*.log'), reverse=True)
    if not files:
        return web.json_response({'error': 'pb_net log bulunamadı'}, status=404)

    path  = files[0]
    pkts  = parse_netlog(path)
    if not pkts:
        return web.json_response({'error': 'Log boş veya ayrıştırılamadı'}, status=422)

    # Sıfırla
    session.packets.clear()
    session.seq = 0

    evs = []
    for p in pkts:
        raw       = p['raw']
        direction = p['dir']
        ts        = p['ts'] or time.strftime('%H:%M:%S')
        size      = p['size']

        # Challenge tespiti — IV güncelle (apply_iv_if_better: çalışan IV'i korur)
        if direction == 'R' and size == 202 and len(raw) >= 11 and raw[0] == 0xc5:
            session.apply_iv_if_better(bytes(raw[3:11]))
            ev = fmt_packet(session.seq, 'R', raw, None, ts)
            ev['status'] = 'challenge'
            ev['note']   = f'IV={session.iv.hex()} (log)'
            session.seq += 1; _store(ev); evs.append(ev)
            continue

        # Büyük tampon: sub-paket ayrıştırması (header düz metin → raw üzerinden walk)
        if session.has_key() and session.has_iv() and p['full'] and size > 258:
            subs = _walk_subpackets(raw)
            if subs:
                for sub in subs:
                    sub_plain = session.decrypt_subpkt(sub['sub_raw'])
                    ev = fmt_packet(session.seq, direction,
                                    sub['sub_raw'], sub_plain, ts)
                    ev['note'] = f'buf:{size}B @{sub["offset"]} (log)'
                    session.seq += 1; _store(ev); evs.append(ev)
                continue  # büyük buffer'ı tekil event olarak ekleme

        plain = None
        if session.has_key() and session.has_iv() and p['full']:
            plain = session.decrypt(raw, direction)

        ev = fmt_packet(session.seq, direction, raw, plain, ts)
        if not p['full'] and ev['status'] not in ('ok', 'large', 'challenge'):
            ev['status'] = 'truncated'
            ev['note']   = f'log kısaltılmış ({len(raw)}/{size}B)'
        session.seq += 1; _store(ev); evs.append(ev)

    # Tüm istemcilere gönder
    await broadcast({'type': 'cleared'})
    await asyncio.sleep(0.02)
    for ev in evs:
        await broadcast({'type': 'packet', 'pkt': ev})

    return web.json_response({'ok': True, 'count': len(evs), 'path': path,
                              'iv': session.iv.hex() if session.iv else None})

# ─── App ─────────────────────────────────────────────────────────────────────

async def packets_handler(request):
    """GET /api/packets — ham paket listesi (analiz için)."""
    pkts = []
    for ev in session.packets[-200:]:
        pkts.append({
            'seq': ev['seq'], 'ts': ev['ts'], 'dir': ev['dir'],
            'size': ev['size'], 'status': ev['status'],
            'cipher_hex': ev.get('raw_hex', ''),
            'opcode': ev.get('opcode'), 'proto': ev.get('proto'),
            'len_field': ev.get('len_field'),
        })
    return web.json_response({'iv': session.iv.hex() if session.iv else None, 'packets': pkts})

async def log_upload_handler(request):
    """DLL'den gelen log dosyası yüklemesi: POST /log_upload
    Dosya kaydedildikten sonra anahtar/IV otomatik güncellenir ve
    'encrypted' durumdaki paketler retroaktif olarak çözülür.
    """
    name = request.headers.get('X-Log-Name', '')
    name = os.path.basename(name)                       # path traversal engelle
    if not name or not name.endswith('.log'):
        return web.Response(status=400, text='bad filename')
    data = await request.read()
    if not data:
        return web.Response(status=400, text='empty body')
    os.makedirs('log_data', exist_ok=True)
    path = os.path.join('log_data', name)
    with open(path, 'wb') as f:
        f.write(data)
    print(f'[LOG] ✓ {name} yüklendi — {len(data)} bayt → {path}')
    await broadcast({'type': 'log_uploaded', 'name': name,
                     'size': len(data), 'path': path})

    # ── Otomatik anahtar / IV güncelleme ──────────────────────────────────
    if name == 'pb_crypto.log':
        candidates = load_all_candidates(path)
        P, S = None, None
        crack_used = False

        if candidates:
            print(f'[KEY] {len(candidates)} aday yüklendi — crack deneniyor…')
            # IV ve test paketleri mevcutsa otomatik crack
            if session.iv:
                test_pkts = [
                    (bytes.fromhex(ev['raw_hex']), ev['size'])
                    for ev in session.packets
                    if ev.get('status') in ('encrypted', 'mismatch', 'ok', 'large')
                    and ev.get('dir') == 'R'
                    and ev.get('raw_hex')
                    and ev.get('size', 0) <= 258   # küçük tam paketler
                ][:20]
                if test_pkts:
                    P, S = crack_key(candidates, session.iv, test_pkts)
                    if P and S:
                        crack_used = True

            # Crack başarısız veya test paketi yoksa: CONFIRMED_SIG ara, sonra son aday
            if not (P and S):
                # 1. Onaylı SIG'e sahip aday var mı?
                for cp, cs in candidates:
                    sig = (cs[0][0], cs[1][0], cs[2][0], cs[3][0])
                    if sig == CONFIRMED_SIG:
                        P, S = cp, cs
                        break
            if not (P and S):
                # 2. Son aday
                P, S = candidates[-1]

        if P and S:
            sig = (S[0][0], S[1][0], S[2][0], S[3][0])
            sig_str = ' '.join(f'{x:08x}' for x in sig)
            is_confirmed = sig == CONFIRMED_SIG
            # bf_key.bin'e sadece doğrulanmış anahtar yaz — yanlış aday önbelleği kirletmesin
            save_cache = crack_used or is_confirmed
            if not save_cache:
                print(f'[KEY] Doğrulanmamış aday session\'a yüklendi (bf_key.bin korundu)')
            session.set_key(P, S, save_cache=save_cache)
            confirmed = '✓ ONAYLANDI' if is_confirmed else ('✓ CRACK' if crack_used else '(doğrulanmadı — önbelleksiz)')
            msg = f'[AUTO] Anahtar güncellendi {confirmed} — SIG={sig_str}'
            print(msg)
            await broadcast({'type': 'key_loaded',
                             'iv': session.iv.hex() if session.iv else None})
            await broadcast({'type': 'status', 'msg': msg, 'level': 'ok'})
            await _redecrypt_session()

    elif name == 'pb_net.log':
        iv = load_iv_from_net_log(path)
        if iv:
            session.set_iv(iv)
            msg = f'[AUTO] IV güncellendi — {iv.hex()}'
            print(msg)
            await broadcast({'type': 'key_loaded', 'iv': iv.hex()})
            await broadcast({'type': 'status', 'msg': msg, 'level': 'ok'})
            await _redecrypt_session()
        else:
            print('[AUTO] pb_net.log yüklendi — challenge paketi bulunamadı, IV bekleniyor.')

    return web.Response(text='ok')

async def _dll_keepalive():
    """DLL WebSocket bağlantılarını Replit proxy idle timeout'undan korumak için
    her 20 saniyede bir uygulama seviyesinde keepalive frame gönderir.
    WinHTTP heartbeat=None olduğu için bu yöntem kullanılır — WinHTTP BINARY
    frame olarak alır, tip kontrolü geçemeyince yok sayar (zararsız)."""
    # Keepalive marker: tip=0xFF (özel), veri=0 byte
    KEEPALIVE = bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00])
    while True:
        await asyncio.sleep(20)
        dead = set()
        for ws in list(session.dll_clients):
            if ws.closed:
                dead.add(ws)
                continue
            try:
                await ws.send_bytes(KEEPALIVE)
            except Exception:
                dead.add(ws)
        if dead:
            session.dll_clients -= dead
            if session._dll_ws_latest in dead:
                session._dll_ws_latest = None


async def _start_keepalive(app):
    app['_dll_keepalive'] = asyncio.ensure_future(_dll_keepalive())


async def _stop_keepalive(app):
    task = app.get('_dll_keepalive')
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


def make_app():
    app = web.Application(client_max_size=32 * 1024 * 1024)  # 32 MB — büyük log dosyaları için
    app.router.add_get('/',              index_handler)
    app.router.add_get('/api/status',   status_handler)
    app.router.add_get('/api/packets',  packets_handler)
    app.router.add_get('/api/replay',   replay_handler)
    app.router.add_get('/dll',         dll_handler)
    app.router.add_get('/ui',          ui_handler)
    app.router.add_post('/log_upload',  log_upload_handler)
    app.router.add_get('/favicon.ico', lambda r: web.Response(status=204))
    app.on_startup.append(_start_keepalive)
    app.on_cleanup.append(_stop_keepalive)
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

    # ── Anahtar yükleme sırası ────────────────────────────────────────────────
    # 1. Önbellek (bf_key.bin) — restart'ta kaybolmaz
    P, S = load_key_cache()
    if P and S:
        session.set_key(P, S)
        sig = (S[0][0], S[1][0], S[2][0], S[3][0])
        confirmed = '✓ ONAYLANDI' if sig == target_sig else '(doğrulanmadı)'
        print(f'[KEY] ✓ Önbellekten yüklendi {confirmed} — bf_key.bin')
    else:
        # 2. Crypto log dosyaları
        key_candidates = [
            args.crypto,
            'log_data/pb_crypto.log',
            'pb_crypto.log',
        ] + sorted(glob.glob('attached_assets/pb_crypto_*.log'), reverse=True)

        for path in key_candidates:
            if not path:
                continue
            P, S = load_key(path, target_sig)
            if P and S:
                session.set_key(P, S)
                print(f'[KEY] ✓ Anahtar yüklendi: {path}')
                print(f'[KEY]   SIG={" ".join(f"{x:08x}" for x in target_sig)}')
                break
        else:
            print('[KEY] ✗ Anahtar bulunamadı — DLL bağlandığında veya manuel giriş ile yüklenecek.')

    # ── IV yükleme sırası (pb_net.log'dan challenge[3:11]) ────────────────
    iv_candidates = [
        'log_data/pb_net.log',
        'pb_net.log',
    ]
    for path in iv_candidates:
        iv = load_iv_from_net_log(path)
        if iv:
            session.set_iv(iv)
            print(f'[IV]  ✓ IV yüklendi: {path} — {iv.hex()}')
            break
    else:
        print('[IV]  ✗ IV bulunamadı — DLL challenge paketi gönderince otomatik set edilecek.')

    app = make_app()

    print(f'\n[SERVER] Çalışıyor → http://{args.host}:{args.port}')
    print(f'[SERVER] DLL bağlantısı → ws://HOST:{args.port}/dll')
    print(f'[SERVER] Web UI        → http://HOST:{args.port}/')
    print(f'[SERVER] Durum API     → http://HOST:{args.port}/api/status\n')

    web.run_app(app, host=args.host, port=args.port, print=lambda *a: None)

if __name__ == '__main__':
    main()
