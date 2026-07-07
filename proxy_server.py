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
    Geçerlilik kriteri: plain[0]==(size-3)&0xFF  ve  plain[1]==0x0D
    min_hits adayın en az kaç pakette eşleşmesi gerektiğini belirtir.
    En çok eşleşen adayı döndürür; bulunamazsa (None, None)."""
    best_p, best_s, best_hits = None, None, -1
    for P, S in candidates:
        hits = 0
        iv_state = bytearray(iv_bytes)
        n_state = 0
        for cipher, size in test_packets:
            plain, iv_state, n_state = _cfb64(P, S, cipher, bytes(iv_state),
                                               encrypt=False, n_in=n_state)
            iv_state = bytearray(iv_state)
            expected_len = (size - 3) & 0xFF
            if len(plain) >= 2 and plain[0] == expected_len and plain[1] == 0x0D:
                hits += 1
        if hits > best_hits:
            best_hits, best_p, best_s = hits, P, S
    if best_hits >= min_hits:
        return best_p, best_s
    # min_hits sağlanamadı; en azından 1 eşleşme varsa dön
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
        # ── Oyuncu takibi ──────────────────────────────────────────────────
        self.players: dict[int, dict] = {}   # player_id → player_dict
        self.game_state: str = 'lobby'       # 'lobby' | 'room' | 'ingame'
        self.room_id: int = 0

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
        """IV adayının mevcut paketlere göre skor hesapla (stateless, sadece ilk paket)."""
        if not self.P:
            return 0
        test = [ev for ev in self.packets[-30:]
                if ev.get('size', 0) < 64 and ev.get('raw_hex') and ev.get('status') != 'challenge'][:n_pkts]
        score = 0
        for ev in test:
            raw = bytes.fromhex(ev['raw_hex'])
            p, _, _ = _cfb64(self.P, self.S, raw, candidate_iv, encrypt=False)
            if p and len(p) > 1 and p[1] == 0x0D:
                score += 1
        return score

    def apply_iv_if_better(self, candidate_iv: bytes) -> bool:
        new_score = self.score_iv(candidate_iv)
        old_score = self.score_iv(self.iv) if self.iv else -1
        if new_score >= old_score:
            self.set_iv(candidate_iv)
            return True
        print(f'[IV] Reddedildi {candidate_iv.hex()} (skor {new_score}) < mevcut {self.iv.hex()} (skor {old_score})')
        return False

    def decrypt(self, cipher, direction='R'):
        """Stateful CFB-64 decrypt — yön başına bağımsız akış durumu korunur."""
        if not self.has_key() or not self.has_iv():
            return None
        if direction == 'R':
            if self.iv_recv is None:
                self.iv_recv, self.n_recv = self.iv, 0
            plain, self.iv_recv, self.n_recv = _cfb64(
                self.P, self.S, cipher, self.iv_recv, encrypt=False, n_in=self.n_recv)
        else:
            if self.iv_send is None:
                self.iv_send, self.n_send = self.iv, 0
            plain, self.iv_send, self.n_send = _cfb64(
                self.P, self.S, cipher, self.iv_send, encrypt=False, n_in=self.n_send)
        return plain

    def encrypt(self, plain):
        """Stateful CFB-64 encrypt — SEND akışı durumu korunur."""
        if not self.has_key() or not self.has_iv():
            return None
        if self.iv_send is None:
            self.iv_send, self.n_send = self.iv, 0
        cipher, self.iv_send, self.n_send = _cfb64(
            self.P, self.S, plain, self.iv_send, encrypt=True, n_in=self.n_send)
        return cipher

session = Session()

# ─── Protocol Decoder ────────────────────────────────────────────────────────
#
# Opcode tablosu: 0xNN → (kısa_ad, yön_ipucu, açıklama)
# yön_ipucu: 'C→S' = client→server, 'S→C' = server→client, '?' = bilinmiyor
# Yeni opcode eklemek için buraya satır ekle; proxy yeniden başlatmaya gerek yok
# (sunucu yeniden başlatılınca tablo güncellenir).
_OPCODES: dict[int, tuple[str, str, str]] = {
    # ── Bağlantı / Oturum ──────────────────────────────────────
    0x01: ('CONNECT',       '?',   'Bağlantı isteği / ilk握手'),
    0x02: ('PING',          '?',   'Bağlantı canlı tutma — ping'),
    0x03: ('PONG',          '?',   'Bağlantı canlı tutma — pong'),
    0x04: ('DISCONNECT',    '?',   'Bağlantı kesme bildirimi'),
    # ── Giriş / Kimlik ──────────────────────────────────────────
    0x14: ('LOGIN_REQ',     'C→S', 'Kullanıcı adı + şifre/hash gönderimi'),
    0x15: ('LOGIN_ACK',     'S→C', 'Login yanıtı (başarı/hata kodu)'),
    0x16: ('AUTH_TOKEN',    'C→S', 'Kimlik doğrulama token\'ı'),
    0x17: ('USER_INFO',     'S→C', 'Kullanıcı bilgileri (seviye, deneyim)'),
    0x18: ('CHAR_SELECT',   'C→S', 'Karakter / slot seçimi'),
    # ── Lobi / Kanal ────────────────────────────────────────────
    0x1e: ('LOBBY_LIST',    'S→C', 'Lobi / kanal listesi'),
    0x1f: ('CHANNEL_JOIN',  'C→S', 'Kanala giriş isteği'),
    0x20: ('CHANNEL_ACK',   'S→C', 'Kanal giriş yanıtı'),
    0x21: ('PLAYER_LIST',   'S→C', 'Kanaldaki oyuncu listesi'),
    0x22: ('PLAYER_ENTER',  'S→C', 'Kanala yeni oyuncu girdi'),
    0x23: ('PLAYER_LEAVE',  'S→C', 'Kanaldan oyuncu çıktı'),
    # ── Oda ─────────────────────────────────────────────────────
    0x28: ('ROOM_LIST',     'S→C', 'Oda listesi'),
    0x29: ('ROOM_CREATE',   'C→S', 'Oda oluşturma isteği'),
    0x2a: ('ROOM_JOIN',     'C→S', 'Odaya katılma isteği'),
    0x2b: ('ROOM_LEAVE',    'C→S', 'Odadan ayrılma'),
    0x2c: ('ROOM_ACK',      'S→C', 'Oda işlemi yanıtı'),
    0x2d: ('ROOM_INFO',     'S→C', 'Oda bilgisi (harita, mod, oyuncular)'),
    0x2e: ('ROOM_READY',    'C→S', 'Hazır butonu'),
    0x2f: ('ROOM_KICK',     'S→C', 'Odadan atıldı'),
    # ── Oyun ────────────────────────────────────────────────────
    0x32: ('GAME_START',    'S→C', 'Oyun başladı — harita ve takım bilgisi'),
    0x33: ('GAME_END',      'S→C', 'Oyun bitti — skor tablosu'),
    0x34: ('ROUND_START',   'S→C', 'Tur başladı'),
    0x35: ('ROUND_END',     'S→C', 'Tur bitti'),
    0x36: ('MAP_DATA',      'S→C', 'Harita verisi / spawn noktaları'),
    # ── Oyuncu Durumu ───────────────────────────────────────────
    0x3c: ('SPAWN',         'S→C', 'Spawn koordinatları + takım'),
    0x3d: ('MOVE',          'both','Hareket paketi (konum + açı)'),
    0x3e: ('JUMP',          'C→S', 'Zıplama'),
    0x3f: ('CROUCH',        'C→S', 'Çömelme'),
    0x40: ('STANCE',        'both','Duruş değişikliği'),
    # ── Silah / Savaş ───────────────────────────────────────────
    0x46: ('SHOOT',         'C→S', 'Ateş paketi — silah ve hedef'),
    0x47: ('HIT',           'S→C', 'Vurma bildirimi — hasar + vuran'),
    0x48: ('MISS',          'S→C', 'Ateş ıskalaması'),
    0x49: ('RELOAD',        'C→S', 'Şarjör doldurma'),
    0x4a: ('WEAPON_SWITCH', 'C→S', 'Silah değiştirme'),
    0x4b: ('PLAYER_DEAD',   'S→C', 'Ölüm bildirimi — ölen ve öldüren'),
    0x4e: ('GRENADE',       'C→S', 'El bombası fırlatma'),
    0x4f: ('EXPLOSION',     'S→C', 'Patlama efekti'),
    # ── Sohbet ──────────────────────────────────────────────────
    0x4c: ('CHAT',          'both','Sohbet mesajı'),
    0x5b: ('SYSTEM_MSG',    'S→C', 'Sistem mesajı / duyuru'),
    # ── Skor / İstatistik ───────────────────────────────────────
    0x50: ('SCORE',         'S→C', 'Skor güncellemesi'),
    0x51: ('KILL_FEED',     'S→C', 'Kill/ölüm özeti'),
    0x52: ('STATS',         'S→C', 'Oyun sonu istatistikleri'),
    # ── Envanter / Mağaza ───────────────────────────────────────
    0x5a: ('SHOP_BUY',      'C→S', 'Eşya / silah satın alma'),
    0x5c: ('INVENTORY',     'S→C', 'Envanter listesi'),
    0x5d: ('EQUIP',         'C→S', 'Eşya donatma'),
    # ── Diğer ───────────────────────────────────────────────────
    0x64: ('HEARTBEAT',     'both','Uygulama seviyesi canlı tutma'),
    0x6e: ('SERVER_INFO',   'S→C', 'Sunucu bilgisi (IP, port, bölge)'),
    0x78: ('CLAN_INFO',     'S→C', 'Klan bilgisi'),
}

def _ascii_safe(b: bytes) -> str:
    return ''.join(chr(x) if 0x20 <= x < 0x7f else '.' for x in b)

def _try_string(data: bytes, offset: int) -> tuple[str, int]:
    """[1B len][bytes] Pascal string okur; geçersizse hex döndürür."""
    if offset >= len(data): return '', offset
    slen = data[offset]; offset += 1
    raw = data[offset:offset + slen]
    try:   text = raw.decode('utf-8', errors='replace')
    except Exception: text = raw.hex()
    return text, offset + slen

def _decode_fields(opcode_byte: int, payload: bytes, direction: str) -> list[dict]:
    """Opcode'a göre payload alanlarını ayrıştır. Bilinmeyen → hex dump."""
    fields: list[dict] = []

    def f(name, value, kind='val'):
        fields.append({'n': name, 'v': str(value), 'k': kind})

    try:
        if opcode_byte == 0x02 and len(payload) >= 4:   # PING
            f('Timestamp', struct.unpack_from('<I', payload)[0], 'u32')

        elif opcode_byte == 0x14 and len(payload) >= 1:  # LOGIN_REQ
            uname, off = _try_string(payload, 0)
            f('Kullanıcı adı', uname, 'str')
            if off < len(payload):
                f('Şifre/Hash', payload[off:off+32].hex(), 'hex')

        elif opcode_byte == 0x15 and len(payload) >= 1:  # LOGIN_ACK
            code = payload[0]
            names = {0: 'Başarılı', 1: 'Hatalı şifre', 2: 'Hesap yok',
                     3: 'Zaten giriş yapıldı', 4: 'Sunucu dolu'}
            f('Sonuç', f"0x{code:02x} — {names.get(code, 'Bilinmiyor')}", 'status')
            if len(payload) >= 5:
                uid = struct.unpack_from('<I', payload, 1)[0]
                f('Kullanıcı ID', uid, 'u32')

        elif opcode_byte == 0x3d and len(payload) >= 12: # MOVE
            x, y, z = struct.unpack_from('<fff', payload, 0)
            f('X', f'{x:.3f}', 'float')
            f('Y', f'{y:.3f}', 'float')
            f('Z', f'{z:.3f}', 'float')
            if len(payload) >= 14:
                yaw   = struct.unpack_from('<H', payload, 12)[0]
                f('Yaw (açı)', f'{yaw} ({yaw/65535*360:.1f}°)', 'u16')

        elif opcode_byte == 0x47 and len(payload) >= 6:  # HIT
            attacker = struct.unpack_from('<H', payload, 0)[0]
            victim   = struct.unpack_from('<H', payload, 2)[0]
            damage   = struct.unpack_from('<H', payload, 4)[0]
            f('Saldıran ID', attacker, 'u16')
            f('Hedef ID',    victim,   'u16')
            f('Hasar',       damage,   'u16')
            if len(payload) >= 7:
                zone_map = {0:'Gövde', 1:'Kafa', 2:'Sol kol', 3:'Sağ kol',
                            4:'Sol bacak', 5:'Sağ bacak'}
                zone = payload[6]
                f('Bölge', f"{zone_map.get(zone, f'0x{zone:02x}')}", 'val')

        elif opcode_byte == 0x4b and len(payload) >= 4:  # PLAYER_DEAD
            killer = struct.unpack_from('<H', payload, 0)[0]
            victim = struct.unpack_from('<H', payload, 2)[0]
            f('Öldüren ID', killer, 'u16')
            f('Ölen ID',    victim, 'u16')
            if len(payload) >= 5:
                weapon = payload[4]
                f('Silah kodu', f'0x{weapon:02x}', 'hex')

        elif opcode_byte == 0x4c and len(payload) >= 2:  # CHAT
            sender, off = _try_string(payload, 0)
            if off < len(payload):
                msg, _ = _try_string(payload, off)
                f('Gönderen', sender, 'str')
                f('Mesaj',    msg,    'str')

        elif opcode_byte == 0x50 and len(payload) >= 4:  # SCORE
            team_a = struct.unpack_from('<H', payload, 0)[0]
            team_b = struct.unpack_from('<H', payload, 2)[0]
            f('Takım A', team_a, 'u16')
            f('Takım B', team_b, 'u16')

        elif opcode_byte == 0x32 and len(payload) >= 2:  # GAME_START
            map_id = struct.unpack_from('<H', payload, 0)[0]
            f('Harita ID', map_id, 'u16')
            if len(payload) >= 3:
                mode = payload[2]
                modes = {0:'Deathmatch', 1:'Team DM', 2:'Bomba', 3:'Bayrak'}
                f('Mod', f"{modes.get(mode, f'0x{mode:02x}')}", 'val')

        elif opcode_byte == 0x3c and len(payload) >= 12: # SPAWN
            x, y, z = struct.unpack_from('<fff', payload, 0)
            f('Spawn X', f'{x:.1f}', 'float')
            f('Spawn Y', f'{y:.1f}', 'float')
            f('Spawn Z', f'{z:.1f}', 'float')
            if len(payload) >= 13:
                team = payload[12]
                f('Takım', 'Mavi' if team == 0 else ('Kırmızı' if team == 1 else f'0x{team:02x}'), 'val')

    except Exception:
        pass  # parse hatası → sadece hex dump göster

    return fields

def decode_packet(opcode_byte: int, payload: bytes, direction: str) -> dict:
    """Paketi ayrıştır: isim + açıklama + alanlar + hex dump döndür."""
    entry = _OPCODES.get(opcode_byte)
    name  = entry[0] if entry else f'UNK_{opcode_byte:02X}'
    hint  = entry[1] if entry else '?'
    desc  = entry[2] if entry else 'Bilinmeyen opcode — ham veri gösteriliyor'

    fields = _decode_fields(opcode_byte, payload, direction)

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
    base['len_field']   = plain[0] if plain else None
    base['proto']       = plain[1] if len(plain) > 1 else None
    base['payload_hex'] = plain[3:67].hex() if len(plain) > 3 else ''

    op_byte = plain[2] if len(plain) > 2 else None
    base['opcode'] = op_byte

    expected = (size - 3) & 0xFF
    len_ok   = (base['len_field'] == expected and size <= 258)
    proto_ok = (base['proto'] == 0x0D)

    if len_ok and proto_ok:         base['status'] = 'ok'
    elif proto_ok and not len_ok:   base['status'] = 'large'
    elif len_ok and not proto_ok:   base['status'] = 'proto?'
    else:                           base['status'] = 'mismatch'

    # Decode packet fields
    if op_byte is not None:
        payload = plain[3:]
        dec = decode_packet(op_byte, payload, direction)
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
                await on_dll_frame(msg.data)
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

# ─── KEY frame yönetimi (debounce + skorlama) ─────────────────────────────────
# DLL 20+ aday key gönderir; her birini hemen uygulamak yerine 0.5s bekleyip
# CFB64 decrypt üzerinden en yüksek proto=0x0D oranını veren adayı seçiyoruz.

_key_candidates: list[tuple] = []         # (P, S, sig) buffer
_key_debounce_task: 'asyncio.Task | None' = None  # son bekleyen task

def _score_key(P: list, S: list, test_pkts: list) -> int:
    """Aday key'i test paketlerine karşı değerlendir.
    Stateful CFB64 oynatır; proto=0x0D eşleşmesi başına 1 puan,
    len_field de doğruysa +1 puan ekler."""
    if not P or not S or not session.iv:
        return 0
    score = 0
    iv, n = session.iv, 0
    for raw, size in test_pkts:
        try:
            plain, iv, n = _cfb64(P, S, raw, iv, encrypt=False, n_in=n)
            if len(plain) >= 2 and plain[1] == 0x0D:
                score += 1
                if len(plain) >= 3 and size <= 258:
                    if plain[0] == (size - 3) & 0xFF:
                        score += 1  # len_field de tutarlı
        except Exception:
            pass
    return score

async def _select_best_key():
    """0.5s debounce sonrası: tüm aday key'leri skorla ve en iyiyi uygula."""
    global _key_candidates
    await asyncio.sleep(0.5)

    candidates = list(_key_candidates)
    _key_candidates.clear()
    if not candidates:
        return

    # Skorlama için küçük RECV paketleri kullan (tam decrypt edilememiş olanlar)
    test_pkts = [
        (bytes.fromhex(ev['raw_hex']), ev['size'])
        for ev in session.packets[-40:]
        if ev.get('raw_hex') and ev.get('dir') == 'R'
        and ev.get('status') in ('encrypted', 'mismatch', 'ok', 'large')
        and 3 <= ev.get('size', 0) <= 258
    ][:15]

    # Varsayılan: son gelen aday (en yeni tarama sonucu)
    best_P, best_S, best_sig, best_score = candidates[-1]
    for P, S, sig in candidates:
        sc = _score_key(P, S, test_pkts)
        if sig == CONFIRMED_SIG:
            sc += 1000          # bilinen SIG varsa büyük bonus
        if sc > best_score:
            best_score, best_P, best_S, best_sig = sc, P, S, sig

    # Test paketi yoksa ve zaten çalışan bir key varsa değiştirme
    if not test_pkts and session.has_key() and best_score <= 0 and best_sig != CONFIRMED_SIG:
        print(f'[KEY] Test paketi yok — mevcut anahtar korundu')
        return

    is_confirmed = best_sig == CONFIRMED_SIG
    crack_ok     = best_score >= 3 and not is_confirmed
    # bf_key.bin'e sadece güvenilir anahtarları yaz
    save_cache   = is_confirmed or crack_ok
    session.set_key(best_P, best_S, save_cache=save_cache)

    sig_str = ' '.join(f'{x:08x}' for x in best_sig)
    if is_confirmed:
        label = '✓ ONAYLANDI'
    elif crack_ok:
        label = f'✓ CRACK (skor={best_score})'
    else:
        label = f'(varsayılan — son aday, skor={best_score})'
    level = 'ok' if (is_confirmed or crack_ok) else 'warn'
    msg   = f'Anahtar seçildi {label} — SIG={sig_str}  ({len(candidates)} adaydan)'
    print(f'[KEY] {msg}')
    await broadcast({'type': 'key_loaded', 'iv': session.iv.hex() if session.iv else None})
    await broadcast({'type': 'status', 'msg': msg, 'level': level})
    await _redecrypt_session()

async def _handle_key_frame(raw: bytes):
    """DLL'den gelen KEY frame (0x4B): adayı arabelleğe ekle, debounce ile seç."""
    global _key_candidates, _key_debounce_task
    if len(raw) < BF_KEY_SIZE:
        return
    P   = list(struct.unpack_from('<18I', raw, 0))
    S   = [list(struct.unpack_from('<256I', raw, (18 + i * 256) * 4)) for i in range(4)]
    sig = (S[0][0], S[1][0], S[2][0], S[3][0])
    _key_candidates.append((P, S, sig))
    sig_str = ' '.join(f'{x:08x}' for x in sig)
    print(f'[KEY] Aday #{len(_key_candidates)} — SIG={sig_str}')
    # Debounce: son aday geldikten 0.5s sonra en iyiyi seç
    if _key_debounce_task and not _key_debounce_task.done():
        _key_debounce_task.cancel()
    _key_debounce_task = asyncio.create_task(_select_best_key())

async def _redecrypt_session():
    """Tüm paketi baştan stateful oynat: RECV ve SEND CFB akışlarını sıfırlayıp
    sırayla decrypt uygular. 'encrypted' / 'mismatch' paketleri günceller.
    Doğru akış durumu için challenge olmayan TÜM paketler işlenir."""
    if not session.has_key() or not session.has_iv():
        return
    # Her yön için bağımsız başlangıç durumu
    iv_r, n_r = session.iv, 0
    iv_s, n_s = session.iv, 0
    changed = 0
    for ev in session.packets:
        status = ev.get('status')
        if status == 'challenge':
            # Yeni challenge → IV güncelle, akışları sıfırla
            raw_ch = bytes.fromhex(ev.get('raw_hex', ''))
            if len(raw_ch) >= 11 and raw_ch[0] == 0xc5:
                new_iv = bytes(raw_ch[3:11])
                iv_r, n_r = new_iv, 0
                iv_s, n_s = new_iv, 0
            continue
        raw = bytes.fromhex(ev.get('raw_hex', ''))
        if not raw:
            continue
        direction = ev.get('dir', 'R')
        if direction == 'R':
            plain, iv_r, n_r = _cfb64(session.P, session.S, raw, iv_r, encrypt=False, n_in=n_r)
        else:
            plain, iv_s, n_s = _cfb64(session.P, session.S, raw, iv_s, encrypt=False, n_in=n_s)
        # Sadece henüz çözülemeyen paketleri güncelle
        if status in ('encrypted', 'mismatch', 'proto?'):
            ev['plain_hex']   = plain.hex()
            ev['len_field']   = plain[0] if plain else None
            ev['proto']       = plain[1] if len(plain) > 1 else None
            ev['payload_hex'] = plain[3:67].hex() if len(plain) > 3 else ''
            op_byte           = plain[2] if len(plain) > 2 else None
            ev['opcode']      = op_byte
            expected  = (ev['size'] - 3) & 0xFF
            len_ok    = (ev['len_field'] == expected and ev['size'] <= 258)
            proto_ok  = (ev['proto'] == 0x0D)
            if len_ok and proto_ok:        ev['status'] = 'ok'
            elif proto_ok and not len_ok:  ev['status'] = 'large'
            elif len_ok and not proto_ok:  ev['status'] = 'proto?'
            else:                          ev['status'] = 'mismatch'
            if op_byte is not None:
                dec = decode_packet(op_byte, plain[3:], ev.get('dir','R'))
                ev['decoded']   = dec
                ev['pkt_name']  = dec['name']
                ev['opcode']    = f"0x{op_byte:02x}"
            if ev['proto']  is not None:   ev['proto']  = f"0x{ev['proto']:02x}"
            ev['note'] = 'retroaktif çözüldü'
            if ev['status'] != status:
                changed += 1
    # Canlı stream durumunu güncelle — sonraki paketler doğru noktadan devam eder
    session.iv_recv, session.n_recv = iv_r, n_r
    session.iv_send, session.n_send = iv_s, n_s
    if changed:
        print(f'[REDECRYPT] {changed} paket güncellendi')
        await broadcast({'type': 'redecrypted', 'packets': session.packets[-500:]})
        await broadcast({'type': 'status',
                         'msg':   f'✓ Retroaktif çözüm: {changed} paket şifre açıldı',
                         'level': 'ok'})

async def on_dll_frame(data: bytes):
    """DLL'den gelen binary frame: [1B type][1B dir][4B len LE][...data...]"""
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

    # CHALLENGE frame: DLL kayıtlı challenge'ı bağlantıda otomatik gönderir
    if pkt_type == 0x43:
        raw = data[6: 6 + data_len]
        if len(raw) >= 11 and raw[0] == 0xc5:
            new_iv = bytes(raw[3:11])
            is_new_session = (session.iv != new_iv)  # IV değiştiyse → yeni oyun oturumu
            session.try_challenge(raw)

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
    if direction == 'R' and len(raw) == 202 and session.try_challenge(raw):
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

    plain = session.decrypt(raw, direction)
    ev    = fmt_packet(session.seq, direction, raw, plain, ts)
    session.seq += 1
    _store(ev)
    await broadcast({'type': 'packet', 'pkt': ev})
    if _track_event(ev):
        await broadcast({'type': 'players_update',
                         'players':    list(session.players.values()),
                         'game_state': session.game_state})

def _store(ev):
    session.packets.append(ev)
    if len(session.packets) > 500:
        session.packets = session.packets[-500:]

# ─── Rütbe adları ────────────────────────────────────────────────────────────

RANK_NAMES: dict[int, str] = {
    0:  'Acemi',      1:  'Er',          2:  'Onbaşı',
    3:  'Çavuş',      4:  'Üstçavuş',    5:  'Başçavuş',
    6:  'Teğmen',     7:  'Üsteğmen',    8:  'Yüzbaşı',
    9:  'Binbaşı',    10: 'Yarbay',      11: 'Albay',
    12: 'Tuğgeneral', 13: 'Tümgeneral',  14: 'Korgeneral',
    15: 'Orgeneral',  16: 'Mareşal',
}

# ─── Oyuncu takip motoru ──────────────────────────────────────────────────────

def _player_ensure(pid: int, ts: str) -> dict:
    if pid not in session.players:
        session.players[pid] = {
            'id': pid, 'name': f'Oyuncu-{pid}', 'rank': 0,
            'rank_name': 'Acemi', 'team': -1, 'alive': False,
            'in_game': False, 'kills': 0, 'deaths': 0, 'score': 0,
            'seen_at': ts,
        }
    return session.players[pid]

def _parse_player_entry(payload: bytes, ts: str, in_game: bool = False) -> bool:
    """Genel oyuncu giriş formatı: [2B id][1B name_len][name…][1B rank][1B team]"""
    try:
        if len(payload) < 4:
            return False
        pid      = struct.unpack_from('<H', payload, 0)[0]
        name_len = payload[2]
        if 3 + name_len > len(payload):
            return False
        name = payload[3:3 + name_len].decode('utf-8', errors='replace').strip('\x00')
        rank = payload[3 + name_len]     if (3 + name_len)     < len(payload) else 0
        team = payload[4 + name_len]     if (4 + name_len)     < len(payload) else -1
        p = _player_ensure(pid, ts)
        if name: p['name'] = name
        p['rank']      = rank
        p['rank_name'] = RANK_NAMES.get(rank, f'Rütbe-{rank}')
        if team != 0xFF: p['team'] = team
        p['in_game']   = True
        p['alive']     = in_game
        p['seen_at']   = ts
        return True
    except Exception:
        return False

def _parse_player_list(payload: bytes, ts: str) -> bool:
    """PLAYER_LIST: [1B count][oyuncu giriş…]"""
    try:
        count   = payload[0]
        offset  = 1
        changed = False
        for _ in range(min(count, 32)):
            if offset + 4 > len(payload):
                break
            name_len = payload[offset + 2]
            changed |= _parse_player_entry(payload[offset:], ts,
                                           in_game=(session.game_state == 'ingame'))
            offset += 3 + name_len + 2   # id(2) + len(1) + name + rank(1) + team(1)
        return changed
    except Exception:
        return False

def _track_event(ev: dict) -> bool:
    """Paketten oyuncu durumunu güncelle. Değişiklik olduysa True döndür."""
    if ev.get('status') not in ('ok', 'large'):
        return False
    op_str = ev.get('opcode', '')
    if not op_str:
        return False
    try:
        op = int(op_str, 16)
    except ValueError:
        return False
    plain_hex = ev.get('plain_hex', '')
    if not plain_hex:
        return False
    try:
        plain = bytes.fromhex(plain_hex)
    except ValueError:
        return False
    payload = plain[3:]   # [len][proto][opcode] → payload
    ts      = ev.get('ts', time.strftime('%H:%M:%S'))
    changed = False

    try:
        if op == 0x32:               # GAME_START
            session.game_state = 'ingame'
            for p in session.players.values():
                p['in_game'] = True
                p['alive']   = True
                p['kills']   = 0
                p['deaths']  = 0
                p['score']   = 0
            changed = True

        elif op == 0x33:             # GAME_END
            session.game_state = 'room'
            for p in session.players.values():
                p['alive']   = False
                p['in_game'] = False
            changed = True

        elif op == 0x22 and len(payload) >= 4:  # PLAYER_ENTER
            changed = _parse_player_entry(payload, ts,
                                          in_game=(session.game_state == 'ingame'))

        elif op == 0x21 and len(payload) >= 1:  # PLAYER_LIST
            changed = _parse_player_list(payload, ts)

        elif op == 0x23 and len(payload) >= 2:  # PLAYER_LEAVE
            pid = struct.unpack_from('<H', payload, 0)[0]
            if pid in session.players:
                session.players[pid]['in_game'] = False
                session.players[pid]['alive']   = False
                changed = True

        elif op == 0x4b and len(payload) >= 4:  # PLAYER_DEAD
            killer = struct.unpack_from('<H', payload, 0)[0]
            victim = struct.unpack_from('<H', payload, 2)[0]
            if victim in session.players:
                session.players[victim]['alive']  = False
                session.players[victim]['deaths'] += 1
                changed = True
            if killer in session.players and killer != victim:
                session.players[killer]['kills'] += 1
                changed = True

        elif op == 0x3c and len(payload) >= 2:  # SPAWN — oyuncu yeniden doğdu
            # Spawn paketinde genellikle pid yoktur; koordinatlardan hangisi bilinmez.
            # Güvenli yaklaşım: tüm oyuncuların alive durumunu koruyalım.
            pass

        elif op in (0x17, 0x4d) and len(payload) >= 3:  # USER_INFO / PLAYER_INFO
            changed = _parse_player_entry(payload, ts,
                                          in_game=(session.game_state == 'ingame'))
    except Exception:
        pass
    return changed

# ─── Oyuncu eylem paket yapıcıları ───────────────────────────────────────────
# NOT: Bu formatlar PB özel sunucu protokolüne dayalı en iyi tahmindir.
# Gerçek admin paketleri yakalandıkça güncelleyin.

def _mk_pkt(opcode: int, payload: bytes) -> bytes:
    """[len_field][0x0D][opcode][payload]"""
    return bytes([len(payload) & 0xFF, 0x0D, opcode]) + payload

def build_kill_pkt(target_id: int) -> bytes:
    """Admin öldür: opcode 0x60, eylem=0x01, hedef"""
    return _mk_pkt(0x60, struct.pack('<BH', 0x01, target_id))

def build_kick_pkt(target_id: int, reason: int = 0) -> bytes:
    """Odadan at: opcode 0x62, hedef + sebep"""
    return _mk_pkt(0x62, struct.pack('<HB', target_id, reason))

def build_edit_name_pkt(target_id: int, new_name: str) -> bytes:
    """İsim değiştir: opcode 0x65, hedef + [len][name]"""
    nb = new_name.encode('utf-8')[:32]
    return _mk_pkt(0x65, struct.pack('<HB', target_id, len(nb)) + nb)

def build_edit_rank_pkt(target_id: int, new_rank: int) -> bytes:
    """Rütbe değiştir: opcode 0x66, hedef + rütbe"""
    return _mk_pkt(0x66, struct.pack('<HH', target_id, new_rank & 0xFF))

def build_give_item_pkt(target_id: int, item_id: int,
                         qty: int = 1, days: int = 0) -> bytes:
    """Eşya ver: opcode 0x67, hedef + item_id + adet + gün"""
    return _mk_pkt(0x67, struct.pack('<HHHH', target_id, item_id, qty & 0xFFFF, days & 0xFFFF))

def build_teleport_pkt(target_id: int, x: float, y: float, z: float) -> bytes:
    """Işınla: opcode 0x68, hedef + xyz float"""
    return _mk_pkt(0x68, struct.pack('<Hfff', target_id, x, y, z))

async def _inject_plain(ws, plain: bytes, action_label: str, pid: int):
    """Plaintext paketi şifrele ve DLL'e gönder; sonucu ws'e bildir.

    ÖNEMLİ — CFB stream desynci:
    DLL inject'i hook_send'i tetiklemeden orig_send ile gönderir.
    Bu yüzden inject cipher game server'ın state'ini ilerletir ama
    game client habersiz kalır → sonraki gerçek paket game server'da
    yanlış decrypt edilir → bağlantı kesilir.

    Çözüm: şifrelemeden önce iv_send/n_send snapshot'ı alıp geri yükle.
    Böylece Python tracking game client ile senkron kalır.
    Game server desynci DLL tarafında çözülmeli (inject sonrası
    game client state'ini de ilerletmek gerekir).
    """
    if not session.dll_ws:
        await ws.send_json({'type': 'action_error', 'msg': 'DLL bağlı değil'})
        return
    if not session.has_key() or not session.has_iv():
        await ws.send_json({'type': 'action_error', 'msg': 'Anahtar / IV yok'})
        return

    # Snapshot — inject orig_send ile gönderildiği için hook_send tetiklenmez;
    # state'i geri yükleyerek Python tracking'i game client ile senkron tutuyoruz.
    iv_snap = session.iv_send
    n_snap  = session.n_send

    cipher = session.encrypt(plain)

    # State'i geri yükle: game client inject'ten habersiz, Python bunu bilmeli.
    session.iv_send = iv_snap
    session.n_send  = n_snap

    frame = bytes([0x49, 0x00]) + struct.pack('<I', len(cipher)) + cipher
    try:
        await session.dll_ws.send_bytes(frame)
        pname = session.players.get(pid, {}).get('name', f'ID={pid}')
        await ws.send_json({
            'type':      'action_ok',
            'action':    action_label,
            'pid':       pid,
            'pname':     pname,
            'plain_hex': plain.hex(),
            'msg':       f'✓ {action_label} → {pname} (plain: {plain.hex()})',
        })
    except Exception as e:
        await ws.send_json({'type': 'action_error', 'msg': str(e)})

# ─── WebSocket: Tarayıcı bağlantısı (/ui) ────────────────────────────────────

async def ui_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    session.ui_clients.add(ws)

    # İlk bağlantıda geçmiş + durum + oyuncu listesi gönder
    await ws.send_json({
        'type':       'init',
        'dll_status': 'connected' if session.dll_ws else 'disconnected',
        'has_key':    session.has_key(),
        'has_iv':     session.has_iv(),
        'iv':         session.iv.hex() if session.iv else None,
        'history':    session.packets[-200:],
        'players':    list(session.players.values()),
        'game_state': session.game_state,
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

        # Snapshot/restore: inject orig_send ile gider, hook_send tetiklenmez.
        # Python tracking'i bozmaması için iv_send geri yüklenir; DLL'den
        # gelen px_forward echo frame'i durumu doğru konuma taşır.
        iv_snap, n_snap = session.iv_send, session.n_send
        cipher = session.encrypt(plain)
        session.iv_send, session.n_send = iv_snap, n_snap
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

    elif t == 'player_action':
        action = cmd.get('action', '')
        try:
            pid = int(cmd.get('pid', 0))
        except (ValueError, TypeError):
            await ws.send_json({'type': 'action_error', 'msg': 'Geçersiz pid'}); return

        _builders = {
            'kill':      lambda: build_kill_pkt(pid),
            'kick':      lambda: build_kick_pkt(pid, int(cmd.get('reason', 0))),
            'edit_name': lambda: build_edit_name_pkt(pid, str(cmd.get('name', ''))[:32]),
            'edit_rank': lambda: build_edit_rank_pkt(pid, int(cmd.get('rank', 0))),
            'give_item': lambda: build_give_item_pkt(
                pid, int(cmd.get('item_id', 0)),
                int(cmd.get('qty', 1)), int(cmd.get('days', 0))),
            'teleport':  lambda: build_teleport_pkt(
                pid, float(cmd.get('x', 0.0)),
                float(cmd.get('y', 0.0)), float(cmd.get('z', 0.0))),
        }
        if action not in _builders:
            await ws.send_json({'type': 'action_error', 'msg': f'Bilinmeyen eylem: {action}'}); return
        try:
            plain = _builders[action]()
        except Exception as e:
            await ws.send_json({'type': 'action_error', 'msg': f'Paket oluşturulamadı: {e}'}); return
        await _inject_plain(ws, plain, action, pid)

    elif t == 'get_players':
        await ws.send_json({
            'type':       'players_update',
            'players':    list(session.players.values()),
            'game_state': session.game_state,
        })

    elif t == 'clear_players':
        session.players.clear()
        session.game_state = 'lobby'
        await broadcast({'type': 'players_update', 'players': [], 'game_state': 'lobby'})

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

async def players_handler(request):
    return web.json_response({
        'players':    list(session.players.values()),
        'game_state': session.game_state,
        'count':      len(session.players),
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

/* Right-panel tab bar */
#rtab-bar{display:flex;background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0}
.rtab{flex:1;text-align:center;padding:7px 4px;font-size:10px;text-transform:uppercase;
  letter-spacing:1.5px;color:var(--gray);cursor:pointer;border-bottom:2px solid transparent;
  transition:color .15s,border-color .15s}
.rtab:hover{color:var(--text)}
.rtab.on{color:var(--blue);border-bottom-color:var(--blue)}
.rtab-content{display:flex;flex-direction:column;flex:1;overflow:hidden}

/* Detail tab */
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

/* Players tab */
#tab-players{background:var(--bg)}
#pl-hd{background:var(--bg2);border-bottom:1px solid var(--border);padding:6px 12px;
  flex-shrink:0;display:flex;align-items:center;gap:8px}
#pl-state{font-size:10px;padding:1px 8px;border-radius:10px;border:1px solid;
  background:transparent;font-family:var(--mono)}
#pl-state.lobby{color:var(--gray);border-color:var(--border)}
#pl-state.room{color:var(--yellow);border-color:var(--yellow)55}
#pl-state.ingame{color:var(--green);border-color:var(--green)55}
#pl-cnt{font-size:10px;color:var(--gray);flex:1}
#pl-refresh{font-size:10px;background:transparent;border:1px solid var(--border);
  color:var(--gray);padding:1px 8px;border-radius:3px;cursor:pointer}
#pl-refresh:hover{color:var(--text)}
#pl-clear-btn{font-size:10px;background:transparent;border:1px solid var(--red)55;
  color:var(--red);padding:1px 8px;border-radius:3px;cursor:pointer}
#pl-clear-btn:hover{background:var(--red);color:#000}
#pl-list{flex:1;overflow-y:auto;padding:6px 8px}
#pl-empty{color:var(--gray);font-size:11px;text-align:center;padding:24px 0}

.pl-team-hd{font-size:9px;text-transform:uppercase;letter-spacing:1.5px;
  padding:4px 4px 2px;margin-top:6px;margin-bottom:2px}
.pl-team-blue{color:#58a6ff}.pl-team-red{color:#f85149}.pl-team-none{color:var(--gray)}

.pl-card{background:var(--bg2);border:1px solid var(--border);border-radius:5px;
  margin-bottom:5px;overflow:hidden}
.pl-card-top{display:flex;align-items:center;gap:7px;padding:6px 8px}
.pl-alive-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.pl-alive-dot.alive{background:var(--green);box-shadow:0 0 4px var(--green)}
.pl-alive-dot.dead{background:#3a3f4a}
.pl-name{font-size:12px;font-weight:700;color:var(--text);flex:1;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pl-rank{font-size:9px;color:#cba6f7;white-space:nowrap}
.pl-id{font-size:9px;color:var(--gray)}
.pl-kd{font-size:9px;color:var(--gray);white-space:nowrap}
.pl-card-acts{display:flex;gap:4px;padding:0 8px 6px;flex-wrap:wrap}
.act-btn{font-size:9px;padding:2px 8px;border-radius:3px;cursor:pointer;border:1px solid;
  background:transparent;font-family:var(--mono);transition:background .12s}
.act-kill{color:var(--red);border-color:var(--red)55}
.act-kill:hover{background:var(--red);color:#000}
.act-kick{color:var(--yellow);border-color:var(--yellow)55}
.act-kick:hover{background:var(--yellow);color:#000}
.act-edit{color:var(--blue);border-color:var(--blue)55}
.act-edit:hover{background:var(--blue);color:#000}
.act-log{font-size:9px;color:var(--gray);font-style:italic}

/* Action log at bottom of players panel */
#pl-actlog{background:var(--bg2);border-top:1px solid var(--border);
  padding:5px 8px;flex-shrink:0;min-height:32px;max-height:70px;overflow-y:auto}
.al-line{font-size:10px;padding:1px 0}
.al-ok{color:var(--green)}.al-err{color:var(--red)}.al-info{color:var(--gray)}

/* Edit modal */
#pl-modal{display:none;position:fixed;inset:0;z-index:100;align-items:center;justify-content:center}
#pl-modal.open{display:flex}
#modal-bg{position:absolute;inset:0;background:#0009}
#modal-box{position:relative;background:var(--bg2);border:1px solid var(--border);
  border-radius:8px;width:360px;max-width:95vw;z-index:1;padding:0;overflow:hidden}
#modal-hd{background:var(--bg3);padding:10px 14px;display:flex;align-items:center;gap:8px;
  border-bottom:1px solid var(--border)}
#modal-hd h2{font-size:12px;flex:1;color:var(--text)}
#modal-close{background:transparent;border:none;color:var(--gray);cursor:pointer;font-size:16px;line-height:1}
#modal-body{padding:12px 14px;display:flex;flex-direction:column;gap:10px}
.mf{display:flex;flex-direction:column;gap:3px}
.mf label{font-size:9px;color:var(--gray);text-transform:uppercase;letter-spacing:1px}
.mf input,.mf select{background:var(--bg3);border:1px solid var(--border);color:var(--text);
  padding:5px 8px;border-radius:4px;font-family:var(--mono);font-size:11px;width:100%}
.mf-row{display:flex;gap:8px}
.mf-row .mf{flex:1}
#modal-ft{padding:10px 14px;display:flex;gap:8px;justify-content:flex-end;
  border-top:1px solid var(--border);background:var(--bg3)}
.modal-apply{background:var(--blue);border:none;color:#000;padding:4px 16px;
  border-radius:4px;cursor:pointer;font-family:var(--mono);font-size:11px;font-weight:700}
.modal-apply:hover{opacity:.85}
.modal-cancel{background:transparent;border:1px solid var(--border);color:var(--gray);
  padding:4px 10px;border-radius:4px;cursor:pointer;font-size:11px}
#modal-st{font-size:10px;min-height:14px;padding:0 14px 6px;color:var(--gray)}

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

  <!-- Sağ: detay + oyuncular + inject -->
  <div id="right">
    <!-- Tab bar -->
    <div id="rtab-bar">
      <div class="rtab on" data-tab="detail">📦 Detay</div>
      <div class="rtab"    data-tab="players">👥 Oyuncular</div>
    </div>

    <!-- Detay tab -->
    <div id="tab-detail" class="rtab-content">
      <div id="detail-hd">Paket Detayı</div>
      <div id="detail"><p style="color:var(--gray);font-size:11px;margin-top:8px">Bir satıra tıklayın…</p></div>
    </div>

    <!-- Oyuncular tab -->
    <div id="tab-players" class="rtab-content" style="display:none">
      <div id="pl-hd">
        <span id="pl-state" class="lobby">lobby</span>
        <span id="pl-cnt">0 oyuncu</span>
        <button id="pl-refresh">↺ Yenile</button>
        <button id="pl-clear-btn">🗑 Temizle</button>
      </div>
      <div id="pl-list"><div id="pl-empty">Henüz oyuncu gözlemlenmedi.<br>Oyuna girilince otomatik dolacak.</div></div>
      <div id="pl-actlog"><span class="al-info">— Eylem günlüğü —</span></div>
    </div>

    <!-- Inject (her zaman altta) -->
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

<!-- Oyuncu düzenleme modal -->
<div id="pl-modal">
  <div id="modal-bg"></div>
  <div id="modal-box">
    <div id="modal-hd">
      <h2 id="modal-title">Oyuncu Düzenle</h2>
      <button id="modal-close">✕</button>
    </div>
    <div id="modal-body">
      <div class="mf">
        <label>📝 Yeni İsim</label>
        <input id="m-name" type="text" maxlength="32" placeholder="Oyuncu adı (max 32 karakter)">
      </div>
      <div class="mf">
        <label>⭐ Rütbe (0–16)</label>
        <input id="m-rank" type="number" min="0" max="16" value="0" placeholder="0 = Acemi … 16 = Mareşal">
      </div>
      <div class="mf">
        <label>🎒 Eşya Ver</label>
        <div class="mf-row">
          <div class="mf"><label>Item ID</label><input id="m-item" type="number" min="0" value="0" placeholder="Eşya ID"></div>
          <div class="mf"><label>Adet</label><input id="m-qty" type="number" min="1" value="1"></div>
          <div class="mf"><label>Gün (0=kalıcı)</label><input id="m-days" type="number" min="0" value="0"></div>
        </div>
      </div>
      <div class="mf">
        <label>📍 Işınlama Koordinatları</label>
        <div class="mf-row">
          <div class="mf"><label>X</label><input id="m-x" type="number" value="0" step="0.1"></div>
          <div class="mf"><label>Y</label><input id="m-y" type="number" value="0" step="0.1"></div>
          <div class="mf"><label>Z</label><input id="m-z" type="number" value="0" step="0.1"></div>
        </div>
      </div>
    </div>
    <div id="modal-st"></div>
    <div id="modal-ft">
      <button class="modal-cancel" id="modal-cancel-btn">İptal</button>
      <button class="modal-apply" id="m-apply-name">İsim Uygula</button>
      <button class="modal-apply" id="m-apply-rank">Rütbe Uygula</button>
      <button class="modal-apply" id="m-apply-item">Eşya Ver</button>
      <button class="modal-apply" id="m-apply-tp" style="background:#3fb950">Işınla</button>
    </div>
  </div>
</div>

<script>
// ── WebSocket ────────────────────────────────────────────────────────────────
const WS_URL = `${location.protocol.replace('http','ws')}//${location.host}/ui`;
let ws, packets = [], selSeq = -1, autoScroll = true, injectMode = 'plain';
// Player state
let players = {}, gameState = 'lobby', modalPid = null;

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
    if (m.players) setPlayers(m.players, m.game_state || 'lobby');
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
  else if (m.type === 'players_update') {
    setPlayers(m.players || [], m.game_state || gameState);
  }
  else if (m.type === 'action_ok') {
    addActLog(`✓ ${esc(m.action)} → ${esc(m.pname||'')} · ${esc(m.plain_hex||'')}`, 'ok');
    document.getElementById('modal-st').textContent = m.msg || '✓ Eylem uygulandı';
    document.getElementById('modal-st').style.color = 'var(--green)';
  }
  else if (m.type === 'action_error') {
    addActLog(`✗ ${esc(m.msg||'')}`, 'err');
    document.getElementById('modal-st').textContent = '✗ ' + (m.msg||'Hata');
    document.getElementById('modal-st').style.color = 'var(--red)';
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
  const nmColor = nm.startsWith('UNK') || !nm ? 'var(--gray)' : '#cba6f7';
  // preview: prefer decoded string fields (network-derived → must esc), else raw hex
  let preview = '';
  if (p.decoded && p.decoded.fields && p.decoded.fields.length > 0) {
    const strFields = p.decoded.fields.filter(f => f.k === 'str' && f.v);
    if (strFields.length > 0)
      preview = esc(strFields.map(f => f.v).join(' · ').slice(0, 40));
  }
  if (!preview) preview = esc(p.payload_hex ? p.payload_hex.slice(0,32) : '');
  // All interpolated values: seq/size are numbers; ts/status/opcode/nm are server tokens
  // preview is already esc()'d above; nm comes from _OPCODES (trusted) but esc for depth
  tr.innerHTML = `
    <td class="c-seq">${+p.seq}</td>
    <td class="c-ts">${esc(p.ts)}</td>
    <td class="c-dir d${p.dir==='R'?'R':'S'}">${p.dir==='R'?'←':'→'}</td>
    <td class="c-sz">${+p.size}B</td>
    <td class="c-st s-${esc(p.status)}">${esc(p.status)}</td>
    <td class="c-op">${esc(p.opcode||'—')}</td>
    <td class="c-nm" style="color:${nmColor}">${esc(nm)}</td>
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

// ── HTML escaping (XSS prevention) ───────────────────────────────────────────
// All packet-derived strings MUST pass through esc() before innerHTML insertion.
const _ESC_MAP = {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => _ESC_MAP[c]);
}

// ── Detail ───────────────────────────────────────────────────────────────────
function selectPkt(seq) {
  selSeq = seq;
  document.querySelectorAll('#tbody tr').forEach(r =>
    r.className = +r.dataset.seq === seq ? 'sel' : '');
  const p = packets.find(x => x.seq === seq);
  if (p) showDetail(p);
}

function hexDumpStr(hexStr) {
  // hexStr comes from Python's bytes.hex() — only [0-9a-f] chars, no escaping needed
  // ASCII column: escape HTML metacharacters (0x3c=<, 0x3e=>, 0x26=&, 0x22=", 0x27=')
  if (!hexStr) return '';
  const bytes = hexStr.match(/.{2}/g) || [];
  let out = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.slice(i, i+16);
    const addr = i.toString(16).padStart(4,'0');
    const hex  = row.map((b,j) => b + (j===7?'  ':' ')).join('').trimEnd();
    const asc  = row.map(b => {
      const c = parseInt(b, 16);
      if (c < 32 || c >= 127) return '.';
      return esc(String.fromCharCode(c));   // escape <, >, &, ", '
    }).join('');
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

// Validate that a string is pure lowercase hex (safe to embed in onclick attr)
function isHexOnly(s) { return /^[0-9a-f]*$/.test(s||''); }

function showDetail(p) {
  const d = document.getElementById('detail');
  let h = '';

  // ── Hero: packet name ────────────────────────────────────────────────────
  const dec = p.decoded;
  // name/desc/hint come from our own _OPCODES table (trusted), but escape anyway
  const name = esc(dec ? dec.name : (p.pkt_name || (p.status==='challenge'?'CHALLENGE':'')));
  const desc = esc(dec ? dec.desc : '');
  const hint = dec ? dec.hint : '?';   // only literal values from _OPCODES: 'C→S','S→C','both','?'
  const isUnk = name.startsWith('UNK') || !name;

  h += `<div class="pkt-hero">`;
  h += `<div class="pkt-hero-name${isUnk?' unk':''}">${name||'—'}</div>`;
  if (desc) h += `<div class="pkt-hero-desc">${desc}</div>`;

  // badges — status/opcode/dir are server-controlled safe tokens, esc for defence-in-depth
  h += `<div class="pkt-badges">`;
  if (p.dir==='R')       h += `<span class="pb pb-recv">← S→C</span>`;
  else if (p.dir==='S')  h += `<span class="pb pb-send">→ C→S</span>`;
  const hintCls = badgeCls(hint);
  if (hint && hint!=='?') h += `<span class="pb ${hintCls}">${esc(hint)}</span>`;
  h += `<span class="pb pb-st-${esc(p.status)}">${esc(p.status)}</span>`;
  if (p.opcode) h += `<span class="pb pb-unk">${esc(p.opcode)}</span>`;
  if (dec && dec.pay_len != null) h += `<span class="pb pb-unk">payload ${+dec.pay_len}B</span>`;
  h += `</div></div>`;

  // ── Meta ─────────────────────────────────────────────────────────────────
  h += `<div class="pkt-meta">`;
  h += `<span class="pm">#<b>${+p.seq}</b></span>`;
  h += `<span class="pm">⏱ <b>${esc(p.ts)}</b></span>`;
  h += `<span class="pm">📦 <b>${+p.size}B</b></span>`;
  if (p.proto) h += `<span class="pm">proto <b>${esc(p.proto)}</b></span>`;
  if (p.len_field != null) {
    const exp = (p.size-3)&0xFF;
    const match = p.len_field===exp ? '✓' : `≠${+exp}`;
    h += `<span class="pm">len_field <b>${+p.len_field}</b> ${match}</span>`;
  }
  if (p.note) h += `<span class="pm" style="color:var(--yellow)">${esc(p.note)}</span>`;
  h += `</div>`;

  // ── Decoded fields (UNTRUSTED — all values from network payload) ───────────
  if (dec && dec.fields && dec.fields.length > 0) {
    h += `<div class="sec-hd">Çözümlenen Alanlar</div>`;
    h += `<table class="field-tbl">`;
    for (const f of dec.fields) {
      // f.n (field name) and f.v (field value) are both network-derived → must escape
      const klass = /^[a-z0-9_-]+$/.test(f.k||'') ? f.k : 'val';   // whitelist CSS class
      h += `<tr><td class="fk">${esc(f.n)}</td><td class="fv ${klass}">${esc(f.v)}</td></tr>`;
    }
    h += `</table>`;
  }

  // ── Plaintext hex dump ────────────────────────────────────────────────────
  if (p.plain_hex && isHexOnly(p.plain_hex)) {
    const byteCount = p.plain_hex.length / 2;
    h += `<div class="sec-hd">Plaintext (${byteCount}B)</div>`;
    h += `<div class="hdump-wrap"><div class="hdump">${hexDumpStr(p.plain_hex)}</div>`;
    // onclick attrs: hex is validated pure-hex above — safe to embed directly
    h += `<button class="copy-btn" onclick="fillInject('${p.plain_hex}')">↓ Inject kutusuna kopyala</button>`;
    h += `<button class="copy-btn" onclick="copyHex('${p.plain_hex}')">📋 Kopyala</button></div>`;
  }

  // ── Raw (cipher) hex dump ─────────────────────────────────────────────────
  if (p.raw_hex && isHexOnly(p.raw_hex)) {
    const label = p.status === 'challenge' ? 'Challenge Ham Veri' : 'Raw / Şifreli';
    h += `<div class="sec-hd">${label} (${p.raw_hex.length/2}B)</div>`;
    h += `<div class="hdump-wrap"><div class="hdump">${hexDumpStr(p.raw_hex)}</div></div>`;
  }

  d.innerHTML = h;
  // Use textContent for the header — never innerHTML with packet data
  document.getElementById('detail-hd').textContent =
    (dec?.name || p.pkt_name) ? `Paket: ${dec?.name || p.pkt_name}` : 'Paket Detayı';
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

// ── Tab switching ────────────────────────────────────────────────────────────
document.querySelectorAll('#rtab-bar .rtab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('#rtab-bar .rtab').forEach(t => t.classList.remove('on'));
    tab.classList.add('on');
    document.querySelectorAll('.rtab-content').forEach(c => c.style.display = 'none');
    const target = document.getElementById('tab-' + tab.dataset.tab);
    if (target) target.style.display = 'flex';
  });
});

// ── Players ──────────────────────────────────────────────────────────────────
const RANK_NAMES = ['Acemi','Çavuş','Üstçavuş','Asteğmen','Teğmen','Üsteğmen',
  'Yüzbaşı','Binbaşı','Yarbay','Albay','Tuğgeneral','Tümgeneral','Korgeneral',
  'General','Mareşal Yrd','Mareşal','Büyük Mareşal'];

function setPlayers(arr, state) {
  // update state badge
  gameState = state || 'lobby';
  const stEl = document.getElementById('pl-state');
  stEl.textContent = gameState;
  stEl.className = gameState;

  // rebuild lookup
  players = {};
  arr.forEach(p => { players[p.id] = p; });

  document.getElementById('pl-cnt').textContent = arr.length + ' oyuncu';

  const list = document.getElementById('pl-list');
  if (!arr.length) {
    list.innerHTML = '<div id="pl-empty">Henüz oyuncu gözlemlenmedi.<br>Oyuna girilince otomatik dolacak.</div>';
    return;
  }

  // group by team
  const teams = {};
  arr.forEach(p => {
    const t = p.team ?? 0;
    if (!teams[t]) teams[t] = [];
    teams[t].push(p);
  });

  let h = '';
  Object.entries(teams).sort(([a],[b]) => +a - +b).forEach(([team, members]) => {
    const teamLabel = team == 1 ? '🔵 Mavi Takım' : team == 2 ? '🔴 Kırmızı Takım' : '⬜ Takımsız';
    const teamCls   = team == 1 ? 'pl-team-blue' : team == 2 ? 'pl-team-red' : 'pl-team-none';
    h += `<div class="pl-team-hd ${teamCls}">${teamLabel}</div>`;
    members.forEach(p => {
      const alive = p.alive !== false;
      const rankName = RANK_NAMES[p.rank] || ('Rütbe ' + (p.rank||0));
      h += `<div class="pl-card">
        <div class="pl-card-top">
          <div class="pl-alive-dot ${alive?'alive':'dead'}"></div>
          <div class="pl-name">${esc(p.name||'?')}</div>
          <div class="pl-rank">${esc(rankName)}</div>
          <div class="pl-id">ID ${+p.id}</div>
          <div class="pl-kd">${+( p.kills||0)}K / ${+(p.deaths||0)}D</div>
        </div>
        <div class="pl-card-acts">
          <button class="act-btn act-kill" onclick="playerAction(${+p.id},'kill')">☠ Kill</button>
          <button class="act-btn act-kick" onclick="playerAction(${+p.id},'kick')">⚡ Kick</button>
          <button class="act-btn act-edit" onclick="openModal(${+p.id})">✏ Düzenle</button>
        </div>
      </div>`;
    });
  });
  list.innerHTML = h;
}

function playerAction(pid, action) {
  ws && ws.send(JSON.stringify({type:'player_action', pid, action}));
}

function addActLog(msg, cls) {
  const log = document.getElementById('pl-actlog');
  const div = document.createElement('div');
  div.className = 'al-line al-' + (cls||'info');
  div.textContent = msg;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

// ── Player refresh / clear ────────────────────────────────────────────────────
document.getElementById('pl-refresh').addEventListener('click', () =>
  ws && ws.send(JSON.stringify({type:'get_players'})));
document.getElementById('pl-clear-btn').addEventListener('click', () =>
  ws && ws.send(JSON.stringify({type:'clear_players'})));

// ── Edit modal ────────────────────────────────────────────────────────────────
function openModal(pid) {
  modalPid = pid;
  const p = players[pid] || {};
  document.getElementById('modal-title').textContent = 'Oyuncu Düzenle — ' + esc(p.name||('ID '+pid));
  document.getElementById('m-name').value  = p.name  || '';
  document.getElementById('m-rank').value  = p.rank  ?? 0;
  document.getElementById('m-item').value  = 0;
  document.getElementById('m-qty').value   = 1;
  document.getElementById('m-days').value  = 0;
  document.getElementById('m-x').value     = 0;
  document.getElementById('m-y').value     = 0;
  document.getElementById('m-z').value     = 0;
  document.getElementById('modal-st').textContent = '';
  document.getElementById('pl-modal').classList.add('open');
}

function closeModal() {
  document.getElementById('pl-modal').classList.remove('open');
  modalPid = null;
}

document.getElementById('modal-close').addEventListener('click', closeModal);
document.getElementById('modal-cancel-btn').addEventListener('click', closeModal);
document.getElementById('modal-bg').addEventListener('click', closeModal);

document.getElementById('m-apply-name').addEventListener('click', () => {
  if (modalPid == null) return;
  const name = document.getElementById('m-name').value.trim();
  if (!name) return;
  ws && ws.send(JSON.stringify({type:'player_action', pid:modalPid, action:'edit_name', name}));
});
document.getElementById('m-apply-rank').addEventListener('click', () => {
  if (modalPid == null) return;
  const rank = parseInt(document.getElementById('m-rank').value) || 0;
  ws && ws.send(JSON.stringify({type:'player_action', pid:modalPid, action:'edit_rank', rank}));
});
document.getElementById('m-apply-item').addEventListener('click', () => {
  if (modalPid == null) return;
  const item_id = parseInt(document.getElementById('m-item').value) || 0;
  const qty     = parseInt(document.getElementById('m-qty').value)  || 1;
  const days    = parseInt(document.getElementById('m-days').value) || 0;
  ws && ws.send(JSON.stringify({type:'player_action', pid:modalPid, action:'give_item', item_id, qty, days}));
});
document.getElementById('m-apply-tp').addEventListener('click', () => {
  if (modalPid == null) return;
  const x = parseFloat(document.getElementById('m-x').value) || 0;
  const y = parseFloat(document.getElementById('m-y').value) || 0;
  const z = parseFloat(document.getElementById('m-z').value) || 0;
  ws && ws.send(JSON.stringify({type:'player_action', pid:modalPid, action:'teleport', x, y, z}));
});
</script>
</body>
</html>"""

# ─── Log replay ──────────────────────────────────────────────────────────────

_NET_LINE = re.compile(
    r'\[(\d{2}:\d{2}:\d{2})'       # timestamp HH:MM:SS
    r'[^\]]*\]\s+TCP\s+'
    r'(RECV|SEND)\s+[←→]\s+'
    r'(\S+)\s+'                     # IP:port
    r'bf_calls=\d+\s+'
    r'\[(\d+) bytes\]:\s+'
    r'([0-9a-fA-F]+)'               # hex (may be truncated)
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
                    'ts':   ts,
                    'dir':  'R' if direction == 'RECV' else 'S',
                    'size': size,
                    'raw':  raw,                  # first ≤128 bytes
                    'full': len(raw) >= size,     # no truncation?
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

    # Replay için yön başına bağımsız CFB akış durumu
    rp_iv_r = rp_iv_s = session.iv  # mevcut IV'den başla (challenge bulunana kadar)
    rp_n_r  = rp_n_s  = 0

    evs = []
    for p in pkts:
        raw, direction, ts, size = p['raw'], p['dir'], p['ts'], p['size']

        # Challenge tespiti — yeni IV + akışları sıfırla
        if direction == 'R' and size == 202 and len(raw) >= 11 and raw[0] == 0xc5:
            new_iv = bytes(raw[3:11])
            rp_iv_r = rp_iv_s = new_iv
            rp_n_r  = rp_n_s  = 0
            session.set_iv(new_iv)     # session IV'ini de set_iv() ile güncelle
            ev = fmt_packet(session.seq, 'R', raw, None, ts)
            ev['status'] = 'challenge'
            ev['note']   = f'IV={new_iv.hex()} (log)'
        else:
            plain = None
            if session.P and session.S and rp_iv_r and p['full']:
                # Stateful CFB: yön başına akış durumu korunur
                if direction == 'R':
                    plain, rp_iv_r, rp_n_r = _cfb64(
                        session.P, session.S, raw, rp_iv_r, encrypt=False, n_in=rp_n_r)
                else:
                    plain, rp_iv_s, rp_n_s = _cfb64(
                        session.P, session.S, raw, rp_iv_s, encrypt=False, n_in=rp_n_s)
            ev = fmt_packet(session.seq, direction, raw, plain, ts)
            if not p['full'] and ev['status'] not in ('ok', 'large', 'challenge'):
                ev['status'] = 'truncated'
                ev['note']   = f'log kısaltılmış ({len(raw)}/{size}B)'
        session.seq += 1
        _store(ev)
        evs.append(ev)

    # Replay bitti — canlı akış durumunu sync et
    session.iv_recv, session.n_recv = rp_iv_r, rp_n_r
    session.iv_send, session.n_send = rp_iv_s, rp_n_s

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
    app.router.add_get('/api/players',  players_handler)
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
