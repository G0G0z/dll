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
        for cipher, size in test_packets:
            # Per-buffer: her paket n=0'dan bağımsız çözülür
            plain, _, _ = _cfb64(P, S, cipher, iv_bytes, encrypt=False, n_in=0)
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
        """Per-buffer CFB-64 decrypt — her TCP tamponu n=0'dan bağımsız çözülür.
        PointBlank her send()/recv() çağrısını aynı başlangıç IV'i ile ayrı ayrı şifreler."""
        if not self.has_key() or not self.has_iv():
            return None
        plain, _, _ = _cfb64(self.P, self.S, cipher, self.iv, encrypt=False, n_in=0)
        return plain

    def encrypt(self, plain):
        """Per-buffer CFB-64 encrypt — her inject n=0'dan bağımsız şifrelenir."""
        if not self.has_key() or not self.has_iv():
            return None
        cipher, _, _ = _cfb64(self.P, self.S, plain, self.iv, encrypt=True, n_in=0)
        return cipher

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
    #   [~] Protokol akışından çıkarılan tahmin
    #   [?] Bilinmiyor / spekülatif
    # ══════════════════════════════════════════════════════════════
    # ── Bağlantı / Oturum ──────────────────────────────────────
    0x01: ('CONNECT',       'C→S',  'Bağlantı isteği — TCP bağlantı kurulduktan sonra ilk paket [~]'),
    0x02: ('PING',          'both', 'Canlı tutma ping — her iki yönde çalışır [~]'),
    0x03: ('PONG',          'both', 'Canlı tutma pong yanıtı [~]'),
    0x04: ('DISCONNECT',    'both', 'Bağlantı kesme bildirimi — istemci veya sunucu [~]'),
    0x05: ('HANDSHAKE',     'both', 'El sıkışma / kriptografi başlatma [~]'),
    0x06: ('SESSION_OK',    'S→C',  'Oturum onayı — sunucu bağlantıyı kabul etti [~]'),
    0x07: ('RECONNECT',     'C→S',  'Yeniden bağlantı isteği — oturum ID ile [~]'),
    0x08: ('ECHO',          'both', 'Bağlantı test echo — RTT ölçümü [~]'),
    # ── Giriş / Kimlik ──────────────────────────────────────────
    0x14: ('LOGIN_REQ',     'C→S',  'Kullanıcı adı + şifre/hash gönderimi [~]'),
    0x15: ('LOGIN_ACK',     'S→C',  'Login yanıtı — başarı kodu + kullanıcı ID [~]'),
    0x16: ('AUTH_TOKEN',    'C→S',  'Kimlik doğrulama token\'ı — oturum anahtarı [~]'),
    0x17: ('USER_INFO',     'S→C',  'Kullanıcı bilgileri — seviye, deneyim, rütbe [~]'),
    0x18: ('CHAR_SELECT',   'C→S',  'Karakter / slot seçimi [~]'),
    # ── Lobi / Kanal ────────────────────────────────────────────
    0x1e: ('LOBBY_LIST',    'S→C',  'Lobi / kanal listesi — kanal adları ve oyuncu sayıları [~]'),
    0x1f: ('CHANNEL_JOIN',  'C→S',  'Kanala giriş isteği [~]'),
    0x20: ('CHANNEL_ACK',   'S→C',  'Kanal giriş yanıtı — kabul/red kodu [~]'),
    0x21: ('PLAYER_LIST',   'S→C',  'Kanaldaki oyuncu listesi — toplu oyuncu snapshot [~]'),
    0x22: ('PLAYER_ENTER',  'S→C',  'Kanala yeni oyuncu girdi — oyuncu bilgisi [~]'),
    0x23: ('PLAYER_LEAVE',  'S→C',  'Kanaldan oyuncu çıktı — oyuncu ID [~]'),
    # ── Oda ─────────────────────────────────────────────────────
    0x28: ('ROOM_LIST',     'S→C',  'Oda listesi — lobi odaları snapshot [~]'),
    0x29: ('ROOM_CREATE',   'C→S',  'Oda oluşturma isteği — harita, mod, ayarlar [~]'),
    0x2a: ('ROOM_JOIN',     'C→S',  'Odaya katılma isteği — oda ID + şifre [~]'),
    0x2b: ('ROOM_LEAVE',    'C→S',  'Odadan ayrılma [~]'),
    0x2c: ('ROOM_ACK',      'S→C',  'Oda işlemi yanıtı — oluşturma/katılma sonucu [~]'),
    0x2d: ('ROOM_INFO',     'S→C',  'Oda bilgisi — harita, mod, oyuncular, ayarlar [~]'),
    0x2e: ('ROOM_READY',    'C→S',  'Hazır butonu — oyuncu hazır/hazır değil toggle [~]'),
    0x2f: ('ROOM_KICK',     'S→C',  'Odadan atıldı — neden kodu [~]'),
    # ── Oyun / Tur ──────────────────────────────────────────────
    0x32: ('GAME_START',    'S→C',  'Oyun başladı — harita ID, takım atamaları [~]'),
    0x33: ('GAME_END',      'S→C',  'Oyun bitti — kazanan takım, skor tablosu [~]'),
    0x34: ('ROUND_START',   'S→C',  'Tur başladı — süre ve takım bilgisi [~]'),
    0x35: ('ROUND_END',     'S→C',  'Tur bitti — tur kazananı [~]'),
    0x36: ('MAP_DATA',      'S→C',  'Harita verisi / spawn noktaları [~]'),
    0x39: ('ROOM_SETTINGS', 'C→S',  'Oda ayarı değiştirme isteği — oda lideri gönderir [~]'),
    # ── Oyuncu Konumu ve Durumu ──────────────────────────────────
    0x3c: ('SPAWN',         'S→C',  'Spawn koordinatları — konum (x,y,z) + takım [~]'),
    0x3d: ('MOVE',          'both', 'Hareket paketi — konum (x,y,z) + yaw açısı [~]'),
    0x3e: ('JUMP',          'C→S',  'Zıplama [~]'),
    0x3f: ('CROUCH',        'C→S',  'Çömelme / ayağa kalkma toggle [~]'),
    0x40: ('STANCE',        'both', 'Duruş değişikliği / hareket durumu; login akışında 291 B olarak da görüldü (proto=0x0C) [~]'),
    # ── Oyuncu genişletilmiş durum ──────────────────────────────
    0x41: ('STANCE_EX',     'both', 'Duruş / hareket genişletilmiş — animasyon durumu [~]'),
    0x42: ('DAMAGE_NOTIF',  'S→C',  'Hasar bildirimi — aldığı hasar miktarı [~]'),
    0x43: ('BATCH_DATA',    'S→C',  'Toplu kanal/oda verisi — birden fazla alanı bir arada gönderir [~]'),
    0x44: ('PLAYER_DATA',   'S→C',  'Oyuncu temel verisi — isim, seviye, takım [~]'),
    0x45: ('CHAR_DATA',     'S→C',  'Karakter profil verisi — login sonrası S→C, 163 B (160 B payload) [✓]'),
    # ── Silah / Savaş ───────────────────────────────────────────
    0x46: ('SHOOT',         'C→S',  'Ateş paketi — silah ID ve hedef koordinatı [~]'),
    0x47: ('HIT',           'S→C',  'Vurma bildirimi — saldıran ID, hedef ID, hasar, vurulan bölge; 35 B [✓]'),
    0x48: ('ITEM_ACTION',   'C→S',  'Eşya kullanma / bırakma — eşya ID ve aksiyon kodu [~]'),
    0x49: ('RELOAD',        'C→S',  'Şarjör doldurma [~]'),
    0x4a: ('WEAPON_SWITCH', 'C→S',  'Silah değiştirme — silah slot ID [~]'),
    0x4b: ('PLAYER_DEAD',   'S→C',  'Ölüm bildirimi — ölen ID, öldüren ID, silah kodu [~]'),
    0x4c: ('CHAT',          'both', 'Sohbet mesajı; C→S olarak login akışında da gözlemlendi, 19 B [✓]'),
    0x4d: ('SERVER_REDIR',  'S→C',  'Sunucu yönlendirme — oyun sunucusu IP + port [~]'),
    0x4e: ('GRENADE',       'C→S',  'El bombası fırlatma — tip + başlangıç koordinatı [~]'),
    0x4f: ('EXPLOSION',     'S→C',  'Patlama efekti — merkez koordinatı + yarıçap [~]'),
    # ── Skor / İstatistik ───────────────────────────────────────
    0x50: ('SCORE',         'S→C',  'Skor güncellemesi — takım A ve B puanı [~]'),
    0x51: ('KILL_FEED',     'S→C',  'Kill/ölüm özeti — öldüren, ölen, silah [~]'),
    0x52: ('STATS',         'S→C',  'Oyun sonu istatistikleri — tüm oyuncu skorları [~]'),
    # ── Oyuncu / Takım Genişletilmiş ─────────────────────────────
    0x53: ('MAP_INFO_EX',   'S→C',  'Harita genişletilmiş bilgi — ek harita parametreleri [~]'),
    0x54: ('TEAM_INFO',     'S→C',  'Takım ataması / bilgisi — takım isimleri ve üyeler [~]'),
    # ── DİKKAT: 0x55 ve 0x57 gerçek trafik verisiyle C→S doğrulandı ──
    0x55: ('SESSION_REQ',   'C→S',  'Oturum isteği / istemci onay paketi — login akışında C→S, 19 B (16 B payload) [✓]'),
    0x56: ('XP_UPDATE',     'S→C',  'Deneyim / seviye güncellemesi — yeni XP ve seviye [~]'),
    0x57: ('DATA_ACK',      'C→S',  'Sunucu verisi onayı — login akışında C→S, 19 B (16 B payload) [✓]'),
    0x58: ('SERVER_CFG',    'S→C',  'Sunucu yapılandırma / parametreler [~]'),
    0x59: ('CHAT_CHANNEL',  'S→C',  'Sohbet kanalı bilgisi [~]'),
    # ── Envanter / Mağaza ───────────────────────────────────────
    0x5a: ('SHOP_BUY',      'C→S',  'Eşya / silah satın alma — ürün ID + miktar [~]'),
    0x5b: ('SYSTEM_MSG',    'S→C',  'Sistem mesajı / duyuru — metin içerik [~]'),
    0x5c: ('INVENTORY',     'S→C',  'Envanter listesi — sahip olunan eşyalar [~]'),
    0x5d: ('EQUIP',         'C→S',  'Eşya donatma — slot + eşya ID [~]'),
    0x5e: ('ROOM_STATE',    'S→C',  'Oda üye durumu güncellemesi — hazır/hazır değil [~]'),
    0x5f: ('RANK_INFO',     'S→C',  'Rütbe / VIP bilgisi — mevcut rütbe ve puanı [~]'),
    # ── Oyun İçi Geniş Veri ─────────────────────────────────────
    0x62: ('PLAYER_STATS',  'S→C',  'Oyuncu istatistik paketi — K/D, isabet vs. [~]'),
    0x63: ('KILL_STREAK',   'S→C',  'Kill serisi / combo bildirimi [~]'),
    0x64: ('HEARTBEAT',     'both', 'Uygulama seviyesi canlı tutma — zaman damgası [~]'),
    0x65: ('ACHIEVEMENT',   'S→C',  'Başarım / rozet verisi — yeni kazanılan [~]'),
    0x68: ('WORLD_DATA',    'S→C',  'Oyun dünyası / harita event verisi [~]'),
    0x69: ('OBJECTIVE',     'S→C',  'Hedef / görev bilgisi — bomba, bayrak konumu [~]'),
    0x6a: ('LOBBY_INFO',    'S→C',  'Lobi / kanal toplu veri [~]'),
    0x6b: ('ROOM_ENTER_ACK','S→C',  'Odaya giriş onayı — slot numarası [~]'),
    0x6c: ('GAME_EVENT',    'S→C',  'Oyun içi olay — kapı, araç, nesne [~]'),
    0x6d: ('POS_BATCH',     'S→C',  'Oyuncu konum toplu paketi — tüm oyuncuların konumu [~]'),
    0x6e: ('SERVER_INFO',   'S→C',  'Sunucu bilgisi — IP, port, bölge kodu [~]'),
    0x6f: ('SESSION_DATA',  'S→C',  'Oturum verisi — session token ve parametreler [~]'),
    # ── Toplu Durum (büyük buffer'lardan sub-paket olarak gelir) ─
    0x70: ('STATE_BATCH',   'S→C',  'Oyuncu durum toplu paketi — anlık snapshot [~]'),
    0x71: ('MAP_OBJECTS',   'S→C',  'Harita nesneleri / pickup noktaları [~]'),
    0x72: ('EQUIP_INFO',    'S→C',  'Donanım / ekipman bilgisi — silah ve zırh listesi [~]'),
    0x73: ('GAME_RULES',    'S→C',  'Oyun kuralları / mod ayarları [~]'),
    0x74: ('MISSION',       'S→C',  'Görev bilgisi / ilerleme yüzdesi [~]'),
    0x75: ('VOTE',          'both', 'Oylama — kick, harita değişimi, oyun sonu [~]'),
    0x77: ('PLAYER_ACTION', 'both', 'Oyuncu eylem paketi — animasyon/aksiyon kodu [~]'),
    0x78: ('CLAN_INFO',     'S→C',  'Klan bilgisi — klan adı, üye sayısı, rütbe [~]'),
    0x79: ('CLAN_RANK',     'S→C',  'Klan rütbe güncellemesi [~]'),
    0x7a: ('BROADCAST',     'S→C',  'Sunucu yayını / duyurusu — sistem mesajı [~]'),
    0x7b: ('FRIEND_LIST',   'S→C',  'Arkadaş listesi — login sonrası S→C; 91 B (88 B) veya 755 B (752 B, proto=0x0F) [✓]'),
    0x7c: ('FRIEND_STATUS', 'S→C',  'Arkadaş çevrimiçi durum güncellemesi [~]'),
    0x7d: ('SOCIAL_DATA',   'S→C',  'Sosyal / topluluk verisi — guild, arkadaş grubu [~]'),
    0x7e: ('EVENT_BATCH',   'S→C',  'Oyun olay toplu paketi — sunucu akışı [~]'),
}

# Geçerli proto byte değerleri (PointBlank varyantı):
#   0x0D → standart paket (≤258 B), her iki yön
#   0x0C → büyük istemci paketi (>258 B) — gerçek trafik verisiyle doğrulandı
#   0x0F → büyük sunucu paketi (>258 B) — gerçek trafik verisiyle doğrulandı
_VALID_PROTO: frozenset[int] = frozenset({0x0C, 0x0D, 0x0F})

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

        elif opcode_byte == 0x45 and len(payload) >= 4:  # CHAR_DATA — 160 B login payload
            # Binary struct; gerçek alan düzeni bilinmiyor.
            # İlk u32: büyük olasılıkla oyuncu/oturum ID'si.
            maybe_id = struct.unpack_from('<I', payload, 0)[0]
            f('Olası oyuncu ID (u32@0)', f'0x{maybe_id:08x}', 'hex')
            f('Payload boyutu', len(payload), 'u32')

        elif opcode_byte == 0x47 and len(payload) >= 6:  # HIT — 32 B; login fazında alan anlamı belirsiz
            # Uyarı: bu decoder oyun içi HIT semantiği varsayar.
            # Login fazında (35 B buffer) alanlar farklı anlam taşıyabilir.
            attacker = struct.unpack_from('<H', payload, 0)[0]
            victim   = struct.unpack_from('<H', payload, 2)[0]
            damage   = struct.unpack_from('<H', payload, 4)[0]
            f('Alan@0 (u16)', f'0x{attacker:04x}', 'hex')
            f('Alan@2 (u16)', f'0x{victim:04x}',   'hex')
            f('Alan@4 (u16)', f'0x{damage:04x}',   'hex')
            if len(payload) >= 7:
                zone = payload[6]
                f('Alan@6 (u8)', f'0x{zone:02x}', 'hex')

        elif opcode_byte == 0x4b and len(payload) >= 4:  # PLAYER_DEAD
            killer = struct.unpack_from('<H', payload, 0)[0]
            victim = struct.unpack_from('<H', payload, 2)[0]
            f('Öldüren ID', killer, 'u16')
            f('Ölen ID',    victim, 'u16')
            if len(payload) >= 5:
                weapon = payload[4]
                f('Silah kodu', f'0x{weapon:02x}', 'hex')

        elif opcode_byte == 0x4c and len(payload) >= 2:  # CHAT / login akışında istemci onay paketi
            # Oyun içi: [1B len][str gönderen][1B len][str mesaj]
            # Login fazı: 16 B binary — Pascal string parse başarısız olursa ham hex göster
            first_len = payload[0]
            if first_len < len(payload) and all(0x20 <= b < 0x7f or b == 0 for b in payload[1:first_len+1]):
                sender, off = _try_string(payload, 0)
                if off < len(payload):
                    msg, _ = _try_string(payload, off)
                    f('Gönderen', sender, 'str')
                    f('Mesaj',    msg,    'str')
                else:
                    f('Gönderen', sender, 'str')
            else:
                f('Token/Binary (hex)', payload.hex(), 'hex')

        elif opcode_byte in (0x55, 0x57) and len(payload) >= 2:
            # SESSION_REQ / DATA_ACK — login akışında C→S, 16 B payload [✓]
            # Binary struct; büyük olasılıkla oturum token veya kimlik doğrulama verisi.
            f('Token (hex)', payload[:16].hex() if len(payload) >= 16 else payload.hex(), 'hex')
            if len(payload) >= 4:
                maybe_id = struct.unpack_from('<I', payload, 0)[0]
                f('Olası token ID@0 (u32)', f'0x{maybe_id:08x}', 'hex')

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

        elif opcode_byte == 0x7b and len(payload) >= 2:  # FRIEND_LIST — 88 B veya 752 B payload [✓]
            # Binary struct; gerçek alan düzeni bilinmiyor.
            # 88 B ve 752 B versiyonlar farklı içerik taşıyor olabilir (short vs long list).
            f('Payload boyutu', len(payload), 'u32')
            if len(payload) >= 4:
                maybe_count = struct.unpack_from('<H', payload, 0)[0]
                f('Alan@0 (u16, olası giriş sayısı?)', f'0x{maybe_count:04x} ({maybe_count})', 'hex')
            if len(payload) >= 6:
                second_u16 = struct.unpack_from('<H', payload, 2)[0]
                f('Alan@2 (u16)', f'0x{second_u16:04x} ({second_u16})', 'hex')

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

    expected   = (size - 3) & 0xFF
    len_ok     = (base['len_field'] == expected)
    proto_ok   = (base['proto'] in _VALID_PROTO)
    # 0x0D → standart (≤258 B), 0x0C/0x0F → büyük paket (>258 B) — hepsi geçerli
    std_size   = (size <= 258)
    alt_proto  = (base['proto'] in (0x0C, 0x0F))

    if len_ok and proto_ok and (std_size or alt_proto):
        base['status'] = 'ok'
    elif proto_ok and not len_ok:   base['status'] = 'large'
    elif proto_ok and len_ok:       base['status'] = 'ok'    # len_ok ama size>258 ve 0x0D
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


def _walk_subpackets(plain: bytes, raw: bytes) -> list[dict]:
    """Decrypt edilmiş TCP tamponundan [len][0x0D][op][payload] bloklarını çıkar.
    raw: orijinal şifreli buffer (slice için).

    Geçerlilik kuralı (veri kaybı olmadan):
      • buffer tamamen tüketildi (leftover == 0), VEYA
      • kalan bayt sayısı < 3 (geçerli bir paket için minimum — padding sayılır).
    Herhangi bir anlamlı artık varsa (leftover >= 3) split yapılmaz;
    orijinal büyük event fmt_packet'e geri döner."""
    pkts = []
    i    = 0
    while i + 3 <= len(plain):
        length = plain[i]
        proto  = plain[i + 1]
        opcode = plain[i + 2]
        total  = length + 3
        if proto != 0x0D:
            break                           # proto yanlış → framing bozuk
        if i + total > len(plain):
            break                           # buffer taşıyor → tamamlanmamış
        pkts.append({
            'offset':    i,
            'total':     total,
            'op':        opcode,
            'len':       length,
            'sub_plain': plain[i: i + total],
            'sub_raw':   raw  [i: i + total] if i + total <= len(raw) else b'',
        })
        i += total

    if not pkts:
        return []

    leftover = len(plain) - i
    # Split yalnızca buffer tamamen tüketildiyse VEYA kalan < 3B (geçerli paket olamaz)
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

        plain, _, _ = _cfb64(session.P, session.S, raw, session.iv, encrypt=False, n_in=0)

        # Büyük buffer: sub-paket ayrıştırması dene
        if ev.get('size', 0) > 258 and status in ('encrypted', 'mismatch', 'proto?', 'large'):
            subs = _walk_subpackets(plain, raw)
            if subs:
                for sub in subs:
                    sub_ev = fmt_packet(0, ev['dir'],
                                        sub['sub_raw'], sub['sub_plain'], ev['ts'])
                    sub_ev['note'] = f'buf:{len(raw)}B @{sub["offset"]} (retro)'
                    new_packets.append(sub_ev)
                changed += len(subs)
                continue  # orijinal büyük event yerine sub-event'ler kullanılır

        # Küçük / ayrıştırılamayan paket — yerinde güncelle
        if status in ('encrypted', 'mismatch', 'proto?'):
            ev['plain_hex']   = plain.hex()
            ev['len_field']   = plain[0] if plain else None
            ev['proto']       = plain[1] if len(plain) > 1 else None
            ev['payload_hex'] = plain[3:67].hex() if len(plain) > 3 else ''
            op_byte           = plain[2] if len(plain) > 2 else None
            sz        = ev['size']
            expected  = (sz - 3) & 0xFF
            len_ok    = (ev['len_field'] == expected)
            proto_ok  = (ev['proto'] in _VALID_PROTO)
            alt_proto = (ev['proto'] in (0x0C, 0x0F))
            if len_ok and proto_ok and (sz <= 258 or alt_proto):
                ev['status'] = 'ok'
            elif proto_ok and len_ok:     ev['status'] = 'ok'
            elif proto_ok:                ev['status'] = 'large'
            elif len_ok:                  ev['status'] = 'proto?'
            else:                         ev['status'] = 'mismatch'
            if op_byte is not None:
                dec = decode_packet(op_byte, plain[3:], ev.get('dir', 'R'))
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

    plain = session.decrypt(raw, direction)

    # Büyük buffer: birden fazla game sub-paketi içerebilir — ayır
    if plain is not None and len(raw) > 258:
        subs = _walk_subpackets(plain, raw)
        if subs:
            for sub in subs:
                ev = fmt_packet(session.seq, direction,
                                sub['sub_raw'], sub['sub_plain'], ts)
                ev['note'] = f'buf:{len(raw)}B @{sub["offset"]}'
                session.seq += 1
                _store(ev)
                await broadcast({'type': 'packet', 'pkt': ev})
            return

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

        plain = None
        if session.P and session.S and session.iv and p['full']:
            plain, _, _ = _cfb64(session.P, session.S, raw, session.iv,
                                  encrypt=False, n_in=0)

        # Büyük tampon: sub-paket ayrıştırması
        if plain is not None and size > 258:
            subs = _walk_subpackets(plain, raw)
            if subs:
                for sub in subs:
                    ev = fmt_packet(session.seq, direction,
                                    sub['sub_raw'], sub['sub_plain'], ts)
                    ev['note'] = f'buf:{size}B @{sub["offset"]} (log)'
                    session.seq += 1; _store(ev); evs.append(ev)
                continue  # büyük buffer'ı tekil event olarak ekleme

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
