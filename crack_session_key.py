#!/usr/bin/env python3
"""
crack_session_key.py
====================
1. pb_crypto.log'dan BF_KEY adaylarını (P-array + S-box) çıkar
2. pb_net.log'dan port 39190 şifreli paketleri çıkar
3. Her aday için BF CFB64 decrypt dene; geçerli protokol başlığı ara
4. Eşleşmeleri raporla

Kullanım: python crack_session_key.py [crypto_log] [net_log]
"""

import sys, re, struct, math, time
from pathlib import Path

CRYPTO_LOG = sys.argv[1] if len(sys.argv) > 1 else "log_data/pb_crypto.log"
NET_LOG    = sys.argv[2] if len(sys.argv) > 2 else "log_data/pb_net.log"

# ─── 1. Game server packets ─────────────────────────────────────────────────

print("[ 1/4 ] Ağ paketleri okunuyor…", flush=True)

GAME_SERVER = "31.169.73.205:39190"

def extract_packets(path):
    packets = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            # "TCP RECV ← 31.169.73.205:39190 ... [N bytes]: hexdata"
            m = re.search(
                r'TCP (RECV|SEND)\s+[←→]\s+31\.169\.73\.205:39190\b.*?\[(\d+) bytes\]:\s*([0-9a-fA-F]+)',
                line)
            if m:
                direction = "recv" if m.group(1) == "RECV" else "send"
                n = int(m.group(2))
                raw = bytes.fromhex(m.group(3))
                # Timestamp
                tm = re.match(r'\[(\d{2}:\d{2}:\d{2}\.\d{3})\]', line)
                ts = tm.group(1) if tm else "?"
                packets.append({"ts": ts, "dir": direction, "n": n, "raw": raw})
    return packets

packets = extract_packets(NET_LOG)
print(f"    → {len(packets)} paket (sunucu: {GAME_SERVER})")
for p in packets:
    print(f"      [{p['ts']}] {p['dir']} {p['n']:5d}B  {p['raw'][:16].hex()}")

# Candidate encrypted packets: skip the first server packet (plaintext challenge)
# Packet 0 from server: c500... starts with c5 00 02 09 → plaintext
recv_pkts = [p for p in packets if p["dir"] == "recv"]
send_pkts = [p for p in packets if p["dir"] == "send"]

print(f"\n    Alınan: {len(recv_pkts)}, Gönderilen: {len(send_pkts)}")

# First recv is the plaintext challenge (opcode 0x0902 identified)
# Subsequent recvs are encrypted candidates
challenge = recv_pkts[0] if recv_pkts else None
encrypted_candidates = recv_pkts[1:] if len(recv_pkts) > 1 else []

if challenge:
    print(f"\n    Challenge (plaintext): {challenge['n']}B  {challenge['raw'][:16].hex()}")
    # The challenge bytes after the 2-byte length may seed the IV
    # offset 4-11 often used as challenge bytes
    challenge_bytes = challenge["raw"]

# Pick the target packet for decryption:
# Use the smallest recv packet after challenge (91B) – fully captured (< 128B)
target = None
for p in encrypted_candidates:
    if p["n"] <= 128:
        target = p
        break
if target is None and encrypted_candidates:
    target = encrypted_candidates[0]

if not target:
    print("HATA: Hedef şifreli paket yok.")
    sys.exit(1)

print(f"\n    Hedef paket: {target['n']}B @ {target['ts']}")
print(f"    Hex: {target['raw'].hex()}")

# ─── 2. Blowfish core (pre-expanded tables) ─────────────────────────────────

def bf_encrypt_block(data_pair, P, S):
    """
    PointBlank custom Blowfish block encrypt.

    Non-standard round structure (confirmed by cipher analysis):
    Standard Blowfish swaps L and R after every round; this game's
    implementation does NOT swap per round — it accumulates all F(L_i)
    into R, then performs a single swap at the end.
    F function (same as standard): F(x) = ((S0[a]+S1[b]) ^ S2[c]) + S3[d]

    Returns encrypted [L, R].
    """
    L, R = data_pair
    for i in range(16):
        L ^= P[i]
        # F(L)
        a = (L >> 24) & 0xFF
        b = (L >> 16) & 0xFF
        c = (L >>  8) & 0xFF
        d =  L        & 0xFF
        F = ((S[0][a] + S[1][b]) & 0xFFFFFFFF) ^ S[2][c]
        F = (F + S[3][d]) & 0xFFFFFFFF
        R ^= F
        # No per-round swap — intentional (confirmed by packet invariant analysis)
    L, R = R, L          # single swap at end
    return [(L ^ P[16]) & 0xFFFFFFFF, (R ^ P[17]) & 0xFFFFFFFF]

def bf_cfb64_decrypt(ciphertext, P, S, iv_bytes=None, le_iv=False):
    """
    BF CFB-64 decryption using pre-expanded P and S tables.

    iv_bytes : 8-byte IV (default all zeros)
    le_iv    : if True, interpret IV as 2×LE uint32 (game custom)
               if False, interpret as 2×BE uint32 (OpenSSL l2n/n2l)
    """
    if iv_bytes is None:
        iv_bytes = bytearray(8)
    else:
        iv_bytes = bytearray(iv_bytes)

    out = bytearray(len(ciphertext))
    n = 0  # position within 8-byte block

    for i, cc in enumerate(ciphertext):
        if n == 0:
            # Read IV as 2 uint32
            if le_iv:
                v0 = struct.unpack_from("<I", iv_bytes, 0)[0]
                v1 = struct.unpack_from("<I", iv_bytes, 4)[0]
            else:
                v0 = struct.unpack_from(">I", iv_bytes, 0)[0]
                v1 = struct.unpack_from(">I", iv_bytes, 4)[0]

            e0, e1 = bf_encrypt_block([v0, v1], P, S)

            if le_iv:
                struct.pack_into("<I", iv_bytes, 0, e0)
                struct.pack_into("<I", iv_bytes, 4, e1)
            else:
                struct.pack_into(">I", iv_bytes, 0, e0)
                struct.pack_into(">I", iv_bytes, 4, e1)

        c_out = iv_bytes[n]
        iv_bytes[n] = cc          # feed ciphertext back
        out[i] = c_out ^ cc
        n = (n + 1) & 7

    return bytes(out)


def entropy(b):
    if not b: return 0.0
    freq = [0] * 256
    for x in b: freq[x] += 1
    n = len(b)
    e = 0.0
    for f in freq:
        if f:
            p = f / n
            e -= p * math.log2(p)
    return e


# ─── 3. Parse BF_KEY candidates from pb_crypto.log ──────────────────────────

print("\n[ 2/4 ] BF_KEY adayları ayrıştırılıyor (175 MB)…", flush=True)
t0 = time.time()

candidates = {}   # sig_tuple → (P_list, S_lists)

with open(CRYPTO_LOG, encoding="utf-8", errors="replace") as f:
    in_candidate = False
    cur_sig = None
    cur_p   = None
    cur_s   = []

    for line in f:
        stripped = line.strip()

        # Start of a new BF_KEY ADAYI block
        if "BF_KEY ADAYI" in stripped:
            # Save previous if complete
            if cur_sig and cur_p and len(cur_s) == 4:
                if cur_sig not in candidates:
                    candidates[cur_sig] = (cur_p, cur_s)
            in_candidate = True
            cur_sig = None
            cur_p   = None
            cur_s   = []
            continue

        if not in_candidate:
            continue

        # Signature line
        m = re.search(
            r'\[SIG\]\s+S0_0=([0-9a-f]+)\s+S1_0=([0-9a-f]+)\s+S2_0=([0-9a-f]+)\s+S3_0=([0-9a-f]+)',
            stripped)
        if m:
            cur_sig = tuple(int(x, 16) for x in m.groups())
            continue

        # P-array
        m = re.search(r'\[FULL_KEY\]\s+P:([0-9a-fA-F]+)', stripped)
        if m:
            h = m.group(1)
            if len(h) >= 144:
                data = bytes.fromhex(h[:144])
                # P-array: 18 × uint32 little-endian (x86 native)
                cur_p = list(struct.unpack("<18I", data))
            continue

        # S-box lines: "S[N] (1024B)  [1024 bytes]: hexdata"
        m = re.search(r'S\[\d\].*?\[1024 bytes\]:\s*([0-9a-fA-F]+)', stripped)
        if m:
            h = m.group(1)
            if len(h) >= 2048:
                data = bytes.fromhex(h[:2048])
                sbox = list(struct.unpack("<256I", data))
                cur_s.append(sbox)
            continue

# Save last candidate
if cur_sig and cur_p and len(cur_s) == 4:
    if cur_sig not in candidates:
        candidates[cur_sig] = (cur_p, cur_s)

print(f"    → {len(candidates)} benzersiz aday  ({time.time()-t0:.1f}s)")

# Filter to typical BF entropy range
def typical(sig):
    return all(0x10000000 <= x <= 0xefffffff for x in sig)

good = {sig: v for sig, v in candidates.items() if typical(sig)}
print(f"    → {len(good)} aday (tipik BF entropi aralığı)")

# ─── 4. Brute-force decrypt ──────────────────────────────────────────────────

print(f"\n[ 3/4 ] Şifre çözme deneniyor ({len(good)} aday × 2 IV modu)…", flush=True)
t0 = time.time()

cipher = target["raw"]
pkt_len = target["n"]

# Expected: after decrypt, bytes 0-1 (LE) = plausible packet length
# From challenge: c5 00 = 197, total = 202, overhead = 5
# So for target packet (N bytes): expected LE16 = N - 5
OVERHEAD = 5
expected_len = pkt_len - OVERHEAD
# Allow ±4 bytes tolerance
LEN_LO = max(0, expected_len - 4)
LEN_HI = expected_len + 4

# Also try: overhead = 3, 4, 6, 7
alt_overheads = [3, 4, 5, 6, 7]

# Candidate IVs to try:
# 1. All zeros
# 2. First 8 bytes of challenge (bytes 4-11)
# 3. Bytes 6-13 of challenge
iv_candidates = [
    ("zero",       bytes(8)),
]
if challenge and len(challenge["raw"]) >= 12:
    iv_candidates.append(("challenge[4:12]",  bytes(challenge["raw"][4:12])))
if challenge and len(challenge["raw"]) >= 14:
    iv_candidates.append(("challenge[6:14]",  bytes(challenge["raw"][6:14])))

hits = []
checked = 0

for sig, (P, S_list) in good.items():
    S = [S_list[0], S_list[1], S_list[2], S_list[3]]
    checked += 1

    for iv_label, iv_bytes in iv_candidates:
        for le_iv in (False, True):
            plain = bf_cfb64_decrypt(cipher, P, S, iv_bytes, le_iv=le_iv)

            # Check 1: first 2 bytes LE = plausible length
            first16 = struct.unpack_from("<H", plain, 0)[0]
            len_ok = any(abs(first16 - (pkt_len - ov)) <= 4 for ov in alt_overheads)

            # Check 2: entropy of full decrypted output
            e = entropy(plain)

            # Check 3: null byte ratio (structured data has some nulls)
            nulls = plain.count(0)
            null_ratio = nulls / len(plain)

            # Check 4: printable byte ratio in first 16 bytes
            printable = sum(0x20 <= b <= 0x7e for b in plain[:16])

            score = 0
            if len_ok:             score += 10
            if e < 6.0:            score += 5   # lower entropy = more structured
            if null_ratio > 0.05:  score += 3   # game packets have null bytes
            if printable >= 4:     score += 2   # some ASCII fields

            if score >= 10 or (e < 5.5 and null_ratio > 0.1):
                hits.append({
                    "sig": sig, "iv": iv_label, "le": le_iv,
                    "plain": plain, "first16": first16,
                    "entropy": e, "nulls": nulls, "score": score,
                })

    if checked % 200 == 0:
        elapsed = time.time() - t0
        rate = checked / elapsed if elapsed > 0 else 0
        remaining = (len(good) - checked) / rate if rate > 0 else 0
        print(f"    {checked}/{len(good)} ({rate:.0f}/s)  hits={len(hits)}  "
              f"ETA={remaining:.0f}s", flush=True)

elapsed = time.time() - t0
print(f"    Tamamlandı: {checked} aday / {elapsed:.1f}s  ({checked/elapsed:.0f}/s)")

# ─── 5. Report ───────────────────────────────────────────────────────────────

print(f"\n[ 4/4 ] Sonuçlar  ({len(hits)} hit):")
print("=" * 70)

if not hits:
    print("  ⚠️  Eşleşme bulunamadı.")
    print("     Olası nedenler:")
    print("     • IV sıfır değil (oyun challenge baytlarından türetiyor)")
    print("     • Şifreli paket henüz handshake sonrası değil")
    print("     • Oyunun Blowfish CFB'si farklı geri-besleme boyutu kullanıyor")

    # Show top-5 by score regardless
    all_scored = []
    for sig, (P, S_list) in list(good.items())[:500]:  # sample first 500
        S = [S_list[0], S_list[1], S_list[2], S_list[3]]
        plain = bf_cfb64_decrypt(cipher, P, S, bytes(8), le_iv=False)
        e = entropy(plain)
        f16 = struct.unpack_from("<H", plain, 0)[0]
        all_scored.append((e, f16, sig, plain))
    all_scored.sort()
    print(f"\n  En düşük entropili 5 aday (ilk 500'den):")
    for e, f16, sig, plain in all_scored[:5]:
        print(f"    entropy={e:.3f}  first2_LE={f16}  hex={plain[:16].hex()}")
        print(f"    S0_0={sig[0]:08x} S1_0={sig[1]:08x} S2_0={sig[2]:08x} S3_0={sig[3]:08x}")
else:
    # Sort by score desc, then entropy asc
    hits.sort(key=lambda h: (-h["score"], h["entropy"]))
    for h in hits[:20]:
        p = h["plain"]
        s0,s1,s2,s3 = h["sig"]
        le_str = "LE-IV" if h["le"] else "BE-IV"
        print(f"\n  ✓ SCORE={h['score']}  entropy={h['entropy']:.3f}  "
              f"first2_LE={h['first16']}  nulls={h['nulls']}/{len(p)}")
        print(f"    IV={h['iv']}  mode={le_str}")
        print(f"    S0_0={s0:08x} S1_0={s1:08x} S2_0={s2:08x} S3_0={s3:08x}")
        print(f"    Plaintext[0:32]: {p[:32].hex()}")
        print(f"    ASCII: {''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in p[:32])}")

    # Save best hit's key for further use
    best = hits[0]
    P_best, S_best = good[best["sig"]]
    print(f"\n  En iyi aday P-array (hex):")
    print(f"    {bytes(struct.pack('<18I', *P_best)).hex()}")

    # Try to decrypt ALL game server packets with the best key
    print(f"\n  Tüm paketler en iyi anahtar ile çözülüyor…")
    print(f"  IV={best['iv']}  mode={'LE' if best['le'] else 'BE'}")
    iv_b = dict(iv_candidates)[best["iv"]]
    S_b = [S_best[i] for i in range(4)]

    # Stateful CFB: maintain running IV across packets
    iv_state = bytearray(iv_b)
    num_state = [0]

    def decrypt_packet_stateful(cipher_bytes, P, S, iv_state, num_ref, le_iv):
        out = bytearray(len(cipher_bytes))
        n = num_ref[0]
        iv = iv_state  # mutable
        for i, cc in enumerate(cipher_bytes):
            if n == 0:
                if le_iv:
                    v0 = struct.unpack_from("<I", iv, 0)[0]
                    v1 = struct.unpack_from("<I", iv, 4)[0]
                else:
                    v0 = struct.unpack_from(">I", iv, 0)[0]
                    v1 = struct.unpack_from(">I", iv, 4)[0]
                e0, e1 = bf_encrypt_block([v0, v1], P, S)
                if le_iv:
                    struct.pack_into("<I", iv, 0, e0)
                    struct.pack_into("<I", iv, 4, e1)
                else:
                    struct.pack_into(">I", iv, 0, e0)
                    struct.pack_into(">I", iv, 4, e1)
            c_out = iv[n]
            iv[n] = cc
            out[i] = c_out ^ cc
            n = (n + 1) & 7
        num_ref[0] = n
        return bytes(out)

    for p in recv_pkts:
        plain = decrypt_packet_stateful(
            p["raw"], P_best, S_b, iv_state, num_state, best["le"])
        f16 = struct.unpack_from("<H", plain, 0)[0] if len(plain) >= 2 else 0
        f32 = struct.unpack_from("<HH", plain, 0) if len(plain) >= 4 else (0, 0)
        e = entropy(plain[:32])
        ascii16 = ''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in plain[:16])
        print(f"  [{p['ts']}] {p['n']:5d}B  len_field={f16}  opcode=0x{f32[1]:04x}  "
              f"e={e:.2f}  {plain[:16].hex()}  |{ascii16}|")
