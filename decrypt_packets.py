"""
decrypt_packets.py – PointBlank session-key packet decryptor
=============================================================
Confirmed key:   BF_KEY ADAYI #48  (SIG c87bf7d2 64215ab6 4108fddb 5e2ee03f)
IV derivation:   challenge[3:11]  (bytes 3-10 of the 202-byte server challenge)
Endian mode:     LE  (game stores BF IV as union { BF_LONG ul[2]; uint8 uc[8]; } — LE uint32)
Packet format:   [1B payload_len] [1B proto=0x0D] [1B opcode] [payload_len bytes]
Overhead:        3 header bytes;  payload_len = total_pkt_bytes - 3
Evidence:        keystream[0]=0x00, keystream[1]=0x8D from BF_enc(IV)
                 ⟹ cipher[0] == pkt_len-3 and cipher[1] == 0x80 for ALL small packets
                 (8/8 small packets across both send and recv match)

Usage:
  python3 decrypt_packets.py                       # LE mode, stateless
  python3 decrypt_packets.py --endian be           # compare with BE mode
  python3 decrypt_packets.py --endian both         # show both side by side
  python3 decrypt_packets.py --stateful            # chain CFB state across packets
  python3 decrypt_packets.py --dump-all            # hex-dump every packet
  python3 decrypt_packets.py --crypto path/to/pb_crypto.log --net path/to/pb_net.log
"""
import argparse, re, struct, math, sys

# ─── CLI ──────────────────────────────────────────────────────────────────────
ap = argparse.ArgumentParser()
ap.add_argument("--crypto",   default="log_data/pb_crypto.log")
ap.add_argument("--net",      default="log_data/pb_net.log")
ap.add_argument("--endian",   choices=["le", "be", "both"], default="le",
                help="le = game custom LE-uint32 IV (confirmed), "
                     "be = standard OpenSSL BE-uint32 IV")
ap.add_argument("--stateful", action="store_true",
                help="chain CFB state across packets (default: reset per packet)")
ap.add_argument("--dump-all", action="store_true",
                help="hex-dump every packet including large ones")
ap.add_argument("--sig", default="c87bf7d2 64215ab6 4108fddb 5e2ee03f",
                help="override target SIG (4 space-separated hex values)")
args = ap.parse_args()

TARGET_SIG = tuple(int(x, 16) for x in args.sig.split())

# ─── Load confirmed key ────────────────────────────────────────────────────────
# Log block structure per "BF_KEY ADAYI #N":
#   P-array [72 bytes]: <144 hex>   → 18 × LE uint32
#   S[0..3] [1024 bytes]: <2048 hex> → 256 × LE uint32 each
#   [SIG]   S0_0=XXXXXXXX S1_0=… S2_0=… S3_0=…
print(f"Loading key  SIG={' '.join(f'{x:08x}' for x in TARGET_SIG)} …")

P_key: list[int] = []
S_key: list[list[int]] = []
_cur_p: list[int] | None = None
_cur_s: list[list[int]] = []

with open(args.crypto, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        s = line.strip()
        if "BF_KEY ADAYI" in s:
            _cur_p = None
            _cur_s = []
            continue
        m = re.search(r'\[72 bytes\]:\s*([0-9a-fA-F]{144})', s)
        if m:
            _cur_p = list(struct.unpack("<18I", bytes.fromhex(m.group(1))))
            continue
        m = re.search(r'S\[\d\] \(1024B\).*?\[1024 bytes\]:\s*([0-9a-fA-F]{2048})', s)
        if m:
            _cur_s.append(list(struct.unpack("<256I", bytes.fromhex(m.group(1)))))
            continue
        m = re.search(r'\[SIG\]\s+S0_0=([0-9a-f]+)\s+S1_0=([0-9a-f]+)'
                      r'\s+S2_0=([0-9a-f]+)\s+S3_0=([0-9a-f]+)', s)
        if m:
            if (tuple(int(x, 16) for x in m.groups()) == TARGET_SIG
                    and _cur_p and len(_cur_s) == 4):
                P_key = _cur_p
                S_key = _cur_s
                break

if not P_key:
    sys.exit(f"ERROR: key {args.sig} not found in {args.crypto}")

print(f"  P[0]={P_key[0]:08x}  "
      f"S[0][0]={S_key[0][0]:08x}  S[1][0]={S_key[1][0]:08x}  "
      f"S[2][0]={S_key[2][0]:08x}  S[3][0]={S_key[3][0]:08x}")


# ─── Blowfish primitives ───────────────────────────────────────────────────────
def bf_enc(L: int, R: int) -> tuple[int, int]:
    """PointBlank variant of Blowfish encrypt.

    NOTE — non-standard round structure (confirmed by cipher analysis):
    Standard Blowfish swaps L and R after every round; this game's implementation
    does NOT swap per round — it accumulates all F(L_i) into R, then swaps once
    at the end.  Switching to the standard swap produces keystream[0]=0x5c for
    IV=challenge[3:11], which is inconsistent with the observed cipher bytes
    (all 22 small packets satisfy cipher[0]=pkt_len-3 ⟺ ks[0]=0x00 only with
    this no-per-round-swap variant).  Keep this form to match the game.

    F function (same as standard): F(x) = ((S0[a]+S1[b]) ^ S2[c]) + S3[d]
    """
    for i in range(16):
        L ^= P_key[i]
        a = (L >> 24) & 0xFF
        b = (L >> 16) & 0xFF
        c = (L >>  8) & 0xFF
        d =  L        & 0xFF
        t = ((S_key[0][a] + S_key[1][b]) & 0xFFFFFFFF) ^ S_key[2][c]
        t = (t + S_key[3][d]) & 0xFFFFFFFF
        R ^= t
        # No per-round swap — intentional; see docstring.
    L, R = R, L    # single swap after all 16 rounds
    return (L ^ P_key[16]) & 0xFFFFFFFF, (R ^ P_key[17]) & 0xFFFFFFFF


def cfb64_dec(
    cipher:   bytes,
    iv_bytes: bytes,
    le_iv:    bool,
    n_in:     int = 0,
) -> tuple[bytes, bytes, int]:
    """BF-CFB64 decrypt.  Returns (plaintext, final_iv_bytes, final_n).
    le_iv=True  → game custom: reads IV uint32s in little-endian (confirmed)
    le_iv=False → OpenSSL default: reads IV uint32s in big-endian
    Pass final_iv/final_n back in for stateful (chained) decryption.
    """
    iv = bytearray(iv_bytes)
    out = bytearray(len(cipher))
    n = n_in
    for i, cc in enumerate(cipher):
        if n == 0:
            if le_iv:
                v0 = struct.unpack_from("<I", iv, 0)[0]
                v1 = struct.unpack_from("<I", iv, 4)[0]
            else:
                v0 = struct.unpack_from(">I", iv, 0)[0]
                v1 = struct.unpack_from(">I", iv, 4)[0]
            e0, e1 = bf_enc(v0, v1)
            if le_iv:
                struct.pack_into("<I", iv, 0, e0)
                struct.pack_into("<I", iv, 4, e1)
            else:
                struct.pack_into(">I", iv, 0, e0)
                struct.pack_into(">I", iv, 4, e1)
        out[i] = iv[n] ^ cc
        iv[n] = cc
        n = (n + 1) & 7
    return bytes(out), bytes(iv), n


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum(p / n * math.log2(p / n) for p in freq if p)


def hex_dump(data: bytes, indent: str = "    ", width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{i:04x}: {hex_part:<{width*3}}  {asc_part}")
    return "\n".join(lines)


def parse_frames(blob: bytes) -> list[dict]:
    """Split a decrypted TCP blob into [1B len][1B 0x0D][1B opcode][payload] frames.
    Falls back to 2-byte LE length when the 1B length + 3 overhead exceeds blob.
    """
    frames: list[dict] = []
    pos = 0
    while pos < len(blob):
        if len(blob) - pos < 3:
            frames.append({"error": "truncated-header", "pos": pos, "data": blob[pos:]})
            break
        len1 = blob[pos]
        proto = blob[pos + 1]
        opcode = blob[pos + 2]
        end1 = pos + 3 + len1
        if end1 <= len(blob):
            frames.append({
                "pos": pos, "len_field": len1, "len_bytes": 1,
                "proto": proto, "opcode": opcode,
                "payload": blob[pos + 3 : end1],
            })
            pos = end1
        else:
            # Try 2-byte LE length (large packets)
            if len(blob) - pos >= 4:
                len2 = struct.unpack_from("<H", blob, pos)[0]
                opcode2 = blob[pos + 2]
                end2 = pos + 3 + len2
                if end2 <= len(blob) and len2 > 255:
                    frames.append({
                        "pos": pos, "len_field": len2, "len_bytes": 2,
                        "proto": proto, "opcode": opcode2,
                        "payload": blob[pos + 3 : end2],
                    })
                    pos = end2
                    continue
            frames.append({"error": "truncated-frame", "pos": pos, "data": blob[pos:]})
            break
    return frames


# ─── Load all packets (list — no dedup, preserves duplicates at same timestamp) ─
print(f"\nLoading packets from {args.net} …")
all_raw: list[tuple[str, str, int, bytes]] = []  # (ts, dir, size, data)

with open(args.net, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        m = re.search(
            r'\[(\d{2}:\d{2}:\d{2}\.\d{3})\]\s+TCP (RECV|SEND)\s+[←→]\s+'
            r'31\.169\.73\.205:39190\b.*?\[(\d+) bytes\]:\s*([0-9a-fA-F]+)',
            line)
        if m:
            ts        = m.group(1)
            direction = "recv" if m.group(2) == "RECV" else "send"
            size      = int(m.group(3))
            data      = bytes.fromhex(m.group(4))
            all_raw.append((ts, direction, size, data))

recv_all = [(ts, d, n, r) for ts, d, n, r in all_raw if d == "recv"]
send_all = [(ts, d, n, r) for ts, d, n, r in all_raw if d == "send"]
print(f"  {len(recv_all)} recv  {len(send_all)} send  ({len(all_raw)} total)")
print(f"  recv sizes: {[n for _, _, n, _ in recv_all]}")
print(f"  send sizes: {[n for _, _, n, _ in send_all]}")

# Challenge = first recv; session IV from bytes [3:11]
challenge    = recv_all[0][3]          # 202B plaintext
session_iv   = challenge[3:11]         # confirmed IV source

# Encrypted traffic begins after these plaintext/RSA-layer packets:
#   recv[0] = 202B challenge (plaintext, skip)
#   send[0] = 291B RSA login (pre-session, skip)
enc_recv = recv_all[1:]   # skip challenge
enc_send = send_all[1:]   # skip RSA login

print(f"\n  Session IV = challenge[3:11] = {session_iv.hex()}")
v0 = struct.unpack_from("<I", session_iv, 0)[0]
v1 = struct.unpack_from("<I", session_iv, 4)[0]
print(f"    LE uint32: {v0:08x} {v1:08x}")

# Show keystream[0:8] so the reader can verify cipher[0] = plaintext[0]
_iv_tmp = bytearray(session_iv)
_e0, _e1 = bf_enc(v0, v1)
struct.pack_into("<I", _iv_tmp, 0, _e0)
struct.pack_into("<I", _iv_tmp, 4, _e1)
print(f"    keystream[0:8] (LE) = {bytes(_iv_tmp).hex()}"
      f"   ks[0]={_iv_tmp[0]:02x}  ks[1]={_iv_tmp[1]:02x}")
print(f"    → cipher[0] = pkt_len-3 (unaffected: ks[0]=0x00)")
print(f"    → cipher[1] = 0x80 → dec[1] = 0x80 ^ 0x{_iv_tmp[1]:02x} = 0x{0x80 ^ _iv_tmp[1]:02x} = proto byte")

# Verify length+proto pattern against raw cipher bytes.
# A packet is a "small" (1-byte length) packet when pkt_len <= 258 (len_field ≤ 255).
# For those: cipher[0] should equal pkt_len-3 exactly.
# For large packets the 1B invariant does NOT hold — shown as "?" to avoid confusion.
print("\n  Cipher-byte verification (no decryption needed):")
print(f"  {'pkt':>5}  {'dir':4}  {'size':>5}  {'c[0]':>6}  {'c[1]':>6}  "
      f"{'len-3':>5}  {'len?':>5}  {'proto?':>7}")
for ts, d, n, raw in enc_recv + enc_send:
    c0, c1 = raw[0], raw[1]
    expected = n - 3
    is_small = expected <= 255           # 1-byte length field is possible
    ok_len   = "✓" if (is_small and c0 == expected) else ("?" if not is_small else " ")
    ok_proto = "✓" if c1 == 0x80 else " "
    print(f"  {ts}  {d:4}  {n:5d}B  0x{c0:02x}={c0:3d}  0x{c1:02x}  "
          f"{expected:>7}  {ok_len:>5}  {ok_proto:>7}")

# ─── Decryption modes ─────────────────────────────────────────────────────────
modes: list[tuple[str, bool]] = []
if args.endian in ("le", "both"):
    modes.append(("LE (game custom, CONFIRMED)", True))
if args.endian in ("be", "both"):
    modes.append(("BE (OpenSSL standard)",      False))

# Process recv and send merged in timestamp order
ordered_enc = sorted(enc_recv + enc_send, key=lambda x: x[0])

for mode_name, le_iv in modes:
    print(f"\n{'='*72}")
    print(f"  MODE: {mode_name}   stateful={args.stateful}")
    print(f"{'='*72}")

    # In stateful mode the server→client and client→server CFB streams are
    # independent (each direction starts from session_iv and advances separately).
    iv_recv, n_recv = session_iv, 0
    iv_send, n_send = session_iv, 0

    for ts, direction, plen, raw in ordered_enc:
        arrow = "←" if direction == "recv" else "→"

        if args.stateful:
            if direction == "recv":
                plain, iv_recv, n_recv = cfb64_dec(raw, iv_recv, le_iv, n_recv)
            else:
                plain, iv_send, n_send = cfb64_dec(raw, iv_send, le_iv, n_send)
        else:
            plain, _, _ = cfb64_dec(raw, session_iv, le_iv)

        d0   = plain[0]
        d1   = plain[1]
        d2   = plain[2]
        expected_len = plen - 3
        e    = entropy(plain)

        # Length check
        len_ok_1b = (d0 == expected_len % 256 and expected_len < 256)
        # 2-byte LE check for large packets
        len_ok_2b = False
        if not len_ok_1b and plen > 256:
            f2 = struct.unpack_from("<H", plain, 0)[0]
            len_ok_2b = (f2 == expected_len)
        status = "✓" if len_ok_1b else ("✓₂" if len_ok_2b else "?")

        proto_ok = "✓" if d1 == 0x0D else " "

        print(f"\n  {ts} {arrow} {direction.upper():4}  {plen:5d}B  "
              f"len={d0}({status})  proto=0x{d1:02x}({proto_ok})  "
              f"op=0x{d2:02x}({d2:3d})  e={e:.3f}")

        # Always hex-dump first 48 bytes of decrypted data
        should_dump = args.dump_all or len_ok_1b or len_ok_2b or e < 5.5
        if should_dump:
            frames = parse_frames(plain)
            for fr in frames:
                if "error" in fr:
                    preview = fr["data"][:24].hex()
                    print(f"    [frame@{fr['pos']:04x}] {fr['error']}  data={preview}…")
                    break  # stop after first error in a large/partial blob
                else:
                    lb = fr["len_bytes"]
                    ln = fr["len_field"]
                    op = fr["opcode"]
                    pr = fr["proto"]
                    payload = fr["payload"]
                    preview = payload[:24].hex()
                    if len(payload) > 24:
                        preview += "…"
                    print(f"    [frame@{fr['pos']:04x}] "
                          f"len={ln}({lb}B) proto=0x{pr:02x} op=0x{op:02x}  "
                          f"payload({len(payload)}B)={preview}")

            print(hex_dump(plain[:min(64, len(plain))]))


# ─── Summary ──────────────────────────────────────────────────────────────────
print(f"\n{'='*72}")
print("KEY SUMMARY")
print(f"  SIG:          {' '.join(f'{x:08x}' for x in TARGET_SIG)}")
print(f"  IV source:    challenge[3:11] = {session_iv.hex()}")
print(f"  Endian mode:  LE  (game union{{BF_LONG ul[2]; uint8 uc[8]}})")
print(f"  Packet fmt:   [1B len] [1B proto=0x0D] [1B opcode] [len bytes]")
print(f"  Overhead:     3 bytes  (len = total_packet_bytes − 3, wraps mod 256 for pkt<259B)")
print(f"  Scope:        recv[1..] and send[1..]  (skip challenge & RSA login)")
print(f"  Large pkts:   790B/507B/8912B/5979B use different len encoding or")
print(f"                contain multiple concatenated frames — needs further parsing")
