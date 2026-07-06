#!/usr/bin/env python3
"""
pb_crypto.log Parser — Blowfish Key & Packet Analizi
======================================================
Kullanım:
  python log_parser.py pb_crypto.log [pb_net.log]

  pb_net.log verilirse, her TCP satırındaki bf_calls=N değerinden
  export fonksiyonlarının gerçekten çağrılıp çağrılmadığı tespit edilir.

Desteklenen log formatları:
  - BF_set_key EXPORT stub  (export proxy intercept)
  - BF_set_key INLINE hook  (libcrypto-1_1_orig.dll inline detour)
  - BF_cfb64_encrypt EXPORT (her paket)
  - RSA_public_encrypt      (session key RSA öncesi plaintext)
  - BF_encrypt / BF_decrypt (block-mode ECB intercept)
"""

import sys
import re
from pathlib import Path


# ─── helpers ──────────────────────────────────────────────────────────────────

def parse_hex_field(line: str) -> bytes | None:
    """'  label [N bytes]: aabbccdd...' veya benzer formatı ayrıştır."""
    m = re.search(r'\[.*?\]:\s*([0-9a-fA-F]{2,})', line)
    if m:
        h = m.group(1)
        try:
            return bytes.fromhex(h)
        except ValueError:
            pass
    return None


def ascii_safe(b: bytes, limit: int = 32) -> str:
    return ''.join(chr(x) if 0x20 <= x <= 0x7e else '.' for x in b[:limit])


def print_key(label: str, key: bytes) -> None:
    print(f"\n{'='*60}")
    print(f"🔑  {label}")
    print(f"{'='*60}")
    print(f"  HEX  : {key.hex()}")
    print(f"  Boyut: {len(key)} byte  ({len(key)*8} bit)")
    if all(0x20 <= b <= 0x7e for b in key):
        print(f"  ASCII: {key.decode('latin-1')}")
    print(f"{'='*60}")


# ─── parser ───────────────────────────────────────────────────────────────────

def parse(log_path: str) -> None:
    text = Path(log_path).read_text(encoding='utf-8', errors='replace')
    lines = text.splitlines()

    # Tracked state
    keys_found: list[tuple[str, bytes]] = []   # (source, key_bytes)
    rsa_events:  list[dict] = []
    bf_cfb_calls: list[dict] = []
    bf_block_calls: list[dict] = []
    pid_count = 0
    bf_export_max = 0

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # ── PID banner ──────────────────────────────────────────────────────
        if 'libcrypto proxy yuklendi' in stripped or 'proxy yuklendi' in stripped:
            pid_count += 1

        # ── BF_set_key (both EXPORT and INLINE) ─────────────────────────────
        if 'BF_set_key' in stripped and 'SESSION KEY' in stripped:
            source = 'INLINE' if 'INLINE' in stripped else 'EXPORT'
            # Key data is on the next line(s)
            for j in range(i + 1, min(i + 6, len(lines))):
                kb = parse_hex_field(lines[j])
                if kb and len(kb) >= 4:
                    keys_found.append((f'BF_set_key {source}', kb))
                    print_key(f'BLOWFISH SESSION KEY  [{source}]', kb)
                    break
            i += 1
            continue

        # ── RSA_public_encrypt — session key plaintext ───────────────────────
        if 'RSA_public_encrypt' in stripped and 'flen=' in stripped:
            ev: dict = {'flen': 0, 'plaintext': None, 'ciphertext': None}
            m = re.search(r'flen=(\d+)', stripped)
            if m:
                ev['flen'] = int(m.group(1))
            for j in range(i + 1, min(i + 8, len(lines))):
                l2 = lines[j]
                if 'BLOWFISH SESSION KEY' in l2 or 'PLAINTEXT KEY' in l2 or 'plaintext' in l2.lower():
                    kb = parse_hex_field(l2)
                    if not kb:
                        # data might be on the following line
                        if j + 1 < len(lines):
                            kb = parse_hex_field(lines[j + 1])
                    if kb:
                        ev['plaintext'] = kb
                        keys_found.append(('RSA plaintext', kb))
                        print_key('BLOWFISH KEY via RSA_public_encrypt', kb)
                elif 'RSA encrypted' in l2 or 'ciphertext' in l2.lower():
                    ev['ciphertext'] = parse_hex_field(l2)
                elif 'RSA_public_encrypt' in l2 and j != i:
                    break
            rsa_events.append(ev)
            i += 1
            continue

        # ── BF_cfb64_encrypt EXPORT ──────────────────────────────────────────
        if 'BF_cfb64_encrypt EXPORT' in stripped or (
                'BF_cfb64_encrypt' in stripped and ('ENCRYPT' in stripped or 'DECRYPT' in stripped)):
            pkt: dict = {
                'dir': 'ENCRYPT' if 'ENCRYPT' in stripped else 'DECRYPT',
                'length': 0, 'call_n': None,
                'ivec': None, 'data_in': None, 'data_out': None,
                'key_parr': None,
            }
            m = re.search(r'len=(\d+)', stripped)
            if m:
                pkt['length'] = int(m.group(1))
            m = re.search(r'call#(\d+)', stripped)
            if m:
                n = int(m.group(1))
                pkt['call_n'] = n
                if n > bf_export_max:
                    bf_export_max = n
            for j in range(i + 1, min(i + 8, len(lines))):
                l2 = lines[j]
                if 'ivec' in l2:
                    pkt['ivec'] = parse_hex_field(l2)
                elif 'in' in l2 and 'byte' in l2:
                    pkt['data_in'] = parse_hex_field(l2)
                elif 'out' in l2 and 'byte' in l2:
                    pkt['data_out'] = parse_hex_field(l2)
                elif 'key P-array' in l2:
                    pkt['key_parr'] = parse_hex_field(l2)
                elif 'BF_cfb64' in l2 and j != i:
                    break
            bf_cfb_calls.append(pkt)
            i += 1
            continue

        # ── BF_encrypt / BF_decrypt EXPORT ───────────────────────────────────
        if ('BF_encrypt EXPORT' in stripped or 'BF_decrypt EXPORT' in stripped):
            bpkt: dict = {
                'mode': 'encrypt' if 'encrypt' in stripped.lower() else 'decrypt',
                'call_n': None, 'in_block': None, 'out_block': None, 'key_parr': None,
            }
            m = re.search(r'call#(\d+)', stripped)
            if m:
                bpkt['call_n'] = int(m.group(1))
            for j in range(i + 1, min(i + 6, len(lines))):
                l2 = lines[j]
                if 'in block' in l2:
                    bpkt['in_block'] = parse_hex_field(l2)
                elif 'out block' in l2:
                    bpkt['out_block'] = parse_hex_field(l2)
                elif 'key P-array' in l2:
                    bpkt['key_parr'] = parse_hex_field(l2)
                elif ('BF_encrypt' in l2 or 'BF_decrypt' in l2) and j != i:
                    break
            bf_block_calls.append(bpkt)
            i += 1
            continue

        i += 1

    # ─── SUMMARY ──────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("📊  ÖZET")
    print(f"{'='*60}")
    print(f"Proxy yükleme sayısı : {pid_count}")

    if keys_found:
        print(f"\n🔑  Bulunan Blowfish key'ler ({len(keys_found)}):")
        for src, kb in keys_found:
            print(f"  [{src}]  {kb.hex()}  ({len(kb)} byte / {len(kb)*8} bit)")
    else:
        print("\n⚠️  Blowfish session key bulunamadı.")
        print("   Olası nedenler:")
        print("   1. Oyun henüz login aşamasına geçmedi")
        print("   2. VMProtect BF_set_key çağrısını sanal makineye aldı")
        print("      → pb_key_fallback.log dosyasına bakın (inline hook farklı yol dener)")
        print("   3. Oyun OpenSSL kullanmıyor (statik Blowfish)")
        print("   Çözüm: bf_calls=0 net logda → export hiç çağrılmamış demek")
        print("           bf_calls>0 ama key yok → key başka yolla kurulmuş")

    if rsa_events:
        print(f"\n🔐  RSA_public_encrypt çağrıları: {len(rsa_events)}")
        for ev in rsa_events:
            print(f"  flen={ev['flen']} byte"
                  + (f"  key={ev['plaintext'].hex()}" if ev.get('plaintext') else '  (plaintext yok)'))
    else:
        print("\n   RSA_public_encrypt: çağrılmadı")

    enc_calls = [p for p in bf_cfb_calls if p['dir'] == 'ENCRYPT']
    dec_calls = [p for p in bf_cfb_calls if p['dir'] == 'DECRYPT']
    print(f"\n📦  BF_cfb64_encrypt EXPORT çağrıları: {len(bf_cfb_calls)}")
    print(f"    Gönderilen (ENCRYPT): {len(enc_calls)}")
    print(f"    Alınan    (DECRYPT) : {len(dec_calls)}")
    if bf_cfb_calls:
        sizes = [p['length'] for p in bf_cfb_calls]
        print(f"    Paket boyutu: min={min(sizes)}, max={max(sizes)}, ort={sum(sizes)//len(sizes)}")
        print(f"    En yüksek call#: {bf_export_max}")

    if bf_block_calls:
        print(f"\n🧱  BF_encrypt/BF_decrypt EXPORT (block-level): {len(bf_block_calls)}")

    # Show first decrypted packets
    dec_with_data = [p for p in bf_cfb_calls if p.get('data_out') or p.get('data_in')]
    if dec_with_data:
        print(f"\n📦  İlk 10 paket başlığı:")
        for p in dec_with_data[:10]:
            d = p.get('data_out') or p.get('data_in')
            hdr = d[:16] if d else b''
            print(f"  [{p['dir']:7s}] len={p['length']:4d}  "
                  f"header={hdr.hex():<32}  ascii={ascii_safe(hdr)}")

    if bf_export_max == 0 and len(bf_cfb_calls) == 0:
        print("\n💡  TANI: bf_calls=0 → export fonksiyonları hiç çağrılmadı.")
        print("   VMProtect oyunun import tablosunu sanal makineye aldı.")
        print("   Çözüm önerileri:")
        print("   a) pb_key_fallback.log var mı? → inline detour çalıştı mı?")
        print("   b) Oyunun belleğinde Blowfish S-box değerleri ara (0x243f6a88)")
        print("   c) Ağ paketlerinde bilinen başlık varsa known-plaintext saldırısı")

    print(f"\nLog dosyası: {log_path}")


def check_net_log_bf_calls(net_log_path: str) -> int:
    """pb_net.log içindeki bf_calls=N değerlerinin maximumunu döndürür.
    
    Yeni DLL her TCP satırına bf_calls=N ekler.  Bu, export
    fonksiyonlarının gerçekten çağrılıp çağrılmadığını gösterir.
    """
    try:
        text = Path(net_log_path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return -1
    max_calls = 0
    for m in re.finditer(r'bf_calls=(\d+)', text):
        v = int(m.group(1))
        if v > max_calls:
            max_calls = v
    return max_calls


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Kullanım: python log_parser.py pb_crypto.log [pb_net.log]")
        sys.exit(1)
    log_file = sys.argv[1]
    if not Path(log_file).exists():
        print(f"Hata: {log_file} bulunamadı")
        sys.exit(1)

    # Optional net log for bf_calls diagnostic
    net_log_file = sys.argv[2] if len(sys.argv) >= 3 else None
    # Auto-detect: look for pb_net.log next to the crypto log
    if net_log_file is None:
        candidate = Path(log_file).parent / 'pb_net.log'
        if candidate.exists():
            net_log_file = str(candidate)

    if net_log_file:
        max_bf = check_net_log_bf_calls(net_log_file)
        if max_bf >= 0:
            print(f"\n📡  pb_net.log'dan bf_calls tepe değeri: {max_bf}")
            if max_bf == 0:
                print("   → Export fonksiyonları HİÇ çağrılmadı (VMProtect IAT bypass)")
            else:
                print(f"   → Export fonksiyonları en az {max_bf} kez çağrıldı ✓")

    parse(log_file)
