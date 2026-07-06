#!/usr/bin/env python3
"""
pb_crypto.log Parser — Blowfish Paket Analizi
===============================================
Kullanım: python log_parser.py pb_crypto.log
"""

import sys
import re
import struct
from pathlib import Path


def parse_hex(line: str) -> bytes | None:
    """'xx xx xx ...' veya 'xxxxxxxxxxx...' formatından bytes döndürür"""
    # "  key [...bytes]: aabbccdd..." formatı
    m = re.search(r'\[.*?\]:\s*([0-9a-fA-F]+)', line)
    if m:
        h = m.group(1)
        try:
            return bytes.fromhex(h)
        except ValueError:
            return None
    return None


def blowfish_decrypt_session(log_path: str):
    """Log dosyasını parse et, oturum bilgilerini çıkar"""
    sessions = []
    current = {}
    packets = []

    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Yeni bağlantı
        if '======' in stripped and 'proxy yüklendi' in lines[i+1] if i+1 < len(lines) else '':
            if current:
                sessions.append(current)
            current = {'session_key': None, 'rsa_key_size': None, 'packets': []}

        # RSA oturum anahtarı (EN KRİTİK)
        if 'SESSION KEY' in stripped:
            key_line = lines[i] if 'SESSION KEY' in lines[i] else ''
            # Bir sonraki satırda hex data olabilir
            for j in range(i, min(i+3, len(lines))):
                kb = parse_hex(lines[j])
                if kb:
                    current['session_key'] = kb
                    print(f"\n{'='*60}")
                    print(f"🔑 BLOWFISH SESSION KEY BULUNDU!")
                    print(f"{'='*60}")
                    print(f"  HEX : {kb.hex()}")
                    print(f"  Boyut: {len(kb)} byte ({len(kb)*8} bit)")
                    if all(0x20 <= b <= 0x7e for b in kb):
                        print(f"  ASCII: {kb.decode('latin-1')}")
                    print(f"{'='*60}\n")
                    break

        # RSA public key boyutu
        if 'RSA_size' in stripped:
            m = re.search(r'RSA_size=(\d+)', stripped)
            if m:
                current['rsa_key_size'] = int(m.group(1))
                print(f"📡 Sunucu RSA key boyutu: {m.group(1)} bit")

        # BF_cfb64_encrypt çağrısı
        if 'BF_cfb64_encrypt' in stripped:
            enc = 'ENCRYPT' in stripped
            pkt = {'type': 'encrypt' if enc else 'decrypt', 'data': None, 'iv': None, 'length': 0}

            # Length
            m = re.search(r'len=(\d+)', stripped)
            if m:
                pkt['length'] = int(m.group(1))

            # IV ve plaintext
            for j in range(i+1, min(i+6, len(lines))):
                l = lines[j]
                if 'ivec' in l:
                    pkt['iv'] = parse_hex(l)
                elif 'in  (plaintext)' in l:
                    pkt['data'] = parse_hex(l)
                elif 'out (decrypted)' in l:
                    pkt['decoded'] = parse_hex(l)
                elif 'BF_cfb64' in l:
                    break

            packets.append(pkt)
            current.setdefault('packets', []).append(pkt)

    # Son oturumu ekle
    if current:
        sessions.append(current)

    # Özet rapor
    print(f"\n{'='*60}")
    print(f"📊 ÖZET")
    print(f"{'='*60}")
    print(f"Toplam oturum: {len(sessions)}")
    print(f"Toplam paket: {len(packets)}")

    enc_pkts = [p for p in packets if p['type'] == 'encrypt']
    dec_pkts = [p for p in packets if p['type'] == 'decrypt']
    print(f"  Gönderilen (encrypt): {len(enc_pkts)}")
    print(f"  Alınan    (decrypt) : {len(dec_pkts)}")

    if packets:
        sizes = [p['length'] for p in packets]
        print(f"  Paket boyutu: min={min(sizes)}, max={max(sizes)}, ort={sum(sizes)//len(sizes)}")

    # Oturum anahtarlarını listele
    keys_found = [s['session_key'] for s in sessions if s.get('session_key')]
    if keys_found:
        print(f"\n🔑 Bulunan session key'ler ({len(keys_found)}):")
        for i, k in enumerate(keys_found):
            print(f"  [{i+1}] {k.hex()} ({len(k)} byte)")
    else:
        print("\n⚠️  Session key bulunamadı. Oyun henüz login olmadı mı?")

    # Plaintext paketlerin ilk 16 byte'ını göster
    print(f"\n📦 İlk 10 plaintext paket başlığı:")
    shown = 0
    for p in packets:
        d = p.get('data') or p.get('decoded')
        if d and len(d) >= 2:
            print(f"  [{p['type']:7s}] len={p['length']:4d}  header={d[:16].hex()}  "
                  f"{'  ascii=' + ''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in d[:16]) if d else ''}")
            shown += 1
            if shown >= 10:
                break

    print(f"\nLog dosyası tam analiz edildi: {log_path}")
    print("Tüm paket verisi için ham logu inceleyin: pb_crypto.log")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Kullanım: python log_parser.py pb_crypto.log")
        sys.exit(1)

    log_file = sys.argv[1]
    if not Path(log_file).exists():
        print(f"Hata: {log_file} bulunamadı")
        sys.exit(1)

    blowfish_decrypt_session(log_file)
