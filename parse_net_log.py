#!/usr/bin/env python3
"""
pb_net.log Parser — PointBlank Ağ Trafiği Analizi
===================================================
Kullanım: python parse_net_log.py pb_net.log
"""
import sys, re
from pathlib import Path
from collections import defaultdict

def parse_hex_line(line):
    """'  label [N bytes]: aabb...' formatını ayrıştır"""
    m = re.search(r'\[(\d+) bytes\]:\s*([0-9a-fA-F]+)', line)
    if m:
        n = int(m.group(1))
        try:
            raw = bytes.fromhex(m.group(2))
            return n, raw
        except ValueError:
            return n, None
    return 0, None

def ascii_safe(data, limit=32):
    return ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in data[:limit])

def analyze(log_path):
    text = Path(log_path).read_text(encoding='utf-8', errors='replace')
    lines = text.splitlines()

    connections = []
    packets = []
    servers = defaultdict(lambda: {'send': 0, 'recv': 0, 'bytes_s': 0, 'bytes_r': 0})

    time_re = re.compile(r'^\[(\d{2}:\d{2}:\d{2}\.\d{3})\]')

    i = 0
    while i < len(lines):
        line = lines[i]
        tm = time_re.match(line)
        t = tm.group(1) if tm else '??:??:??.???'

        # Bağlantı
        if 'connect' in line.lower() and '→' in line:
            m = re.search(r'→\s+([\d\.]+:\d+)', line)
            if m:
                addr = m.group(1)
                connections.append((t, addr))
                print(f"[{t}] BAĞLANTI → {addr}")

        elif 'WSAConnByNameW' in line or 'WSAConnectByNameW' in line:
            m = re.search(r'→\s+(\S+:\S+)', line)
            if m:
                addr = m.group(1)
                connections.append((t, addr))
                print(f"[{t}] BAĞLANTI (DNS) → {addr}")

        # Paket
        elif any(tag in line for tag in ('TCP SEND', 'TCP RECV', 'UDP SEND',
                                          'UDP RECV', 'WSASend', 'WSARecv',
                                          'WSASndTo', 'WSARcvFr')):
            # Yön ve adres
            send = any(x in line for x in ('SEND', 'WSASend', 'WSASndTo'))
            recv = not send

            addr_m = re.search(r'[→←]\s+([\d\.]+:\d+|\S+:\S+)', line)
            addr = addr_m.group(1) if addr_m else '?'

            proto = 'TCP' if 'TCP' in line else 'UDP'
            if 'WSA' in line and 'To' not in line and 'Fr' not in line:
                proto = 'TCP'

            # Veri hex
            n, raw = parse_hex_line(line)
            if n == 0 and i + 1 < len(lines):
                n, raw = parse_hex_line(lines[i + 1])

            direction = '→' if send else '←'
            srv = addr
            if send:
                servers[srv]['send'] += 1
                servers[srv]['bytes_s'] += n
            else:
                servers[srv]['recv'] += 1
                servers[srv]['bytes_r'] += n

            packets.append({'t': t, 'proto': proto, 'dir': direction,
                            'addr': addr, 'n': n, 'raw': raw})

            if raw:
                preview = raw[:16].hex()
                asc = ascii_safe(raw)
                print(f"[{t}] {proto} {direction} {addr:22s} {n:5d}B  {preview}  |{asc}|")
        i += 1

    # Özet
    print(f"\n{'='*70}")
    print(f"ÖZET")
    print(f"{'='*70}")
    print(f"Toplam bağlantı : {len(connections)}")
    print(f"Toplam paket    : {len(packets)}")
    send_pkts = [p for p in packets if p['dir'] == '→']
    recv_pkts = [p for p in packets if p['dir'] == '←']
    print(f"  Gönderilen    : {len(send_pkts)} paket  "
          f"({sum(p['n'] for p in send_pkts)} byte)")
    print(f"  Alınan        : {len(recv_pkts)} paket  "
          f"({sum(p['n'] for p in recv_pkts)} byte)")

    if servers:
        print(f"\nSunucu başına istatistik:")
        for addr, s in sorted(servers.items()):
            print(f"  {addr:30s}  "
                  f"gönder={s['send']:4d} pkt/{s['bytes_s']:7d}B  "
                  f"al={s['recv']:4d} pkt/{s['bytes_r']:7d}B")

    # İlk/son paketler
    if packets:
        print(f"\nİlk 5 paket:")
        for p in packets[:5]:
            h = p['raw'][:16].hex() if p['raw'] else '(veri yok)'
            print(f"  [{p['t']}] {p['proto']} {p['dir']} {p['addr']:22s} {p['n']:5d}B  {h}")
        if len(packets) > 5:
            print(f"\nSon 5 paket:")
            for p in packets[-5:]:
                h = p['raw'][:16].hex() if p['raw'] else '(veri yok)'
                print(f"  [{p['t']}] {p['proto']} {p['dir']} {p['addr']:22s} {p['n']:5d}B  {h}")

    # Blowfish imzası ara
    print(f"\nBlowfish header arama (login sonrası ilk paketler)...")
    for p in packets[:20]:
        if p['raw'] and len(p['raw']) >= 4:
            # Tipik oyun paketi başlıkları: 2-byte length, 2-byte opcode
            length_field = int.from_bytes(p['raw'][:2], 'little')
            opcode = int.from_bytes(p['raw'][2:4], 'little') if len(p['raw']) >= 4 else 0
            if 4 <= length_field <= 1024:
                print(f"  [{p['t']}] {p['dir']} len_field={length_field} "
                      f"opcode=0x{opcode:04x}  raw={p['raw'][:8].hex()}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Kullanım: python parse_net_log.py pb_net.log")
        sys.exit(1)
    f = sys.argv[1]
    if not Path(f).exists():
        print(f"Hata: {f} bulunamadı")
        sys.exit(1)
    analyze(f)
