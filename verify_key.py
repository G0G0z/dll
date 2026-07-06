#!/usr/bin/env python3
"""
verify_key.py — BF_KEY Aday Doğrulayıcı
=========================================
pb_crypto.log içindeki BELLEK TARAMA v2 adaylarını
pb_net.log ağ trafiğiyle çapraz kontrol ederek
gerçek Blowfish session key'i bulur.

Yöntem (known-plaintext):
  Tüm client→server paketleri IV=0 ile sıfırlanır.
  Plaintext[0] = toplam paket boyutu (1 byte).
  Plaintext[1] = 0x00.

  Bu durumda:
    ks[0] = ciphertext[0] XOR packet_size_mod256
    ks[1] = ciphertext[1]                   (çünkü pt[1]=0x00)

  Ve:
    ks[0..7] = BF_encrypt(IV=0, IV=0) ile hesaplanan keystream

  → BF_encrypt(0, 0)[0] == 0x03 ve [1] == 0x80 olmalı

Kullanım:
  python verify_key.py pb_crypto.log pb_net.log
  python verify_key.py pb_crypto.log           # sadece P-array filtresi

Seçenekler:
  --ks HEXSTRING   Özel keystream baytları (varsayılan: 0380)
  --verbose        Her aday için Blowfish sonucunu göster
  --dump FILE      Doğrulanan anahtarı dosyaya yaz
"""

import sys
import re
import argparse
from pathlib import Path

# ─── Blowfish çekirdek (saf Python, harici kütüphane yok) ──────────────────

def bf_encrypt_block(P: list, S: list, xl: int, xr: int) -> tuple:
    """Tek 64-bit blok şifrele (P-array + S-boxes kullanarak)."""
    for i in range(16):
        xl ^= P[i]
        f  = (S[0][(xl >> 24) & 0xFF] + S[1][(xl >> 16) & 0xFF]) & 0xFFFFFFFF
        f ^= S[2][(xl >>  8) & 0xFF]
        f  = (f + S[3][xl & 0xFF]) & 0xFFFFFFFF
        xr ^= f
        xl, xr = xr, xl
    xl, xr = xr, xl
    xr ^= P[16]
    xl ^= P[17]
    return xl & 0xFFFFFFFF, xr & 0xFFFFFFFF

def keystream_from_key(P: list, S: list, le: bool = False) -> bytes:
    """IV=0 ile BF_encrypt(0, 0) → 8-byte keystream.
    le=False → OpenSSL l2n/n2l yolu: big-endian (standart).
    le=True  → union uc[] yolu: little-endian per 32-bit word.
               Game'in custom implementasyonu bunu kullanıyor olabilir.
    """
    xl, xr = bf_encrypt_block(P, S, 0, 0)
    order = 'little' if le else 'big'
    return xl.to_bytes(4, order) + xr.to_bytes(4, order)

# ─── pb_crypto.log ayrıştırıcı ─────────────────────────────────────────────

def parse_candidates(crypto_log: str) -> list:
    """
    Her BF_KEY ADAYI bloğunu ayrıştır.
    Döndürür: [{'num': int, 'addr': str, 'P': [18 int], 'S': [[256 int]×4],
                 'pass': int, 'pid_context': str}, ...]
    """
    text = Path(crypto_log).read_text(encoding='utf-8', errors='replace')
    lines = text.splitlines()
    candidates = []
    current_pass = 0
    current = None

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Geçiş başlangıcı
        m = re.search(r'BELLEK TARAMASI.*GEÇİŞ\s+(\d+)', stripped)
        if m:
            current_pass = int(m.group(1))
            continue

        # Aday başlığı
        m = re.search(r'BF_KEY ADAYI\s+#(\d+)', stripped)
        if m:
            if current and _candidate_complete(current):
                candidates.append(current)
            current = {
                'num': int(m.group(1)),
                'pass': current_pass,
                'addr': '',
                'P': None,
                'S': [None, None, None, None],
            }
            continue

        if current is None:
            continue

        # Adres
        m = re.search(r'Adres\s*:\s*([0-9A-Fa-f]+)', stripped)
        if m:
            current['addr'] = m.group(1)
            continue

        # FULL_KEY P satırı (en güvenilir P-array kaynağı)
        m = re.match(r'\[FULL_KEY\] P:([0-9a-fA-F]+)', stripped)
        if m:
            hex_p = m.group(1)
            if len(hex_p) == 18 * 8:  # 144 hex chars = 18 dwords
                current['P'] = [
                    int(hex_p[k*8:(k+1)*8], 16) for k in range(18)
                ]
            continue

        # S-box satırları (tam 1024B = 2048 hex chars)
        for sn in range(4):
            lbl = f'S[{sn}] (1024B)'
            if lbl in stripped:
                m2 = re.search(r'\[1024 bytes\]:\s*([0-9a-fA-F]+)', stripped)
                if m2:
                    hex_s = m2.group(1)
                    if len(hex_s) == 256 * 8:
                        # log_hex_full ham bellek baytı yazar (x86 LE)
                        # Her 4 byte → little-endian uint32 olarak oku
                        current['S'][sn] = [
                            int.from_bytes(bytes.fromhex(hex_s[k*8:(k+1)*8]), 'little')
                            for k in range(256)
                        ]
                break

    if current and _candidate_complete(current):
        candidates.append(current)

    return candidates


def _candidate_complete(c: dict) -> bool:
    return (c.get('P') is not None and
            all(s is not None for s in c.get('S', [None]*4)))

# ─── pb_net.log'dan keystream doğrulama verisi al ──────────────────────────

def extract_keystream_check(net_log: str) -> dict | None:
    """
    Client→server küçük paketlerden keystream baytlarını çıkar.
    Döndürür: {'ks0': int, 'ks1': int, 'samples': list}
    veya None (net log yoksa).
    """
    text = Path(net_log).read_text(encoding='utf-8', errors='replace')

    # Oyun sunucusu portundaki TCP SEND paketleri (port 1025-65534, non-HTTP)
    # Pattern: [time] TCP SEND → IP:PORT ... [N bytes]: HEXDATA
    send_re = re.compile(
        r'TCP SEND.*?(\d+\.\d+\.\d+\.\d+):(\d+).*?\[(\d+) bytes\]:\s*([0-9a-fA-F]{4,})'
    )

    samples = []
    for m in send_re.finditer(text):
        port = int(m.group(2))
        size = int(m.group(3))
        hex_data = m.group(4)
        # HTTP/HTTPS/DNS dışı küçük paketler (< 300 bytes)
        if port in (80, 443, 53) or size > 300 or size < 5:
            continue
        if len(hex_data) < size * 2:
            continue
        raw = bytes.fromhex(hex_data[:size * 2])
        samples.append({'size': size, 'raw': raw, 'port': port})

    if not samples:
        return None

    # ─── ks[0..1]: boyut alanından (en güvenilir) ──────────────────────────
    # pt[0] = paket boyutunun düşük byte'ı (size & 0xFF)
    # pt[1] = 0x00 (büyük byte, genellikle sıfır)
    ks0_votes: dict[int, int] = {}
    ks1_votes: dict[int, int] = {}
    for s in samples:
        k0 = s['raw'][0] ^ (s['size'] & 0xFF)
        k1 = s['raw'][1]  # pt[1]=0x00 varsayımı
        ks0_votes[k0] = ks0_votes.get(k0, 0) + 1
        ks1_votes[k1] = ks1_votes.get(k1, 0) + 1

    ks0 = max(ks0_votes, key=ks0_votes.get)
    ks1 = max(ks1_votes, key=ks1_votes.get)

    # ─── ks[2..7]: her byte konumunda çoğunluk oyu ──────────────────────────
    # pt[2..7] bilinmiyor — ama bazı byte'lar paketler arası sabit (opcode,
    # versiyon, padding) olabilir.  Minimum 70% oy alıyorsa sabitleriz.
    # Sadece aynı boyuttaki paketleri gruplandır (aynı format = aynı pt yapısı)
    ks_extra: dict[int, int] = {}  # {byte_index: value}
    from collections import Counter
    by_size: dict[int, list] = {}
    for s in samples:
        by_size.setdefault(s['size'], []).append(s['raw'])

    # En büyük grup üzerinde çalış
    best_group = max(by_size.values(), key=len) if by_size else []
    min_votes_pct = 0.75  # %75 çoğunluk → güvenilir

    if len(best_group) >= 5:
        for bi in range(2, min(8, min(len(r) for r in best_group))):
            c = Counter(r[bi] for r in best_group)
            total_g = len(best_group)
            top_val, top_cnt = c.most_common(1)[0]
            if top_cnt / total_g >= min_votes_pct:
                # Bu byte için en yaygın ct değeri → pt bilinmiyorsa ks olabilir
                # sadece pt[bi] == 0x00 olan pozisyonlar için ks[bi] = ct[bi]
                # ks[bi] kaydediyoruz, doğrulama aşamasında kullanılacak
                ks_extra[bi] = top_val  # ct[bi] (pt[bi]=0 varsayımıyla ks[bi])

    return {
        'ks0': ks0,
        'ks1': ks1,
        'samples': samples,
        'ks0_votes': ks0_votes,
        'ks1_votes': ks1_votes,
        'ks_extra': ks_extra,      # {byte_index: ct_value} for bytes 2-7
        'best_group_size': len(best_group),
    }

# ─── P-array hızlı ön-eleme (pointer / sıfır ağırlıklı yapılar) ────────────

def p_array_plausible(P: list) -> bool:
    """
    Gerçek BF_set_key sonrası P-array'de:
    - 18 değerin tamamı sıfır olmamalı
    - 18 değerden en fazla 2'si sıfır olabilir
    - Üst byte'ı sıfır olan "pointer benzeri" dword sayısı 5'i geçmemeli
    """
    zeros = sum(1 for v in P if v == 0)
    if zeros > 2:
        return False
    # Üst byte = 0x00 olan → Windows user-space pointer görünümlü
    ptr_like = sum(1 for v in P if (v >> 24) == 0)
    if ptr_like > 5:
        return False
    return True

# ─── Alternatif yerleşim yorumları ─────────────────────────────────────────

def candidate_layouts(cand: dict) -> list:
    """
    Aynı ham bellek penceresini farklı BF_KEY yerleşim yorumlarıyla dene.

    Desteklenen yerleşimler:
    ┌─────────────────────────────────────────────────────────────────────┐
    │ P-first (OpenSSL varsayılan):  P[18] | S0[256] | S1[256] | S2[256] │S3[256]
    │ S-first (bazı özel impl.): S0[256] | S1[256] | S2[256] | S3[256] | P[18]
    └─────────────────────────────────────────────────────────────────────┘

    Log'daki ham dword dizisi (toplam 1042 dword = 4168 byte):
      all_dw = P_log(18) + S0_log(256) + S1_log(256) + S2_log(256) + S3_log(256)

    S-first yorumu (S-boxlar önce, P-array sonda):
      true_S0 = all_dw[0:256]
      true_S1 = all_dw[256:512]
      true_S2 = all_dw[512:768]
      true_S3 = all_dw[768:1024]
      true_P  = all_dw[1024:1042]

    Döndürür: [{'label': str, 'P': list, 'S': list}, ...]
    """
    P_log = cand['P']                     # 18 dwords
    S_log = cand['S']                     # 4 × 256 dwords

    layouts = []

    # 1. P-first (mevcut yorumlama)
    layouts.append({
        'label': 'P-first',
        'P': P_log,
        'S': S_log,
    })

    # 2. S-first — raw pencereyi tek dizi olarak yeniden yorumla
    all_dw = P_log + S_log[0] + S_log[1] + S_log[2] + S_log[3]
    # all_dw uzunluğu: 18+256+256+256+256 = 1042
    if len(all_dw) == 1042:
        layouts.append({
            'label': 'S-first',
            'P': all_dw[1024:1042],
            'S': [
                all_dw[0:256],
                all_dw[256:512],
                all_dw[512:768],
                all_dw[768:1024],
            ],
        })

    return layouts


# ─── Ana doğrulama ─────────────────────────────────────────────────────────

def verify_candidates(candidates: list, ks_check: bytes,
                      verbose: bool = False) -> list:
    """
    Her aday için birden fazla bellek yerleşimi yorumuyla BF_encrypt(0, 0)
    hesapla ve keystream ile karşılaştır.
    Döndürür: eşleşen aday listesi
    """
    matches = []
    total = len(candidates)
    filtered_p = 0
    tested = 0

    for idx, cand in enumerate(candidates):
        layouts = candidate_layouts(cand)

        any_tested = False
        for layout in layouts:
            P = layout['P']
            S = layout['S']

            # Hızlı P-array filtresi (P-first için anlamlı, S-first için
            # true_P rastgele görünür — atla sadece P-first'te)
            if layout['label'] == 'P-first' and not p_array_plausible(P):
                filtered_p += 1
                continue

            any_tested = True
            tested += 1
            ks = keystream_from_key(P, S)

            if verbose:
                print(f"  #{cand['num']:4d}  {layout['label']}  addr={cand['addr']}  "
                      f"ks={ks.hex()}  check={ks_check.hex()}")

            # Keystream eşleşme kontrolü
            if ks[:len(ks_check)] == ks_check:
                matches.append({
                    **cand,
                    'keystream': ks,
                    'layout': layout['label'],
                    'matched_P': P,
                    'matched_S': S,
                })
            elif verbose and ks[0] == ks_check[0]:
                print(f"    ⚠ near-miss #{cand['num']} [{layout['label']}]: ks={ks.hex()}")

    print(f"\n  Toplam aday       : {total}")
    print(f"  P-array filtresi  : {filtered_p} elendi (yalnızca P-first)")
    print(f"  Blowfish test     : {tested}")
    print(f"  Eşleşen           : {len(matches)}")
    return matches

# ─── Çıktı ─────────────────────────────────────────────────────────────────

def print_match(cand: dict) -> None:
    ks = cand.get('keystream', b'')
    layout = cand.get('layout', 'P-first')
    P = cand.get('matched_P', cand['P'])
    print(f"\n{'='*64}")
    print(f"✅  DOĞRULANDI — BF_KEY ADAYI #{cand['num']}  [{layout}]")
    print(f"{'='*64}")
    print(f"  Bellek adresi : 0x{cand['addr']}")
    print(f"  Geçiş         : {cand['pass']}")
    print(f"  Yerleşim      : {layout}")
    print(f"  Keystream[0:8]: {ks.hex()}")
    print(f"  P-array (18×4B):")
    for i, v in enumerate(P):
        print(f"    P[{i:2d}] = 0x{v:08X}")
    print(f"  [FULL_KEY] P:", end='')
    for v in P:
        print(f'{v:08x}', end='')
    print()
    print(f"{'='*64}")


# ─── Entrypoint ────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('crypto_log', help='pb_crypto.log yolu')
    ap.add_argument('net_log', nargs='?', help='pb_net.log yolu (opsiyonel)')
    ap.add_argument('--ks', default=None,
                    help='Keystream hex kontrolü (varsayılan: net_log\'dan otomatik)')
    ap.add_argument('--verbose', action='store_true',
                    help='Her aday için keystream göster')
    ap.add_argument('--dump', default=None,
                    help='Doğrulanan anahtarı bu dosyaya yaz')
    args = ap.parse_args()

    # 1. Adayları yükle
    print(f"📂  Adaylar yükleniyor: {args.crypto_log}")
    candidates = parse_candidates(args.crypto_log)
    if not candidates:
        print("⚠️  Hiç aday bulunamadı. Log formatını kontrol edin.")
        sys.exit(1)
    print(f"    {len(candidates)} aday yüklendi.")

    # 2. Keystream belirle
    ks_check: bytes
    if args.ks:
        ks_check = bytes.fromhex(args.ks)
        print(f"🔑  Manuel keystream: {ks_check.hex()}")
    elif args.net_log and Path(args.net_log).exists():
        print(f"📡  Net log analiz ediliyor: {args.net_log}")
        ksc = extract_keystream_check(args.net_log)
        if ksc:
            ks_check = bytes([ksc['ks0'], ksc['ks1']])
            print(f"    Client→server paket örnekleri : {len(ksc['samples'])}")
            print(f"    ks[0] oyları : {ksc['ks0_votes']}")
            print(f"    ks[1] oyları : {ksc['ks1_votes']}")
            print(f"    ➜  Keystream[0:2] = {ks_check.hex()}")

            # ks_extra: yüksek güvenli ek baytlar
            if ksc.get('ks_extra'):
                # pt[bi]=0 varsayımıyla ks[bi] = ct[bi]_dominant
                extra_str = '  '.join(
                    f"ks[{bi}]≈{val:02x}" for bi, val in sorted(ksc['ks_extra'].items())
                )
                print(f"    Ek kısıtlar (pt=0 var.): {extra_str}")
                # Doğrulamaya ekle: sadece pt[5] için güvenilir (sık 0x00)
                # ks[5] = 0x08 => ks_check bytes 0-5 genişlet
                if 5 in ksc['ks_extra']:
                    ks5 = ksc['ks_extra'][5]
                    # Bytes 2-4 bilinmiyor — sadece 0,1 ve 5 kullan → byte 2-4'ü mask ile geç
                    # ks_check'i ks[0..5] = 03 80 ?? ?? ?? 08 şeklinde genişlet, ?? skip
                    ksc['ks5'] = ks5
                    print(f"    ks[5] = {ks5:02x}  (pt[5]=0x00 varsayımı ile)")
        else:
            print("⚠️  Net log'dan paket çıkarılamadı — varsayılan 0380 kullanılıyor")
            ks_check = bytes([0x03, 0x80])
    else:
        # Bu loglardan elle hesaplanan sabit değer
        ks_check = bytes([0x03, 0x80])
        print(f"ℹ️   Keystream varsayılan: {ks_check.hex()}")

    # 3. Doğrula
    print(f"\n🔍  Blowfish doğrulaması başlıyor...")
    matches = verify_candidates(candidates, ks_check, verbose=args.verbose)

    # 4. Sonuç
    if not matches:
        print("\n❌  Eşleşen aday bulunamadı.")
        print("   Öneriler:")
        print("   - Daha fazla keystream baytı biliyorsanız --ks ile verin")
        print("   - GEÇİŞ 2/3 loglarının da dahil olduğundan emin olun")
        print("   - Oyun başladıktan sonra bağlantı kurmayı deneyin")
        sys.exit(0)

    for m in matches:
        print_match(m)

    # 5. Dump
    if args.dump and matches:
        out = Path(args.dump)
        with out.open('w') as f:
            for m in matches:
                # matched_P/matched_S: doğru yerleşim (S-first ise true_P/true_S)
                P_out = m.get('matched_P', m['P'])
                S_out = m.get('matched_S', m['S'])
                f.write(f"ADAYI #{m['num']}  addr=0x{m['addr']}  geçiş={m['pass']}  yerleşim={m.get('layout','P-first')}\n")
                f.write(f"keystream : {m.get('keystream', b'').hex()}\n")
                f.write(f"P         : {''.join(f'{v:08x}' for v in P_out)}\n")
                for sn in range(4):
                    f.write(f"S[{sn}]      : "
                            + ''.join(f'{v:08x}' for v in S_out[sn]) + '\n')
                f.write('\n')
        print(f"\n💾  Sonuç yazıldı: {out}")


if __name__ == '__main__':
    main()
