#!/usr/bin/env python3
"""
PointBlank Paket Analizörü — Araç Listesi
==========================================
Log dosyalarınızı bu dizine kopyaladıktan sonra
aşağıdaki komutlardan birini çalıştırın.
"""

TOOLS = [
    ("log_parser.py",        "pb_crypto.log [pb_net.log]",                       "Log dosyasını parse et (anahtar + istatistik)"),
    ("parse_net_log.py",     "pb_net.log",                                        "Ağ trafiği analizi"),
    ("verify_key.py",        "pb_crypto.log pb_net.log",                          "Oturum anahtarını doğrula (known-plaintext)"),
    ("crack_session_key.py", "pb_crypto.log pb_net.log",                          "Anahtar bul + paketleri çöz"),
    ("decrypt_packets.py",   "--crypto pb_crypto.log --net pb_net.log --endian le","Doğrulanmış anahtar ile tüm paketleri çöz"),
]


def main() -> None:
    print("=" * 64)
    print("  PointBlank Paket Analizörü")
    print("=" * 64)
    print()
    print("Kullanılabilir araçlar:\n")
    for script, args, desc in TOOLS:
        print(f"  {desc}")
        print(f"    python {script} {args}")
        print()
    print("Log dosyalarını (pb_crypto.log, pb_net.log, …) bu")
    print("dizine kopyalayıp yukarıdaki komutlardan birini çalıştırın.")
    print()


if __name__ == "__main__":
    main()
