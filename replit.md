# libcrypto-1_1.dll Proxy — PointBlank Paket Analizörü

PointBlank oyunu için **libcrypto-1_1.dll proxy DLL** ve Python analiz araçları.
DLL, Blowfish / RSA çağrılarını ele geçirir; Python araçları oturum anahtarını bulur ve ağ trafiğini çözer.

## Mimari

İki katmanlı intercept:

| Katman | Yöntem | Amaç |
|--------|--------|-------|
| Export proxy | `__declspec(dllexport)` stub'lar | OpenSSL fonksiyonlarını yakala |
| Inline detour | x86 5-byte JMP patch | VMProtect IAT korumasını atla |

### Log dosyaları (oyun dizininde oluşur)
- `pb_crypto.log` — BF_set_key, RSA_public_encrypt, bellek tarama sonuçları
- `pb_net.log` — ham TCP/UDP trafiği (hex)
- `pb_plain.log` — çözülmüş plaintext paketler (BF export tetiklenirse)

## Derleme (Replit — Windows x86 DLL)

```bash
make
```

Veya doğrudan:

```bash
zig cc -target x86-windows-gnu -shared -O2 \
    -o libcrypto-1_1.dll libcrypto_proxy.c \
    -lkernel32 -lws2_32
```

Çıktı: `libcrypto-1_1.dll` (PE32, Windows x86)

## Python Analiz Araçları

```bash
# Log dosyalarını parse et (anahtar + istatistik)
python log_parser.py pb_crypto.log pb_net.log

# Ağ trafiği analizi
python parse_net_log.py pb_net.log

# Oturum anahtarını doğrula (known-plaintext)
python verify_key.py pb_crypto.log pb_net.log

# Anahtar bul + paketleri çöz (crack mode)
python crack_session_key.py pb_crypto.log pb_net.log

# Doğrulanmış anahtar ile tüm paketleri çöz
python decrypt_packets.py \
    --crypto pb_crypto.log \
    --net    pb_net.log \
    --endian le [--stateful] [--dump-all]
```

## Doğrulanmış Protokol Bilgileri

- **Şifreleme**: Blowfish CFB-64, özel varyant (per-round swap YOK, sonda tek swap)
- **IV kaynağı**: Login sunucusu challenge[3:11] — hem login hem oyun sunucusu için geçerli
- **Paket formatı**: `[1B payload_len][1B proto=0x0D][1B opcode][payload]`
- **Overhead**: 3 byte; `payload_len = toplam_paket_boyutu − 3`
- **Sunucular**: `31.169.73.205:39190` (login) ve `31.169.73.82:39190` (oyun)

## Kurulum (Windows)

1. Oyun dizinindeki `libcrypto-1_1.dll` → `libcrypto-1_1_orig.dll` yeniden adlandır
2. Derlenen `libcrypto-1_1.dll`'i oyun dizinine kopyala
3. Oyunu başlat → `pb_crypto.log` dosyasında session key görünür

## User Preferences

- Build tool: Zig (`zig cc -target x86-windows-gnu`)
- Target: Windows x86 (32-bit PE DLL)
- Log analizi: Python araçları, harici bağımlılık yok (stdlib only)
