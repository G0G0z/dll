# libcrypto-1_1.dll Proxy

PointBlank oyunu için **libcrypto-1_1.dll proxy DLL**'i.
Blowfish / RSA çağrılarını ele geçirir ve ağ trafiğini loglar.

## Mimari

İki katmanlı intercept:

| Katman | Yöntem | Amaç |
|--------|--------|-------|
| Export proxy | `__declspec(dllexport)` stub'lar | OpenSSL fonksiyonlarını yakala |
| Inline detour | x86 5-byte JMP patch | VMProtect IAT korumasını atla |

### Log dosyaları (oyun dizininde oluşur)
- `pb_crypto.log` — BF_set_key, RSA_public_encrypt, bellek tarama sonuçları
- `pb_net.log` — ham TCP/UDP trafiği (hex)
- `pb_key_fallback.log` — crypto log açılamazsa yedek

## Derleme (Replit)

```bash
make
```

veya doğrudan:

```bash
zig cc -target x86-windows-gnu -shared -O2 \
    -o libcrypto-1_1.dll libcrypto_proxy.c \
    -lkernel32 -lws2_32
```

Çıktı: `libcrypto-1_1.dll` (PE32, Windows x86)

## Log analizleri

```bash
# Blowfish key analizi
python log_parser.py pb_crypto.log [pb_net.log]

# Ağ trafiği analizi
python parse_net_log.py pb_net.log
```

## Kurulum (Windows)

1. Oyun dizinindeki `libcrypto-1_1.dll` → `libcrypto-1_1_orig.dll` yeniden adlandır
2. Derlenen `libcrypto-1_1.dll`'i oyun dizinine kopyala
3. Oyunu başlat → `pb_crypto.log` dosyasında session key görünür

## User preferences

- Build tool: Zig (`zig cc -target x86-windows-gnu`)
- Target: Windows x86 (32-bit PE DLL)
