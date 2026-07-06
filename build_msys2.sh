#!/usr/bin/env bash
# =====================================================
#  libcrypto-1_1.dll Proxy — MSYS2 MinGW32 Build
#  Kullanım: MSYS2 "MinGW 32-bit" terminalinde çalıştırın
#  $ bash build_msys2.sh
# =====================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "=== Mimari kontrol ==="
GCC_MACHINE=$(gcc -dumpmachine 2>/dev/null || echo "yok")
echo "gcc hedefi: $GCC_MACHINE"

# 32-bit gcc kontrolü
if [[ "$GCC_MACHINE" != *"i686"* && "$GCC_MACHINE" != *"i386"* ]]; then
    echo ""
    echo "HATA: Bu gcc 32-bit değil (hedef: $GCC_MACHINE)"
    echo ""
    echo "Çözüm:"
    echo "  1. Windows Start'tan 'MSYS2 MinGW 32-bit' terminalini açın"
    echo "  2. Gerekirse: pacman -S mingw-w64-i686-gcc"
    echo "  3. Bu scripti tekrar çalıştırın"
    exit 1
fi

echo "✓ 32-bit gcc OK: $GCC_MACHINE"
echo ""
echo "=== Derleniyor ==="

gcc -shared -O2 \
    -o libcrypto-1_1.dll \
    libcrypto_proxy.c \
    libcrypto_proxy.def \
    -Wl,--kill-at \
    -Wl,--enable-stdcall-fixup \
    -Wall

# Sonucu doğrula
if [ -f "libcrypto-1_1.dll" ]; then
    SIZE=$(stat -c%s libcrypto-1_1.dll 2>/dev/null || stat -f%z libcrypto-1_1.dll)
    echo ""
    echo "✓ libcrypto-1_1.dll oluşturuldu ($SIZE byte)"
    
    # file komutu varsa mimariyi kontrol et
    if command -v file &>/dev/null; then
        FILE_OUT=$(file libcrypto-1_1.dll)
        echo "  $FILE_OUT"
        if echo "$FILE_OUT" | grep -q "80386\|i386\|PE32 "; then
            echo "✓ MİMARİ DOĞRU: 32-bit (PE32)"
        else
            echo "⚠ UYARI: 64-bit çıktı? Yukarıdaki satırı kontrol edin."
        fi
    fi
    
    echo ""
    echo "=== KURULUM ==="
    echo "1. Oyun dizinine git (PointBlank.exe'nin yanı)"
    echo "2. libcrypto-1_1.dll  →  libcrypto-1_1_orig.dll  (yeniden adlandır)"
    echo "3. Bu yeni libcrypto-1_1.dll'i oyun dizinine kopyala"
    echo "4. Oyunu normal başlat"
    echo "5. pb_crypto.log dosyasını oku — session key orada görünecek"
else
    echo "✗ Derleme başarısız!"
    exit 1
fi
