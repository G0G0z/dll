# libcrypto-1_1.dll Proxy — Makefile
# Replit'te derlemek için: make
# Çıktı: libcrypto-1_1.dll (Windows 32-bit)
#
# Derleme aracı: Zig (cross-compile, Windows x86)

ZIG     = zig
TARGET  = libcrypto-1_1.dll
SRC     = libcrypto_proxy.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) libcrypto_proxy.def
	$(ZIG) cc -target x86-windows-gnu -shared -O2 \
	    -o $(TARGET) $(SRC) \
	    -lkernel32 -lws2_32
	@echo ""
	@echo "✓ Derleme tamam: $(TARGET)"
	@ls -lh $(TARGET)
	@echo ""
	@echo "Kurulum adımları:"
	@echo "  1. Oyunun dizinindeki libcrypto-1_1.dll -> libcrypto-1_1_orig.dll yeniden adlandır"
	@echo "  2. Bu klasördeki libcrypto-1_1.dll'i oyun dizinine kopyala"
	@echo "  3. Oyunu çalıştır"
	@echo "  4. Oyun dizininde pb_crypto.log dosyasını incele"

clean:
	rm -f $(TARGET)
