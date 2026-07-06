# libcrypto-1_1.dll Proxy — Makefile
# Replit'te derlemek için: make
# Çıktı: libcrypto-1_1.dll (Windows 32-bit)

CC      = i686-w64-mingw32-gcc
CFLAGS  = -Wall -O2 -shared -m32
LDFLAGS = -Wl,--kill-at -Wl,--enable-stdcall-fixup

TARGET  = libcrypto-1_1.dll
SRC     = libcrypto_proxy.c
DEF     = libcrypto_proxy.def

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) $(DEF)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(DEF) $(LDFLAGS)
	@echo ""
	@echo "Derleme tamam: $(TARGET)"
	@echo ""
	@echo "Kurulum adımları:"
	@echo "  1. Oyunun dizinindeki libcrypto-1_1.dll -> libcrypto-1_1_orig.dll yeniden adlandır"
	@echo "  2. Bu klasördeki libcrypto-1_1.dll'i oyun dizinine kopyala"
	@echo "  3. Oyunu çalıştır"
	@echo "  4. Oyun dizininde pb_crypto.log dosyasını incele"

clean:
	rm -f $(TARGET)
