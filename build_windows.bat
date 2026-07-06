@echo off
REM =====================================================
REM  libcrypto-1_1.dll Proxy — 32-BIT Derleme Scripti
REM  MSYS2 MinGW32 ortamında çalıştırın!
REM  (CMD veya PowerShell'de DEĞİL)
REM =====================================================

echo.
echo === libcrypto proxy DLL derleniyor (32-bit) ===
echo.

REM --- i686 (32-bit) cross compiler'ı ara ---
where i686-w64-mingw32-gcc >nul 2>&1
if %errorlevel%==0 (
    echo [OK] i686-w64-mingw32-gcc bulundu...
    i686-w64-mingw32-gcc -shared -m32 -O2 ^
        -o libcrypto-1_1.dll ^
        libcrypto_proxy.c ^
        libcrypto_proxy.def ^
        -Wl,--kill-at ^
        -Wl,--enable-stdcall-fixup ^
        -Wall
    goto :check
)

REM --- MSYS2 MinGW32 shell'inde plain gcc (32-bit modda) ---
where gcc >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=*" %%i in ('gcc -dumpmachine') do set MACHINE=%%i
    echo Bulunan gcc hedefi: %MACHINE%
    echo %MACHINE% | findstr /i "i686\|i386\|mingw32" >nul
    if %errorlevel%==0 (
        echo [OK] 32-bit gcc bulundu...
        gcc -shared -O2 ^
            -o libcrypto-1_1.dll ^
            libcrypto_proxy.c ^
            libcrypto_proxy.def ^
            -Wl,--kill-at ^
            -Wl,--enable-stdcall-fixup ^
            -Wall
        goto :check
    ) else (
        echo [HATA] Bu gcc 64-bit! MinGW32 shell acin.
        echo.
        echo Windows'ta Start Menu'den "MSYS2 MinGW 32-bit" i arayip acin.
        echo Sonra su komutu calistirin:
        echo   pacman -S mingw-w64-i686-gcc  ^(bir kere^)
        echo   cd /c/path/to/proxy_dll
        echo   bash build_msys2.sh
        goto :end
    )
)

echo [HATA] Hic gcc bulunamadi!
echo.
echo Cozum: MSYS2 kurun ^(https://www.msys2.org/^)
echo  1. MSYS2 MinGW 32-bit terminalini acin
echo  2. pacman -S mingw-w64-i686-gcc
echo  3. cd /c/Users/.../proxy_dll
echo  4. bash build_msys2.sh
goto :end

:check
if exist libcrypto-1_1.dll (
    REM Mimariyi kontrol et
    for /f "skip=1 tokens=3" %%a in ('certutil -hashfile libcrypto-1_1.dll SHA1') do (set DUMMY=%%a & goto :size_check)
    :size_check
    echo.
    echo [BASARILI] libcrypto-1_1.dll olusturuldu.
    echo.
    echo --- KURULUM ADIMLARI ---
    echo  1. Oyun dizinine git  ^(PointBlank.exe neredeyse^)
    echo  2. libcrypto-1_1.dll  adini  libcrypto-1_1_orig.dll  yap
    echo  3. Bu yeni libcrypto-1_1.dll'i oyun dizinine kopyala
    echo  4. Oyunu normal baslatbir
    echo  5. Oyun dizininde olusacak pb_crypto.log'u oku
    echo.
    echo Blowfish session key pb_crypto.log icinde gorunecek.
) else (
    echo [HATA] Derleme basarisiz!
)

:end
pause
