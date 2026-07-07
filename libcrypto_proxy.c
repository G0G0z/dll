/**
 * libcrypto-1_1.dll — Proxy + WinSock Inline Detour
 * ==================================================
 * İki katmanlı intercept:
 *
 * [Katman 1] OpenSSL proxy export'ları
 *   BF_cfb64_encrypt / RSA_public_encrypt / PEM_read_bio_RSAPublicKey …
 *   → VMProtect IAT korursa çalışmayabilir.
 *
 * [Katman 2] ws2_32.dll inline detour (byte-level patch)
 *   send / recv / sendto / recvfrom / WSASend / WSARecv /
 *   WSASendTo / WSARecvFrom / connect / WSAConnectByNameW
 *   → Fonksiyonun kendi byte'larına JMP yazılır.
 *   → VMProtect IAT korumasını tamamen atlar.
 *   → Her paketin ham içeriği pb_net.log'a kaydedilir.
 *
 * Log dosyaları (DLL'in bulunduğu klasör):
 *   pb_crypto.log  — OpenSSL çağrıları (Blowfish key, RSA)
 *   pb_net.log     — tüm ağ trafiği (şifreli, ham hex)
 *
 * Derleme:
 *   zig cc -target x86-windows-gnu -shared -O2 \
 *       -o libcrypto-1_1.dll libcrypto_proxy.c -lkernel32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ══════════════════════════════════════════════════════
 *  ORTAK YARDIMCILAR
 * ══════════════════════════════════════════════════════ */

#define OSSL_CC __cdecl

typedef void BF_KEY;
typedef void RSA;
typedef void BIO;

static FILE *g_log_crypto = NULL;   /* pb_crypto.log  — BF key tarama + OpenSSL çağrıları */
static FILE *g_log_net    = NULL;   /* pb_net.log     — ham şifreli trafik               */
static FILE *g_log_plain  = NULL;   /* pb_plain.log   — çözülmüş plaintext paketler      */

/* Diagnostic: counts every BF export call — visible in pb_net.log lines */
static volatile LONG g_bf_export_calls = 0;

static INIT_ONCE  g_init        = INIT_ONCE_STATIC_INIT;
static HMODULE    g_real_crypto  = NULL;

/* Oyunun yükleme dizinini bir kere hesapla */
static char g_base_dir[MAX_PATH] = {0};

static void make_path(char *out, const char *filename) {
    snprintf(out, MAX_PATH, "%s%s", g_base_dir, filename);
}

/* ── Log dosyaları %TEMP%\PBProxy\ altına yazılır, oyun klasörüne dokunulmaz ── */
static char g_temp_log_dir[MAX_PATH] = {0};

static void ensure_temp_log_dir(void) {
    if (g_temp_log_dir[0]) return;
    char tmp[MAX_PATH];
    DWORD n = GetTempPathA(MAX_PATH, tmp);
    if (!n || n >= MAX_PATH) {
        /* Fallback: oyun klasörü */
        strncpy(g_temp_log_dir, g_base_dir, MAX_PATH - 1);
        return;
    }
    /* Sondaki backslash'i kaldır */
    if (n > 0 && tmp[n - 1] == '\\') tmp[n - 1] = 0;
    snprintf(g_temp_log_dir, MAX_PATH, "%s\\PBProxy", tmp);
    CreateDirectoryA(g_temp_log_dir, NULL); /* zaten varsa hata yok */
}

static void make_temp_log_path(char *out, const char *filename) {
    ensure_temp_log_dir();
    snprintf(out, MAX_PATH, "%s\\%s", g_temp_log_dir, filename);
}

static FILE *open_log(const char *filename) {
    char path[MAX_PATH];
    make_temp_log_path(path, filename);
    return fopen(path, "w");   /* "w" = her oturumda sıfırdan başla */
}

static void log_hex(FILE *f, const char *label,
                    const unsigned char *buf, int len) {
    if (!f || !buf || len <= 0) return;
    int show = len > 128 ? 128 : len;
    fprintf(f, "  %-30s [%d bytes]: ", label, len);
    for (int i = 0; i < show; i++) fprintf(f, "%02x", buf[i]);
    if (len > 128) fprintf(f, "...(+%d)", len - 128);
    fprintf(f, "\n");
}

/* Kesimsiz hex dump — S-box tam logu (1024B) için */
static void log_hex_full(FILE *f, const char *label,
                         const unsigned char *buf, int len) {
    if (!f || !buf || len <= 0) return;
    fprintf(f, "  %-30s [%d bytes]: ", label, len);
    for (int i = 0; i < len; i++) fprintf(f, "%02x", buf[i]);
    fprintf(f, "\n");
}

/* Forward declaration — log_time aşağıda tanımlı */
static void log_time(FILE *f);

/* ══════════════════════════════════════════════════════
 *  PLAINTEXT PAKET LOGGER — pb_plain.log
 *
 *  PointBlank protokol çerçeve formatı (onaylı):
 *    [1B payload_len] [1B proto=0x0D] [1B opcode] [payload_len byte]
 *  total_pkt_bytes = payload_len + 3
 *
 *  BF_cfb64_encrypt çağrılarından doğrudan plaintext alır:
 *    enc=1 (ENCRYPT) → 'in'  tamponu = gönderilecek plaintext
 *    enc=0 (DECRYPT) → 'out' tamponu = çözülmüş plaintext
 *
 *  Büyük paketler (>256B) tek çağrıda gelebileceği gibi
 *  birden fazla BF_cfb64_encrypt çağrısıyla da gelebilir;
 *  her çağrı log satırı olarak bağımsız kaydedilir.
 * ══════════════════════════════════════════════════════ */

/* Çağrı sayacı — plaintext log başlığında sıra numarası */
static volatile LONG g_plain_call_seq = 0;

static void log_pb_plain_pkt(FILE *f,
                              const char          *dir,   /* "SEND →" / "RECV ←" */
                              const unsigned char *data,
                              int                  len,
                              int                  seq) {
    if (!f || !data || len < 1) return;
    log_time(f);

    if (len >= 3) {
        uint8_t  plen   = data[0];          /* payload_len alanı              */
        uint8_t  proto  = data[1];          /* 0x0D sabit proto byte'ı        */
        uint8_t  opcode = data[2];          /* işlev kodu                     */
        int      paysz  = len - 3;          /* gerçek payload boyutu          */

        fprintf(f, "#%-4d %s  total=%-5dB  len_field=%-3u  proto=0x%02x  "
                   "op=0x%02x(%-3u)  payload(%d)=",
                seq, dir, len, plen, proto, opcode, opcode, paysz);

        /* İlk 64 bayt payload hex */
        int show = paysz < 64 ? paysz : 64;
        for (int i = 0; i < show; i++) fprintf(f, "%02x", data[3 + i]);
        if (paysz > 64) fprintf(f, "…(+%d)", paysz - 64);

        /* Protokol uyarıları */
        if (proto != 0x0D)
            fprintf(f, "  [!proto≠0x0D — büyük/çok-parçalı paket?]");
        if (plen != (uint8_t)(len - 3) && len <= 258)
            fprintf(f, "  [!len_field=%u beklenen=%d]", plen, len - 3);
    } else {
        /* <3 byte — raw dump */
        fprintf(f, "#%-4d %s  total=%dB  raw=", seq, dir, len);
        for (int i = 0; i < len; i++) fprintf(f, "%02x", data[i]);
    }

    fprintf(f, "\n");
    fflush(f);
}

/* Çok-satırlı hex dump (isteğe bağlı ayrıntılı mod için) */
static void log_pb_hexdump(FILE *f, const unsigned char *data, int len) {
    if (!f || !data || len <= 0) return;
    int rows = (len + 15) / 16;
    for (int r = 0; r < rows && r < 16; r++) {   /* en fazla 16 satır */
        int base = r * 16;
        fprintf(f, "    %04x: ", base);
        for (int i = 0; i < 16; i++) {
            if (base + i < len) fprintf(f, "%02x ", data[base + i]);
            else                fprintf(f, "   ");
        }
        fprintf(f, " ");
        for (int i = 0; i < 16 && base + i < len; i++) {
            uint8_t c = data[base + i];
            fprintf(f, "%c", (c >= 0x20 && c < 0x7F) ? (char)c : '.');
        }
        fprintf(f, "\n");
    }
    if (rows > 16) fprintf(f, "    … (%d satır daha)\n", rows - 16);
    fflush(f);
}

/*
 * IV çift-endian logu
 *
 * OpenSSL BF_cfb64_encrypt, IV tamponuna l2n() makrosu ile yazar:
 *   l2n(xl, iv)  →  iv[0..3] = xl >> 24..0   (big-endian)
 * Oyunun kendi Blowfish'i  union { BF_LONG ul[2]; unsigned char uc[8]; }
 * kullanıyorsa bellekte little-endian saklıyor demektir.
 * Her iki yorumu da logla; Python'da hangisinin doğru olduğunu test ederiz.
 */
static void log_ivec_endian(FILE *f, const unsigned char *ivec) {
    if (!f || !ivec) return;
    /* Big-endian (OpenSSL l2n uyumlu okuma) */
    uint32_t be0 = ((uint32_t)ivec[0] << 24) | ((uint32_t)ivec[1] << 16) |
                   ((uint32_t)ivec[2] <<  8) |  (uint32_t)ivec[3];
    uint32_t be1 = ((uint32_t)ivec[4] << 24) | ((uint32_t)ivec[5] << 16) |
                   ((uint32_t)ivec[6] <<  8) |  (uint32_t)ivec[7];
    /* Little-endian (game union { BF_LONG ul[2]; uc[8]; } uyumlu okuma) */
    uint32_t le0, le1;
    memcpy(&le0, ivec,     4);
    memcpy(&le1, ivec + 4, 4);
    fprintf(f, "  ivec[BE] %08x %08x   ivec[LE] %08x %08x\n",
            be0, be1, le0, le1);
}

static void log_time(FILE *f) {
    if (!f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

/* Socket → IP:port string */
static void socket_peer(SOCKET s, char *buf, int bufsz) {
    struct sockaddr_in sa;
    int sl = sizeof(sa);
    if (getpeername(s, (struct sockaddr*)&sa, &sl) == 0) {
        unsigned char *ip = (unsigned char*)&sa.sin_addr.s_addr;
        snprintf(buf, bufsz, "%u.%u.%u.%u:%u",
                 ip[0], ip[1], ip[2], ip[3], ntohs(sa.sin_port));
    } else {
        snprintf(buf, bufsz, "sock#%llu", (unsigned long long)s);
    }
}

/* sockaddr → string */
static void addr_str(const struct sockaddr *sa, char *buf, int bufsz) {
    if (!sa) { snprintf(buf, bufsz, "?"); return; }
    const struct sockaddr_in *sin = (const struct sockaddr_in*)sa;
    unsigned char *ip = (unsigned char*)&sin->sin_addr.s_addr;
    snprintf(buf, bufsz, "%u.%u.%u.%u:%u",
             ip[0], ip[1], ip[2], ip[3], ntohs(sin->sin_port));
}

/* ══════════════════════════════════════════════════════
 *  INLINE DETOUR — x86 trampolin altyapısı
 *  Her fonksiyon için 5-byte JMP yazılır.
 *  Orijinal 5 byte + geri JMP = trampolin.
 * ══════════════════════════════════════════════════════ */

#define TRAMP_SIZE 16   /* 5 orijinal byte + 5 JMP geri + hizalama */

typedef struct {
    uint8_t code[TRAMP_SIZE];
    void   *orig_fn;    /* patch yapılan adres */
    BOOL    installed;
} Detour;

static BOOL detour_install(Detour *d, void *target, void *hook) {
    DWORD old;
    /* Çalıştırılabilir bellek ayır (trampolin için) */
    uint8_t *tramp = (uint8_t*)VirtualAlloc(NULL, TRAMP_SIZE,
                         MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);
    if (!tramp) return FALSE;

    /* Orijinal 5 byte'ı kopyala */
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old)) {
        VirtualFree(tramp, 0, MEM_RELEASE);
        return FALSE;
    }
    memcpy(tramp, target, 5);

    /* Trampolin: [5 orijinal byte] + [JMP target+5] */
    tramp[5] = 0xE9;  /* JMP rel32 */
    *(int32_t*)(tramp + 6) =
        (int32_t)((uint8_t*)target + 5 - (tramp + 5 + 5));

    /* Hedef fonksiyona JMP hook yaz */
    uint8_t *tgt = (uint8_t*)target;
    tgt[0] = 0xE9;
    *(int32_t*)(tgt + 1) =
        (int32_t)((uint8_t*)hook - (tgt + 5));

    VirtualProtect(target, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 5);

    d->code[0] = 0;
    d->orig_fn  = tramp;
    d->installed = TRUE;
    return TRUE;
}

/* ══════════════════════════════════════════════════════
 *  WINSOCk HOOK FONKSİYONLARI
 * ══════════════════════════════════════════════════════ */

/* Trampolin pointer tipleri */
typedef int  (WINAPI *fn_connect_t)(SOCKET, const struct sockaddr*, int);
typedef int  (WINAPI *fn_send_t)(SOCKET, const char*, int, int);
typedef int  (WINAPI *fn_recv_t)(SOCKET, char*, int, int);
typedef int  (WINAPI *fn_sendto_t)(SOCKET, const char*, int, int,
                                    const struct sockaddr*, int);
typedef int  (WINAPI *fn_recvfrom_t)(SOCKET, char*, int, int,
                                      struct sockaddr*, int*);
typedef int  (WINAPI *fn_WSASend_t)(SOCKET, LPWSABUF, DWORD,
                                     LPDWORD, DWORD,
                                     LPWSAOVERLAPPED,
                                     LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int  (WINAPI *fn_WSARecv_t)(SOCKET, LPWSABUF, DWORD,
                                     LPDWORD, LPDWORD,
                                     LPWSAOVERLAPPED,
                                     LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int  (WINAPI *fn_WSASendTo_t)(SOCKET, LPWSABUF, DWORD,
                                       LPDWORD, DWORD,
                                       const struct sockaddr*, int,
                                       LPWSAOVERLAPPED,
                                       LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int  (WINAPI *fn_WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD,
                                         LPDWORD, LPDWORD,
                                         struct sockaddr*, LPINT,
                                         LPWSAOVERLAPPED,
                                         LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (WINAPI *fn_WSAConnByName_t)(SOCKET, LPWSTR, LPWSTR,
                                           DWORD*, struct sockaddr*,
                                           DWORD*, struct sockaddr*,
                                           const struct timeval*, LPWSAOVERLAPPED);

static Detour d_connect, d_send, d_recv, d_sendto, d_recvfrom;
static Detour d_WSASend, d_WSARecv, d_WSASendTo, d_WSARecvFrom;
static Detour d_WSAConnByName;

/* ── OpenSSL inline detour'lar (libcrypto-1_1_orig.dll üzerinde) ── */
static Detour d_BF_set_key;         /* ALTIN: ham session key buraya gelir */
static Detour d_BF_cfb64_inline;    /* her encrypt/decrypt çağrısı */
static Detour d_RSA_public_inline;  /* RSA ile şifrelenmeden önce */

/* ══════════════════════════════════════════════════════
 *  BLOWFISH KEY — BELLEK TARAMA MOTORu  v2
 *
 *  Sorun: eski sürüm grafik/ses buffer'larını yanlış
 *  pozitif olarak işaretliyordu (12 K+ sonuç).
 *
 *  v2 iyileştirmeleri:
 *   1. Adres aralığı filtresi: sadece 0x00100000–0x3FFFFFFF
 *      (oyun heap/data; DLL bölgeleri ve grafik belleği dışarıda)
 *   2. Bölge boyutu sınırı: >16 MB bölgeler atlanır
 *   3. Sıkı S-box testi: her 4 byte pozisyonunda histogram
 *      uniformluğu — max frekans <8 (256 girişte uniform=1)
 *   4. Bilinen BF init sabiti reddi: S[0][0]==0xd1310ba6
 *      olduğunda bu, BF_set_key çalışmamış init tablosu
 *   5. TAM S-box logu: Python ile doğrulama için 4×1024B
 *   6. 3 geçiş: 1s / 5s / 10s — oyun sunucusu geç bağlanabilir
 * ══════════════════════════════════════════════════════ */

#define BF_P_DWORDS   18
#define BF_S_DWORDS   (4 * 256)
#define BF_KEY_SIZE   ((BF_P_DWORDS + BF_S_DWORDS) * 4)   /* 4168 byte */

/* Bilinen ilk Blowfish başlangıç sabitleri (BF_set_key çalışmamış tablo) */
#define BF_INIT_S0_0  0xd1310ba6u
#define BF_INIT_P0    0x243f6a88u

/* Tarama durumu */
static volatile LONG g_scan_triggered  = 0;   /* başlangıç thread'i başlatıldı mı */
static volatile LONG g_scan_running    = 0;
static volatile LONG g_recv_scan_count = 0;   /* recv-hook tetiklemesi sayacı */
static HANDLE        g_scan_shutdown   = NULL; /* DLL_PROCESS_DETACH'ta sinyallenir */
static HANDLE        g_scan_thread     = NULL; /* thread tamamlanana kadar join için */

/* Anlık tarama thread'leri — detach'ta join etmek için */
#define MAX_IMM_THREADS 8
static HANDLE g_imm_threads[MAX_IMM_THREADS];
static volatile LONG g_imm_thread_cnt = 0;

/* İlk send scan sayacı — ilk 2 game-server send'de anında tarama */
static volatile LONG g_send_scan_count = 0;

/* run_one_pass() paylaşılan tampon yarış koruması */
static CRITICAL_SECTION g_scan_cs;
static BOOL             g_scan_cs_init = FALSE;

/* Socket → port 39190 mu? (sadece game server trafiği için anlık tarama) */
#define GAME_PORT 39190u
static volatile LONG g_game_socket_seen = 0;  /* game server recv görüldü mü */

/*
 * Tarama erken durdurma:
 *   g_total_candidates  — tüm geçişlerde bulunan toplam aday sayısı
 *   g_memscan_done      — 1 olunca artık hiçbir tarama başlatılmaz,
 *                         devam eden geçişler de çıkar.
 *   SCAN_CANDIDATE_LIMIT — bu kadar adaydan sonra tarama tamamen durur.
 *
 * Neden 100? İlk geçiş gerçek session key'i bulur; sonraki binlerce
 * yanlış pozitif sadece log boyutunu şişirir ve oyunu kastırır.
 */
#define SCAN_CANDIDATE_LIMIT  100
static volatile LONG g_total_candidates = 0;
static volatile LONG g_memscan_done     = 0;

/*
 * Tarama bitti mi? — interlocked okuma (x86'da aligned 32-bit okuma
 * zaten atomik, ama tutarlılık için her okumada CAS kullanıyoruz).
 */
static BOOL memscan_is_done(void) {
    return InterlockedCompareExchange(&g_memscan_done, 0, 0) != 0;
}

/*
 * Taramayı durdur — yalnızca ilk çağrı etkili (CAS ile set-once).
 * Dönüş: TRUE → bu çağrı bayrağı set etti (kazanan thread).
 */
static BOOL memscan_set_done(void) {
    return InterlockedCompareExchange(&g_memscan_done, 1, 0) == 0;
}

/* Forward declaration */
static void ensure_init(void);

/*
 * Sıkı S-box testi — 4 byte pozisyonunun her birinde
 * histogram oluşturur; max frekans < 8 olmalı.
 * Grafik RGBA bufferlarda alpha=0xFF →256 kez tekrar → elenir.
 * Ses PCM bufferlarda üst 16 bit=0 →256 kez tekrar → elenir.
 */
static BOOL sbox_strict(const uint32_t *sbox) {
    /* uint16_t — uint8_t wraps at 256 (e.g. all-zero sbox passes incorrectly) */
    uint16_t h0[256], h1[256], h2[256], h3[256];
    memset(h0,0,sizeof(h0)); memset(h1,0,sizeof(h1));
    memset(h2,0,sizeof(h2)); memset(h3,0,sizeof(h3));

    for (int i = 0; i < 256; i++) {
        uint32_t v = sbox[i];
        h0[(uint8_t)(v >> 24)]++;
        h1[(uint8_t)(v >> 16)]++;
        h2[(uint8_t)(v >>  8)]++;
        h3[(uint8_t)(v      )]++;
    }
    for (int b = 0; b < 256; b++) {
        if (h0[b] > 16 || h1[b] > 16 || h2[b] > 16 || h3[b] > 16)
            return FALSE;
    }
    return TRUE;
}

static void log_bf_candidate(FILE *f, int num, const void *addr,
                              const MEMORY_BASIC_INFORMATION *mbi,
                              const uint32_t *dw) {
    log_time(f);
    fprintf(f,
        "\n╔══════════════════════════════════════════╗\n"
        "║  BF_KEY ADAYI #%-3d — BELLEK TARAMA v2    ║\n"
        "╚══════════════════════════════════════════╝\n"
        "  Adres  : %p\n"
        "  Bölge  : %p  [%lu KB]  Tür=%lu\n",
        num, addr,
        mbi->BaseAddress, (unsigned long)(mbi->RegionSize / 1024),
        (unsigned long)mbi->Type);

    /* P-array tam hex (72 byte) */
    log_hex(f, "P-array", (const uint8_t*)dw, BF_P_DWORDS * 4);

    /* TAM S-box'lar (4 × 1024 byte) — Python doğrulama için gerekli */
    log_hex_full(f, "S[0] (1024B)", (const uint8_t*)(dw + BF_P_DWORDS),               1024);
    log_hex_full(f, "S[1] (1024B)", (const uint8_t*)(dw + BF_P_DWORDS + 256),         1024);
    log_hex_full(f, "S[2] (1024B)", (const uint8_t*)(dw + BF_P_DWORDS + 512),         1024);
    log_hex_full(f, "S[3] (1024B)", (const uint8_t*)(dw + BF_P_DWORDS + 768),         1024);

    /* Hızlı imza (verify_key.py için — her S-box'ın ilk 4 dword'u LE) */
    fprintf(f, "  [SIG] S0_0=%08x S1_0=%08x S2_0=%08x S3_0=%08x\n",
            dw[BF_P_DWORDS],
            dw[BF_P_DWORDS + 256],
            dw[BF_P_DWORDS + 512],
            dw[BF_P_DWORDS + 768]);

    /* Tek satır P-array (Python kopyala/yapıştır için) */
    fprintf(f, "  [FULL_KEY] P:");
    for (int i = 0; i < BF_P_DWORDS; i++) fprintf(f, "%08x", dw[i]);
    fprintf(f, "\n");
    fflush(f);
}

/* Forward declarations — run_one_pass bunları tanımlanmadan önce çağırıyor */
static void px_forward_challenge(void);
static void px_forward_key(const uint8_t *bf_key_bytes);

/* Tek geçiş — belirli adres aralığını tara */
static int run_one_pass(FILE *f, int pass_num) {
    /* Limit dolmuşsa hiç başlama */
    if (memscan_is_done()) {
        fprintf(f, "=== GEÇİŞ %d ATLANDI: tarama limiti doldu ===\n\n", pass_num);
        fflush(f);
        return 0;
    }

    int candidates = 0, pages = 0;

    /* Tüm kullanıcı alanı: 1 MB – 2 GB (VMP image bölgelerini de kapsar) */
    uint8_t *scan_lo = (uint8_t *)0x00100000;
    uint8_t *scan_hi = (uint8_t *)0x7FFFFFFF;

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = scan_lo;

    while (addr < scan_hi &&
           VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {

        uint8_t *base = (uint8_t *)mbi.BaseAddress;
        size_t   rsz  = mbi.RegionSize;

        /* Sonraki adres — taşma koruması */
        uint8_t *next = base + rsz;
        if (next <= base) break;

        /*
         * Filtre: commit, R/W veya RWX, Guard değil, boyut uygun.
         *
         * MEM_PRIVATE : heap/stack — önceki sürüm, artık yetersiz
         * MEM_IMAGE   : VMProtect sanallaştırılmış bölgeleri buraya yazar;
         *               oyunun statik Blowfish context'i genellikle burada
         * MEM_MAPPED  : mapped file/section, gerekirse dahil edilebilir
         *
         * MEM_IMAGE için boyut üst sınırı 64 MB (VMP section'lar büyük olabilir).
         */
        BOOL is_private = (mbi.Type == MEM_PRIVATE);
        BOOL is_image   = (mbi.Type == MEM_IMAGE);
        size_t max_rsz  = is_image ? 64u*1024u*1024u : 16u*1024u*1024u;

        if (mbi.State   == MEM_COMMIT                          &&
            (is_private || is_image)                           &&
            (mbi.Protect & (PAGE_READONLY            |
                            PAGE_READWRITE           |
                            PAGE_WRITECOPY           |
                            PAGE_EXECUTE_READ        |
                            PAGE_EXECUTE_READWRITE   |
                            PAGE_EXECUTE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD)                        &&
            rsz         >= (size_t)BF_KEY_SIZE                 &&
            rsz         <= max_rsz) {

            pages++;

            /*
             * Sabit boyutlu tampon — MEM_IMAGE bölgeleri 64 MB'a kadar
             * olabilir ancak tampon hep 16 MB; büyük bölgeleri 16 MB
             * parçalara bölerek tara.
             */
            /* Heap allocation — static buffer causes data race when scan threads run concurrently */
            const size_t CHUNK = 16u * 1024u * 1024u;
            uint8_t *tmp = (uint8_t *)VirtualAlloc(NULL, CHUNK, MEM_COMMIT | MEM_RESERVE,
                                                    PAGE_READWRITE);
            if (!tmp) { addr = next; continue; }

            for (size_t chunk_off = 0; chunk_off < rsz; chunk_off += CHUNK) {
                size_t to_read = rsz - chunk_off;
                if (to_read > CHUNK) to_read = CHUNK;

                SIZE_T copied = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                                       base + chunk_off, tmp, to_read, &copied)
                    || copied < (size_t)BF_KEY_SIZE) {
                    continue;
                }

            for (size_t off = 0; off + BF_KEY_SIZE <= copied; off += 4) {
                const uint32_t *dw = (const uint32_t *)(tmp + off);

                /* Hızlı ön-eleme */
                if (dw[0] == 0) continue;

                /* Bilinen init sabitini reddet */
                if (dw[BF_P_DWORDS] == BF_INIT_S0_0) continue;

                /* Sıkı histogram testi — tüm 4 S-box */
                if (!sbox_strict(dw + BF_P_DWORDS      )) continue;
                if (!sbox_strict(dw + BF_P_DWORDS + 256)) continue;
                if (!sbox_strict(dw + BF_P_DWORDS + 512)) continue;
                if (!sbox_strict(dw + BF_P_DWORDS + 768)) continue;

                candidates++;
                LONG total = InterlockedIncrement(&g_total_candidates);

                /* g_scan_cs ile atomik log yazımı — çoklu thread log karışmasını önler */
                EnterCriticalSection(&g_scan_cs);
                log_bf_candidate(f, (int)total, base + chunk_off + off, &mbi, dw);
                LeaveCriticalSection(&g_scan_cs);

                /* Anahtar adayını WebSocket üzerinden Python proxy'ye ilet */
                px_forward_key((const uint8_t*)dw);
                px_forward_challenge(); /* kayıtlı challenge varsa birlikte gönder */

                /* Limit doldu → tüm taramaları durdur (CAS: sadece bir thread kazanır) */
                if (total >= SCAN_CANDIDATE_LIMIT) {
                    memscan_set_done();
                    log_time(f);
                    fprintf(f,
                        "=== TARAMA LİMİTİ DOLDU (%d aday) — artık tarama yapılmayacak ===\n\n",
                        SCAN_CANDIDATE_LIMIT);
                    fflush(f);
                    VirtualFree(tmp, 0, MEM_RELEASE);
                    return candidates;
                }

                off += BF_KEY_SIZE - 4;  /* örtüşen eşleşmeleri atla */
            }

            /* Chunk sonunda da limit kontrolü */
            if (memscan_is_done()) {
                VirtualFree(tmp, 0, MEM_RELEASE);
                goto pass_done;
            }
        }
            VirtualFree(tmp, 0, MEM_RELEASE);
        }  /* if (mbi.State == MEM_COMMIT ...) */

        /* Bölge sonunda limit kontrolü — büyük bölgeleri de erkenden bırak */
        if (memscan_is_done()) break;
        addr = next;
    }

pass_done:
    log_time(f);
    fprintf(f, "=== GEÇİŞ %d TAMAM: %d sayfa, %d aday (toplam=%ld) ===\n\n",
            pass_num, pages, candidates, (long)g_total_candidates);
    fflush(f);
    return candidates;
}

static DWORD WINAPI scan_thread(LPVOID param) {
    (void)param;

    /*
     * Genişletilmiş tarama takvimi:
     *   GEÇİŞ 1 : 200 ms   — mümkün olan en erken
     *   GEÇİŞ 2 : 1000 ms  — login key penceresi
     *   GEÇİŞ 3 : 3000 ms  — handshake gecikmesi
     *   GEÇİŞ 4 : 6000 ms  — game server key
     *   GEÇİŞ 5 : 12000 ms — yedek (sunucu geç cevaplayabilir)
     *   GEÇİŞ 6 : 20000 ms — son şans
     */
    static const DWORD delays[] = {200, 1000, 3000, 6000, 12000, 20000};
    static const int   NPASS    = 6;

    for (int pass = 0; pass < NPASS; pass++) {
        /* Hem bekleme hem erken çıkış: DLL kaldırılırsa shutdown sinyali gelir */
        if (g_scan_shutdown) {
            DWORD wr = WaitForSingleObject(g_scan_shutdown, delays[pass]);
            if (wr == WAIT_OBJECT_0 || wr == WAIT_FAILED) break;
        } else {
            Sleep(delays[pass]);
        }

        /* Bekleme sırasında limit dolmuşsa kalan geçişleri atla */
        if (memscan_is_done()) {
            if (g_log_crypto) {
                log_time(g_log_crypto);
                fprintf(g_log_crypto,
                    "=== scan_thread: limit dolu, GEÇİŞ %d..%d atlanıyor ===\n\n",
                    pass + 1, NPASS);
                fflush(g_log_crypto);
            }
            break;
        }

        FILE *f = g_log_crypto;
        FILE *fb = NULL;
        if (!f) {
            char path[MAX_PATH];
            make_temp_log_path(path, "pb_key_fallback.log");
            fb = fopen(path, "a");
            f = fb;
        }
        if (!f) continue;

        log_time(f);
        fprintf(f, "\n=== BELLEK TARAMASI v2 — GEÇİŞ %d (t+%lums) ===\n",
                pass + 1, (unsigned long)delays[pass]);
        fflush(f);

        run_one_pass(f, pass + 1);

        if (fb) { fclose(fb); fb = NULL; }
    }

    InterlockedExchange(&g_scan_running, 0);
    return 0;
}

/* Anında (0-delay) tek tarama — recv/send/connect hook'tan tetiklenir */
static DWORD WINAPI immediate_scan_thread(LPVOID param) {
    (void)param;

    /* Limit dolmuşsa hiç çalışma */
    if (memscan_is_done()) return 0;

    FILE *f = g_log_crypto;
    FILE *fb = NULL;
    if (!f) {
        char path[MAX_PATH];
        make_temp_log_path(path, "pb_key_fallback.log");
        fb = fopen(path, "a");
        f = fb;
    }
    if (f) {
        log_time(f);
        fprintf(f, "\n=== BELLEK TARAMASI v2 — ANİ TARAMA (recv hook) ===\n");
        fflush(f);
        run_one_pass(f, 99);
        if (fb) { fclose(fb); }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════
 *  PYTHON PROXY — WinHTTP WebSocket Köprüsü
 *  pb_proxy.cfg → server_url=wss://HOST/dll
 *  DLL → Python: tüm GAME_PORT paketleri iletilir
 *  Python → DLL: inject komutu alınır ve oyuna gönderilir
 * ══════════════════════════════════════════════════════ */

/* Frame başlık boyutu: type(1) dir(1) len_le32(4) = 6 bayt */
#define PX_HDR          6
#define PX_TYPE_PKT       0x50u   /* 'P' — paket bildirimi (DLL → Python) */
#define PX_TYPE_INJ       0x49u   /* 'I' — inject komutu  (Python → DLL)  */
#define PX_TYPE_KEY       0x4Bu   /* 'K' — BF_KEY frame   (DLL → Python)  */
#define PX_TYPE_CHALLENGE 0x43u   /* 'C' — challenge frame (DLL → Python)  */
#define PX_DIR_RECV       0x52u   /* 'R' — sunucudan gelen (recv)          */
#define PX_DIR_SEND       0x53u   /* 'S' — sunucuya giden  (send)          */

/* ── Kayıtlı challenge (202 byte, 0xc5) ── */
#define CHALLENGE_SIZE  202
static uint8_t       g_saved_challenge[CHALLENGE_SIZE];
static volatile LONG g_saved_challenge_len = 0;
static volatile LONG g_challenge_forwarded  = 0;

/* ── Kayıtlı BF_KEY — bağlantı kurulunca hemen yeniden gönderilir ── */
static uint8_t       g_saved_key[BF_KEY_SIZE]; /* BF_KEY_SIZE = 4168 byte */
static volatile LONG g_saved_key_valid = 0;

/* ── Key-ready event — px_thread_fn bu eventi bekleyip SONRA bağlanır ──
 * Oyun login/sunucu-seçim ekranı geçildikten sonra WS bağlantısı yapılır;
 * bu sayede WinHTTP handshake kritik oyun aşamasıyla çakışmaz.           */
static HANDLE        g_px_key_event   = NULL;

/* ── Config ── */
static wchar_t       g_px_host[512]  = {0};
static INTERNET_PORT g_px_port       = INTERNET_DEFAULT_HTTPS_PORT;
static wchar_t       g_px_path[256]  = {L"/dll"};
static BOOL          g_px_tls        = TRUE;
static BOOL          g_px_enabled    = FALSE;

/* ── Runtime ── */
static volatile LONG g_px_stop       = 0;
static volatile LONG g_px_ready      = 0;
static HINTERNET     g_px_ws         = NULL;
static CRITICAL_SECTION g_px_cs;
static BOOL          g_px_cs_ok      = FALSE;
static HANDLE        g_px_thread     = NULL;

/* ── Send Queue (hook thread'leri WinHTTP'ye dokunmaz; sadece enqueue yapar) ──
 * px_send_thread_fn tek başına WinHttpWebSocketSend çağırır → race yok.     */
#define PXQ_SLOTS  256
typedef struct { uint8_t *data; DWORD len; } PxQItem;
static PxQItem          g_pxq[PXQ_SLOTS];
static volatile LONG    g_pxq_w       = 0;   /* üretici yazar  */
static volatile LONG    g_pxq_r       = 0;   /* tüketici okur  */
static HANDLE           g_pxq_sem     = NULL; /* sayaçlı semafor */
static CRITICAL_SECTION g_pxq_cs;
static BOOL             g_pxq_cs_ok   = FALSE;

/* ── Oyun soketi halkası (inject için) ── */
#define PX_MAX_GS  4
static SOCKET        g_px_gs[PX_MAX_GS];
static int           g_px_gs_head    = 0;
static CRITICAL_SECTION g_px_gs_cs;
static BOOL          g_px_gs_cs_ok   = FALSE;

/* ─────────────────────────────────────────────────── */

static BOOL px_read_cfg(void) {
    char fpath[MAX_PATH];
    make_path(fpath, "pb_proxy.cfg");
    FILE *f = fopen(fpath, "r");
    if (!f) return FALSE;

    char line[1024];
    BOOL found = FALSE;
    while (fgets(line, sizeof(line), f) && !found) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\r' || *p == '\n' || !*p) continue;
        if (strncmp(p, "server_url=", 11) != 0) continue;

        char url[512] = {0};
        strncpy(url, p + 11, sizeof(url) - 1);
        for (int i = (int)strlen(url)-1; i >= 0; i--) {
            if (url[i]=='\r'||url[i]=='\n'||url[i]==' ') url[i]=0; else break;
        }

        char *host_start = url;
        if      (strncmp(url,"wss://",6)==0){g_px_tls=TRUE; host_start=url+6; g_px_port=INTERNET_DEFAULT_HTTPS_PORT;}
        else if (strncmp(url,"ws://", 5)==0){g_px_tls=FALSE;host_start=url+5; g_px_port=INTERNET_DEFAULT_HTTP_PORT;}

        char host_a[256]={0}, path_a[256]="/dll";
        char *slash = strchr(host_start, '/');
        if (slash) {
            size_t hl = (size_t)(slash - host_start);
            if (hl >= sizeof(host_a)) hl = sizeof(host_a)-1;
            memcpy(host_a, host_start, hl);
            snprintf(path_a, sizeof(path_a), "%s", slash);
        } else {
            strncpy(host_a, host_start, sizeof(host_a)-1);
        }
        /* Port override: host:PORT */
        char *colon = strrchr(host_a, ':');
        if (colon) { *colon = 0; g_px_port = (INTERNET_PORT)atoi(colon+1); }

        MultiByteToWideChar(CP_UTF8,0,host_a,-1,g_px_host,512);
        MultiByteToWideChar(CP_UTF8,0,path_a,-1,g_px_path,256);
        found = TRUE;
    }
    fclose(f);
    return found;
}

/* Oyun soketini takip et */
static void px_track(SOCKET s) {
    if (!g_px_gs_cs_ok || s == INVALID_SOCKET) return;
    EnterCriticalSection(&g_px_gs_cs);
    for (int i = 0; i < PX_MAX_GS; i++) if (g_px_gs[i]==s) goto done;
    g_px_gs[g_px_gs_head] = s;
    g_px_gs_head = (g_px_gs_head+1) % PX_MAX_GS;
done:
    LeaveCriticalSection(&g_px_gs_cs);
}

/* En son oyun soketini döndür */
static SOCKET px_gsock(void) {
    if (!g_px_gs_cs_ok) return INVALID_SOCKET;
    EnterCriticalSection(&g_px_gs_cs);
    SOCKET ret = g_px_gs[(g_px_gs_head-1+PX_MAX_GS) % PX_MAX_GS];
    LeaveCriticalSection(&g_px_gs_cs);
    return ret;
}

/* Paketi Python proxy'ye ilet (thread-safe) */
/* ── Send queue yardımcıları ── */

/* buf sahipliğini kuyruğa devreder; kuyruk doluysa serbest bırakır. */
static void px_enqueue(uint8_t *buf, DWORD len) {
    if (!g_pxq_cs_ok || !g_pxq_sem || !buf) { free(buf); return; }
    EnterCriticalSection(&g_pxq_cs);
    LONG w    = g_pxq_w;
    LONG next = (w + 1) % PXQ_SLOTS;
    if (next == g_pxq_r) {
        /* Kuyruk dolu — yeni frame'i düşür */
        LeaveCriticalSection(&g_pxq_cs);
        free(buf);
        return;
    }
    g_pxq[w].data = buf;
    g_pxq[w].len  = len;
    g_pxq_w = next;
    LeaveCriticalSection(&g_pxq_cs);
    ReleaseSemaphore(g_pxq_sem, 1, NULL);
}

/* Paketi kuyruğa ekle (hook thread'lerinden çağrılır, WinHTTP'ye dokunmaz) */
static void px_forward(uint8_t dir, const uint8_t *data, int len) {
    if (!data || len <= 0) return;
    if (!InterlockedCompareExchange(&g_px_ready, 0, 0)) return;
    uint8_t *buf = (uint8_t*)malloc(PX_HDR + len);
    if (!buf) return;
    uint32_t u32 = (uint32_t)len;
    buf[0] = PX_TYPE_PKT; buf[1] = dir;
    memcpy(buf+2, &u32, 4);
    memcpy(buf+6, data, len);
    px_enqueue(buf, (DWORD)(PX_HDR + len));
}

/* Kayıtlı challenge paketini kuyruğa ekle (0x43 'C' frame) */
static void px_forward_challenge(void) {
    if (InterlockedCompareExchange(&g_saved_challenge_len, 0, 0) < CHALLENGE_SIZE) return;
    /* CAS: 0→1 başarılıysa biz göndeririz; aksi halde zaten gönderilmiş */
    if (InterlockedCompareExchange(&g_challenge_forwarded, 1, 0) != 0) return;
    if (!InterlockedCompareExchange(&g_px_ready, 0, 0)) {
        InterlockedExchange(&g_challenge_forwarded, 0); return;
    }
    const DWORD clen = (DWORD)CHALLENGE_SIZE;
    uint8_t *buf = (uint8_t*)malloc(PX_HDR + clen);
    if (!buf) { InterlockedExchange(&g_challenge_forwarded, 0); return; }
    buf[0] = PX_TYPE_CHALLENGE; buf[1] = PX_DIR_RECV;
    memcpy(buf+2, &clen, 4);
    /* g_saved_challenge'ı okumak için g_px_cs yeterli değil; ayrı CS kullanıyoruz */
    EnterCriticalSection(&g_px_cs);
    memcpy(buf+6, g_saved_challenge, clen);
    LeaveCriticalSection(&g_px_cs);
    px_enqueue(buf, (DWORD)(PX_HDR + clen));
}

/* Blowfish anahtarını Python proxy'ye ilet (BF_KEY_SIZE = 4168 byte) */
static volatile LONG g_key_forwarded = 0;   /* her bağlantıda bir kez gönder */

static void px_forward_key(const uint8_t *bf_key_bytes) {
    if (!bf_key_bytes) return;
    /* Anahtarı sakla + key-ready event'ını sinyal ver (bağlantı hâlâ yok olsa bile) */
    EnterCriticalSection(&g_px_cs);
    memcpy(g_saved_key, bf_key_bytes, BF_KEY_SIZE);
    LeaveCriticalSection(&g_px_cs);
    InterlockedExchange(&g_saved_key_valid, 1);
    if (g_px_key_event) SetEvent(g_px_key_event); /* px_thread_fn'i uyandır */

    /* Bağlantı zaten kurulmuşsa kuyruğa ekle */
    if (!InterlockedCompareExchange(&g_px_ready, 0, 0)) return;
    const DWORD klen = (DWORD)BF_KEY_SIZE;
    uint8_t *buf = (uint8_t*)malloc(PX_HDR + klen);
    if (!buf) return;
    buf[0] = PX_TYPE_KEY; buf[1] = 0;
    memcpy(buf+2, &klen, 4);
    memcpy(buf+6, bf_key_bytes, klen);
    px_enqueue(buf, (DWORD)(PX_HDR + klen));
}

/* ── Send thread: kuyruğu boşalt, WinHttpWebSocketSend'i tek thread'den çağır ── */
typedef struct { HINTERNET ws; volatile LONG stop; } PxSendCtx;

static DWORD WINAPI px_send_thread_fn(LPVOID param) {
    PxSendCtx *ctx = (PxSendCtx*)param;
    while (!InterlockedCompareExchange(&ctx->stop, 0, 0) &&
           !InterlockedCompareExchange(&g_px_stop,  0, 0)) {
        DWORD w = WaitForSingleObject(g_pxq_sem, 200);
        if (w == WAIT_TIMEOUT) continue;
        if (w != WAIT_OBJECT_0) break;

        /* Dequeue */
        EnterCriticalSection(&g_pxq_cs);
        LONG r      = g_pxq_r;
        uint8_t *data = g_pxq[r].data;
        DWORD    len  = g_pxq[r].len;
        g_pxq[r].data = NULL;
        g_pxq_r = (r + 1) % PXQ_SLOTS;
        LeaveCriticalSection(&g_pxq_cs);

        if (data) {
            WinHttpWebSocketSend(ctx->ws,
                WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                data, len);
            free(data);
        }
    }
    /* Kalan frame'leri temizle */
    EnterCriticalSection(&g_pxq_cs);
    while (g_pxq_r != g_pxq_w) {
        free(g_pxq[g_pxq_r].data);
        g_pxq[g_pxq_r].data = NULL;
        g_pxq_r = (g_pxq_r + 1) % PXQ_SLOTS;
    }
    LeaveCriticalSection(&g_pxq_cs);
    return 0;
}

/* Proxy thread: bağlan, inject komutlarını oku, kopar → tekrar bağlan */
static DWORD WINAPI px_upload_thread_fn(LPVOID param); /* forward decl */

static DWORD WINAPI px_thread_fn(LPVOID param) {
    (void)param;

    /* Anahtar bulunana kadar bekle — oyun login/sunucu ekranı geçildikten
     * SONRA bağlantı kur; WinHTTP handshake kritik aşamayla çakışmaz.   */
    if (g_px_key_event) {
        if (g_log_net) {
            log_time(g_log_net);
            fprintf(g_log_net,
                "PROXY: BF_KEY bekleniyor — key gelince WS bağlantısı başlayacak\n");
            fflush(g_log_net);
        }
        /* g_px_stop sinyal verirse de çık */
        HANDLE wait_h[2] = { g_px_key_event, g_scan_shutdown };
        WaitForMultipleObjects(2, wait_h, FALSE, INFINITE);
        if (InterlockedCompareExchange(&g_px_stop, 0, 0)) return 0;
    }

    if (g_log_net) {
        log_time(g_log_net);
        fprintf(g_log_net, "PROXY: BF_KEY alındı — WS bağlantısı başlıyor\n");
        fflush(g_log_net);
    }

    while (!InterlockedCompareExchange(&g_px_stop,0,0)) {

        HINTERNET sess = WinHttpOpen(
            L"PBProxy/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!sess) { Sleep(3000); continue; }

        HINTERNET conn = WinHttpConnect(sess, g_px_host, g_px_port, 0);
        if (!conn) { WinHttpCloseHandle(sess); Sleep(3000); continue; }

        DWORD rf = g_px_tls ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET req = WinHttpOpenRequest(
            conn, L"GET", g_px_path,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, rf);
        if (!req) {
            WinHttpCloseHandle(conn); WinHttpCloseHandle(sess);
            Sleep(3000); continue;
        }

        /* TLS sertifika doğrulama (self-signed / dev domain için gevşet) */
        if (g_px_tls) {
            DWORD sf = SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
                      |SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                      |SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                      |SECURITY_FLAG_IGNORE_UNKNOWN_CA;
            WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &sf, sizeof(sf));
        }

        BOOL ok =
            WinHttpSetOption(req, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0) &&
            WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(req, NULL);

        if (!ok) {
            WinHttpCloseHandle(req);
            WinHttpCloseHandle(conn); WinHttpCloseHandle(sess);
            Sleep(3000); continue;
        }

        HINTERNET ws = WinHttpWebSocketCompleteUpgrade(req, 0);
        WinHttpCloseHandle(req);

        if (!ws) {
            WinHttpCloseHandle(conn); WinHttpCloseHandle(sess);
            Sleep(3000); continue;
        }

        /* Hazır — global'a yaz */
        EnterCriticalSection(&g_px_cs);
        g_px_ws = ws;
        LeaveCriticalSection(&g_px_cs);
        InterlockedExchange(&g_px_ready, 1);
        /* Yeniden bağlanmada anahtarın tekrar gönderilmesi için sıfırla */
        InterlockedExchange(&g_key_forwarded, 0);
        InterlockedExchange(&g_challenge_forwarded, 0);
        /* Kayıtlı key varsa hemen kuyruğa ekle */
        if (InterlockedCompareExchange(&g_saved_key_valid, 0, 0)) {
            const DWORD klen = (DWORD)BF_KEY_SIZE;
            uint8_t *kbuf = (uint8_t*)malloc(PX_HDR + klen);
            if (kbuf) {
                kbuf[0] = PX_TYPE_KEY; kbuf[1] = 0;
                memcpy(kbuf+2, &klen, 4);
                EnterCriticalSection(&g_px_cs);
                memcpy(kbuf+6, g_saved_key, klen);
                LeaveCriticalSection(&g_px_cs);
                px_enqueue(kbuf, (DWORD)(PX_HDR + klen));
            }
        }
        px_forward_challenge(); /* kayıtlı challenge varsa yeniden bağlantıda hemen gönder */

        /* Send thread başlat — sadece bu thread WinHttpWebSocketSend çağırır */
        PxSendCtx sctx; sctx.ws = ws; sctx.stop = 0;
        HANDLE send_th = CreateThread(NULL, 0, px_send_thread_fn, &sctx, 0, NULL);

        /* Log dosyalarını ayrı thread'de yükle (WebSocket receive loop'unu bloklamamak için) */
        HANDLE upt = CreateThread(NULL, 0, px_upload_thread_fn, NULL, 0, NULL);
        if (upt) CloseHandle(upt);

        if (g_log_net) {
            log_time(g_log_net);
            fprintf(g_log_net,
                "PROXY: *** WebSocket bağlandı → %ls:%u%ls ***\n",
                g_px_host, (unsigned)g_px_port, g_px_path);
            fflush(g_log_net);
        }

        /* Receive loop — inject komutlarını bekle */
        uint8_t rxbuf[65540];
        while (!InterlockedCompareExchange(&g_px_stop,0,0)) {
            DWORD nread = 0;
            WINHTTP_WEB_SOCKET_BUFFER_TYPE btype;
            DWORD r = WinHttpWebSocketReceive(
                ws, rxbuf, sizeof(rxbuf), &nread, &btype);
            if (r != ERROR_SUCCESS) break;
            if (btype != WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) continue;
            if (nread < PX_HDR) continue;

            /* Inject frame: [0x49][0x00][4B len LE][ciphertext] */
            if (rxbuf[0] == PX_TYPE_INJ) {
                uint32_t dlen;
                memcpy(&dlen, rxbuf+2, 4);
                if (dlen > 0 && dlen <= nread - PX_HDR && d_send.installed) {
                    SOCKET gs = px_gsock();
                    if (gs != INVALID_SOCKET)
                        ((fn_send_t)d_send.orig_fn)(
                            gs, (const char*)(rxbuf+PX_HDR), (int)dlen, 0);
                }
            }
        }

        /* Send thread'i durdur — WinHTTP handle'ları kapatmadan ÖNCE */
        InterlockedExchange(&g_px_ready, 0);
        InterlockedExchange(&sctx.stop, 1);
        if (g_pxq_sem) ReleaseSemaphore(g_pxq_sem, 1, NULL); /* uyandır */
        if (send_th) { WaitForSingleObject(send_th, 3000); CloseHandle(send_th); }

        /* Temizlik */
        EnterCriticalSection(&g_px_cs);
        g_px_ws = NULL;
        LeaveCriticalSection(&g_px_cs);
        WinHttpWebSocketClose(ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
        WinHttpCloseHandle(ws);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);

        if (g_log_net) {
            log_time(g_log_net);
            fprintf(g_log_net, "PROXY: WebSocket bağlantısı kesildi\n");
            fflush(g_log_net);
        }
        if (!InterlockedCompareExchange(&g_px_stop,0,0)) Sleep(3000);
    }
    return 0;
}

/* ── Log dosyası HTTP POST upload (temp'ten oku, upload sonrası sil) ────────── */
static void px_upload_log(const char *filename) {
    char fpath[MAX_PATH];
    make_temp_log_path(fpath, filename);
    FILE *f = fopen(fpath, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > 32 * 1024 * 1024) { fclose(f); return; }

    uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
    if (!buf) { fclose(f); return; }
    if ((long)fread(buf, 1, (size_t)fsize, f) != fsize) { free(buf); fclose(f); return; }
    fclose(f);

    HINTERNET sess = WinHttpOpen(L"PBProxy/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sess) { free(buf); return; }

    HINTERNET conn = WinHttpConnect(sess, g_px_host, g_px_port, 0);
    if (!conn) { WinHttpCloseHandle(sess); free(buf); return; }

    DWORD rf = g_px_tls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", L"/log_upload",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, rf);
    if (!req) { WinHttpCloseHandle(conn); WinHttpCloseHandle(sess); free(buf); return; }

    if (g_px_tls) {
        DWORD sf = SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
                  |SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                  |SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                  |SECURITY_FLAG_IGNORE_UNKNOWN_CA;
        WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &sf, sizeof(sf));
    }

    wchar_t hdr[256];
    swprintf(hdr, 256, L"X-Log-Name: %S\r\nContent-Type: application/octet-stream\r\n", filename);
    BOOL sent = WinHttpSendRequest(req, hdr, (DWORD)-1L,
                                   buf, (DWORD)fsize, (DWORD)fsize, 0);
    BOOL recvd = sent ? WinHttpReceiveResponse(req, NULL) : FALSE;

    /* HTTP durum kodunu kontrol et — sadece 2xx ise başarılı say */
    BOOL upload_ok = FALSE;
    if (recvd) {
        DWORD status = 0, status_len = sizeof(status);
        if (WinHttpQueryHeaders(req,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_len,
                WINHTTP_NO_HEADER_INDEX)) {
            upload_ok = (status >= 200 && status < 300);
        }
    }

    if (g_log_net) {
        log_time(g_log_net);
        if (upload_ok)
            fprintf(g_log_net, "UPLOAD OK: %s — %ld bayt\n", filename, fsize);
        else
            fprintf(g_log_net, "UPLOAD FAIL: %s — %ld bayt (sunucu yanıtı alınamadı)\n",
                    filename, fsize);
        fflush(g_log_net);
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(sess);
    free(buf);

    /* Dosyalar %TEMP%\PBProxy\ altında, DLL yeniden başlayınca "w" moduyla
     * sıfırlanıyor — silmeye gerek yok, açık handle ile çakışır */
    (void)upload_ok;
}

static DWORD WINAPI px_upload_thread_fn(LPVOID param) {
    (void)param;
    /* WebSocket bağlantısı kurulduktan sonra log dosyalarını gönder */
    Sleep(500); /* log dosyalarının kapanıp flush edilmesi için kısa bekleme */
    px_upload_log("pb_crypto.log");
    px_upload_log("pb_net.log");
    px_upload_log("pb_plain.log");
    return 0;
}

static void px_init(void) {
    if (!g_px_enabled || !g_px_cs_ok) return;
    InitializeCriticalSection(&g_px_gs_cs);
    g_px_gs_cs_ok = TRUE;
    memset(g_px_gs, 0xFF, sizeof(g_px_gs));  /* INVALID_SOCKET */
    g_px_thread = CreateThread(NULL, 0, px_thread_fn, NULL, 0, NULL);
    if (g_log_net) {
        log_time(g_log_net);
        fprintf(g_log_net,
            "PROXY: thread başlatıldı → %ls:%u%ls\n",
            g_px_host, (unsigned)g_px_port, g_px_path);
        fflush(g_log_net);
    }
}

static void px_shutdown(void) {
    InterlockedExchange(&g_px_stop, 1);
    /* px_thread_fn key event'ını bekliyorsa uyandır */
    if (g_px_key_event) SetEvent(g_px_key_event);
    /* WS kapatılırsa receive loop hata döner, thread çıkar */
    EnterCriticalSection(&g_px_cs);
    HINTERNET ws = g_px_ws; g_px_ws = NULL;
    LeaveCriticalSection(&g_px_cs);
    if (ws) WinHttpWebSocketClose(
        ws, WINHTTP_WEB_SOCKET_ABORTED_CLOSE_STATUS, NULL, 0);
    if (g_px_thread) {
        WaitForSingleObject(g_px_thread, 3000);
        CloseHandle(g_px_thread);
        g_px_thread = NULL;
    }
    if (g_px_cs_ok)    { DeleteCriticalSection(&g_px_cs);    g_px_cs_ok    = FALSE; }
    if (g_px_gs_cs_ok) { DeleteCriticalSection(&g_px_gs_cs); g_px_gs_cs_ok = FALSE; }
    /* Send queue temizlik */
    if (g_pxq_sem) {
        /* Kalan frame'leri serbest bırak */
        if (g_pxq_cs_ok) {
            EnterCriticalSection(&g_pxq_cs);
            while (g_pxq_r != g_pxq_w) {
                free(g_pxq[g_pxq_r].data);
                g_pxq[g_pxq_r].data = NULL;
                g_pxq_r = (g_pxq_r + 1) % PXQ_SLOTS;
            }
            LeaveCriticalSection(&g_pxq_cs);
        }
        CloseHandle(g_pxq_sem); g_pxq_sem = NULL;
    }
    if (g_pxq_cs_ok) { DeleteCriticalSection(&g_pxq_cs); g_pxq_cs_ok = FALSE; }
    if (g_px_key_event) { CloseHandle(g_px_key_event); g_px_key_event = NULL; }
}

/* ══════════════════════════════════════════════════════ */

/* Oyun sunucusuna bağlanınca taramayı bir kere tetikle */
static void trigger_memscan(void) {
    if (InterlockedCompareExchange(&g_scan_triggered, 1, 0) == 0) {
        InterlockedExchange(&g_scan_running, 1);
        /* Handle'ı kapat MA — detach sırasında join için sakla */
        HANDLE t = CreateThread(NULL, 0, scan_thread, NULL, 0, NULL);
        if (t) g_scan_thread = t;
        else   InterlockedExchange(&g_scan_running, 0);
    }
}

/* ── HOOK: connect ── */
static int WINAPI hook_connect(SOCKET s,
                                const struct sockaddr *name, int namelen) {
    if (g_log_net) {
        char addr[64];
        addr_str(name, addr, sizeof(addr));
        log_time(g_log_net);
        fprintf(g_log_net, "connect  → %s  sock=%llu\n",
                addr, (unsigned long long)s);
        fflush(g_log_net);
    }

    /* Oyun sunucusu portlarında tarama başlat (443/53/80 değil) */
    if (name && name->sa_family == AF_INET) {
        uint16_t port = ntohs(((const struct sockaddr_in *)name)->sin_port);
        if (port != 80 && port != 443 && port != 53 && port > 1024) {
            ensure_init();
            trigger_memscan();  /* gecikmeli (t+200ms) tarama */
        }
            /* Oyun soketini proxy için takip et */
        if (port == GAME_PORT) px_track(s);

        /* Port 39190: key exchange connect() SONRASI hemen gerçekleşir —
         * recv hook'tan önce anında tarama başlat */
        if (port == GAME_PORT && !memscan_is_done()) {
            if (g_log_crypto) {
                log_time(g_log_crypto);
                fprintf(g_log_crypto,
                    "*** GAME PORT %u CONNECT — ANINDA TARAMA (connect hook) ***\n",
                    GAME_PORT);
                fflush(g_log_crypto);
            }
            HANDLE t = CreateThread(NULL, 0, immediate_scan_thread, NULL, 0, NULL);
            if (t) {
                LONG idx = InterlockedIncrement(&g_imm_thread_cnt) - 1;
                if (idx < MAX_IMM_THREADS) g_imm_threads[idx] = t;
                else CloseHandle(t);
            }
        }
    }

    return ((fn_connect_t)d_connect.orig_fn)(s, name, namelen);
}

/* ── HOOK: send (TCP) ── */
static int WINAPI hook_send(SOCKET s, const char *buf, int len, int flags) {
    int ret = ((fn_send_t)d_send.orig_fn)(s, buf, len, flags);

    /* İlk 2 game-server send'de anında tarama — key, send() çağrısından
     * ÖNCE kurulmuş olması ZORUNLU (şifreli veri hazır). Bu en güvenilir
     * tarama noktasıdır. */
    if (ret > 0) {
        struct sockaddr_in sa; int sl = sizeof(sa);
        if (getpeername(s, (struct sockaddr*)&sa, &sl) == 0) {
            uint16_t port = ntohs(sa.sin_port);
            if (port == GAME_PORT && !memscan_is_done()) {
                LONG cnt = InterlockedIncrement(&g_send_scan_count);
                if (cnt <= 2) {
                    if (g_log_crypto) {
                        log_time(g_log_crypto);
                        fprintf(g_log_crypto,
                            "*** GAME PORT %u SEND #%ld — ANINDA TARAMA (send hook) ***\n",
                            GAME_PORT, (long)cnt);
                        fflush(g_log_crypto);
                    }
                    HANDLE t = CreateThread(NULL, 0, immediate_scan_thread, NULL, 0, NULL);
                    if (t) {
                        LONG idx = InterlockedIncrement(&g_imm_thread_cnt) - 1;
                        if (idx < MAX_IMM_THREADS) g_imm_threads[idx] = t;
                        else CloseHandle(t);
                    }
                }
            }
        }
    }

    if (ret > 0) {
        struct sockaddr_in sa2; int sl2 = sizeof(sa2);
        if (getpeername(s,(struct sockaddr*)&sa2,&sl2)==0
            && ntohs(sa2.sin_port)==GAME_PORT) {
            px_track(s);
            px_forward(PX_DIR_SEND, (const uint8_t*)buf, ret);
        }
    }

    if (g_log_net && ret > 0) {
        char peer[64];
        socket_peer(s, peer, sizeof(peer));
        log_time(g_log_net);
        fprintf(g_log_net, "TCP SEND → %-22s  bf_calls=%ld  ",
                peer, (long)g_bf_export_calls);
        log_hex(g_log_net, "", (const unsigned char*)buf, ret);
        fflush(g_log_net);
    }
    return ret;
}

/* ── HOOK: recv (TCP) ── */
static int WINAPI hook_recv(SOCKET s, char *buf, int len, int flags) {
    int ret = ((fn_recv_t)d_recv.orig_fn)(s, buf, len, flags);
    if (ret > 0) {
        /* Game server recv → anında bellek taraması (sadece bir kez) */
        char peer[64];
        socket_peer(s, peer, sizeof(peer));

        /* "31.169.73." veya port 39190 kontrolü */
        struct sockaddr_in sa; int sl = sizeof(sa);
        if (getpeername(s, (struct sockaddr*)&sa, &sl) == 0) {
            uint16_t port = ntohs(sa.sin_port);
            if (port == GAME_PORT) {
                /* İlk 3 game-server recv'de anında tarama yap — limit dolmamışsa */
                LONG cnt = InterlockedIncrement(&g_recv_scan_count);
                if (cnt <= 3 && !memscan_is_done()) {
                    HANDLE t = CreateThread(NULL, 0, immediate_scan_thread, NULL, 0, NULL);
                    if (t) {
                        /* Store handle for safe join at DLL_PROCESS_DETACH */
                        LONG idx = InterlockedIncrement(&g_imm_thread_cnt) - 1;
                        if (idx < MAX_IMM_THREADS) g_imm_threads[idx] = t;
                        else CloseHandle(t);
                    }
                }
                if (cnt == 1) {
                    InterlockedExchange(&g_game_socket_seen, 1);
                    if (g_log_crypto) {
                        log_time(g_log_crypto);
                        fprintf(g_log_crypto,
                            "*** PORT %u RECV ALGILANDI — ANI TARAMA TETIKLENIYOR ***\n",
                            GAME_PORT);
                        fflush(g_log_crypto);
                    }
                }
            }
        }

        /* Proxy'ye ilet */
        {
            struct sockaddr_in sa2; int sl2 = sizeof(sa2);
            if (getpeername(s,(struct sockaddr*)&sa2,&sl2)==0
                && ntohs(sa2.sin_port)==GAME_PORT) {
                px_forward(PX_DIR_RECV, (const uint8_t*)buf, ret);
                /* Challenge tespiti: 202B, 0xc5 başlangıcı → kaydet ve ilet.
                 * g_px_cs ile koru: px_forward_challenge() da aynı CS ile okur. */
                if (ret == CHALLENGE_SIZE && (uint8_t)buf[0] == 0xc5) {
                    EnterCriticalSection(&g_px_cs);
                    memcpy(g_saved_challenge, buf, CHALLENGE_SIZE);
                    LeaveCriticalSection(&g_px_cs);
                    InterlockedExchange(&g_saved_challenge_len, CHALLENGE_SIZE);
                    InterlockedExchange(&g_challenge_forwarded, 0);
                    px_forward_challenge(); /* WS hazırsa hemen gönder */
                }
            }
        }

        if (g_log_net) {
            log_time(g_log_net);
            fprintf(g_log_net, "TCP RECV ← %-22s  bf_calls=%ld  ",
                    peer, (long)g_bf_export_calls);
            log_hex(g_log_net, "", (const unsigned char*)buf, ret);
            fflush(g_log_net);
        }
    }
    return ret;
}

/* ── HOOK: sendto (UDP) ── */
static int WINAPI hook_sendto(SOCKET s, const char *buf, int len, int flags,
                               const struct sockaddr *to, int tolen) {
    int ret = ((fn_sendto_t)d_sendto.orig_fn)(s, buf, len, flags, to, tolen);
    if (g_log_net && ret > 0) {
        char addr[64];
        addr_str(to, addr, sizeof(addr));
        log_time(g_log_net);
        fprintf(g_log_net, "UDP SEND → %-22s  ", addr);
        log_hex(g_log_net, "", (const unsigned char*)buf, ret);
        fflush(g_log_net);
    }
    return ret;
}

/* ── HOOK: recvfrom (UDP) ── */
static int WINAPI hook_recvfrom(SOCKET s, char *buf, int len, int flags,
                                 struct sockaddr *from, int *fromlen) {
    int ret = ((fn_recvfrom_t)d_recvfrom.orig_fn)(
                  s, buf, len, flags, from, fromlen);
    if (g_log_net && ret > 0) {
        char addr[64];
        addr_str(from, addr, sizeof(addr));
        log_time(g_log_net);
        fprintf(g_log_net, "UDP RECV ← %-22s  ", addr);
        log_hex(g_log_net, "", (const unsigned char*)buf, ret);
        fflush(g_log_net);
    }
    return ret;
}

/* ── HOOK: WSASend ── */
static int WINAPI hook_WSASend(SOCKET s, LPWSABUF bufs, DWORD count,
                                LPDWORD sent, DWORD flags,
                                LPWSAOVERLAPPED ov,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE cb) {
    int ret = ((fn_WSASend_t)d_WSASend.orig_fn)(
                  s, bufs, count, sent, flags, ov, cb);
    if (g_log_net) {
        char peer[64];
        socket_peer(s, peer, sizeof(peer));
        for (DWORD i = 0; i < count; i++) {
            if (bufs[i].len > 0 && bufs[i].buf) {
                log_time(g_log_net);
                fprintf(g_log_net, "WSASend  → %-22s  buf[%lu]  ", peer, i);
                log_hex(g_log_net, "", (const unsigned char*)bufs[i].buf,
                        (int)bufs[i].len);
            }
        }
        fflush(g_log_net);
    }
    return ret;
}

/* ── HOOK: WSARecv ── */
static int WINAPI hook_WSARecv(SOCKET s, LPWSABUF bufs, DWORD count,
                                LPDWORD recvd, LPDWORD flags,
                                LPWSAOVERLAPPED ov,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE cb) {
    int ret = ((fn_WSARecv_t)d_WSARecv.orig_fn)(
                  s, bufs, count, recvd, flags, ov, cb);
    if (g_log_net && ret == 0) {
        char peer[64];
        socket_peer(s, peer, sizeof(peer));
        for (DWORD i = 0; i < count; i++) {
            DWORD n = recvd ? *recvd : bufs[i].len;
            if (n > 0 && bufs[i].buf) {
                log_time(g_log_net);
                fprintf(g_log_net, "WSARecv  ← %-22s  buf[%lu]  ", peer, i);
                log_hex(g_log_net, "", (const unsigned char*)bufs[i].buf, (int)n);
            }
        }
        fflush(g_log_net);
    }
    return ret;
}

/* ── HOOK: WSASendTo (UDP async) ── */
static int WINAPI hook_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD count,
                                  LPDWORD sent, DWORD flags,
                                  const struct sockaddr *to, int tolen,
                                  LPWSAOVERLAPPED ov,
                                  LPWSAOVERLAPPED_COMPLETION_ROUTINE cb) {
    int ret = ((fn_WSASendTo_t)d_WSASendTo.orig_fn)(
                  s, bufs, count, sent, flags, to, tolen, ov, cb);
    if (g_log_net) {
        char addr[64];
        addr_str(to, addr, sizeof(addr));
        for (DWORD i = 0; i < count; i++) {
            if (bufs[i].len > 0 && bufs[i].buf) {
                log_time(g_log_net);
                fprintf(g_log_net, "WSASndTo → %-22s  buf[%lu]  ", addr, i);
                log_hex(g_log_net, "", (const unsigned char*)bufs[i].buf,
                        (int)bufs[i].len);
            }
        }
        fflush(g_log_net);
    }
    return ret;
}

/* ── HOOK: WSARecvFrom (UDP async) ── */
static int WINAPI hook_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD count,
                                    LPDWORD recvd, LPDWORD flags,
                                    struct sockaddr *from, LPINT fromlen,
                                    LPWSAOVERLAPPED ov,
                                    LPWSAOVERLAPPED_COMPLETION_ROUTINE cb) {
    int ret = ((fn_WSARecvFrom_t)d_WSARecvFrom.orig_fn)(
                  s, bufs, count, recvd, flags, from, fromlen, ov, cb);
    if (g_log_net && ret == 0) {
        char addr[64];
        addr_str(from, addr, sizeof(addr));
        for (DWORD i = 0; i < count; i++) {
            DWORD n = recvd ? *recvd : bufs[i].len;
            if (n > 0 && bufs[i].buf) {
                log_time(g_log_net);
                fprintf(g_log_net, "WSARcvFr ← %-22s  buf[%lu]  ", addr, i);
                log_hex(g_log_net, "", (const unsigned char*)bufs[i].buf, (int)n);
            }
        }
        fflush(g_log_net);
    }
    return ret;
}

/* ── HOOK: WSAConnectByNameW (TCP async, oyun login'de kullanır) ── */
static BOOL WINAPI hook_WSAConnByName(
        SOCKET s, LPWSTR node, LPWSTR svc,
        DWORD *local_len, struct sockaddr *local_addr,
        DWORD *remote_len, struct sockaddr *remote_addr,
        const struct timeval *timeout, LPWSAOVERLAPPED reserved) {
    if (g_log_net && node) {
        char host[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, node, -1, host, 255, NULL, NULL);
        char port[64]  = {0};
        if (svc) WideCharToMultiByte(CP_UTF8, 0, svc, -1, port, 63, NULL, NULL);
        log_time(g_log_net);
        fprintf(g_log_net, "WSAConnByNameW → %s:%s  sock=%llu\n",
                host, port, (unsigned long long)s);
        fflush(g_log_net);
    }
    return ((fn_WSAConnByName_t)d_WSAConnByName.orig_fn)(
               s, node, svc, local_len, local_addr,
               remote_len, remote_addr, timeout, reserved);
}

/* ══════════════════════════════════════════════════════
 *  OpenSSL INLINE DETOUR HOOK'LARI
 *  libcrypto-1_1_orig.dll byte'larına doğrudan JMP yazılır.
 *  VMProtect IAT koruması bu yöntemi atlatamaz.
 * ══════════════════════════════════════════════════════ */

typedef void (OSSL_CC *fn_BF_set_key_t)(BF_KEY*, int, const unsigned char*);
typedef void (OSSL_CC *fn_BF_cfb64_t)(const unsigned char*, unsigned char*,
                                       long, const BF_KEY*, unsigned char*, int*, int);
typedef int  (OSSL_CC *fn_RSA_pub_enc_t)(int, const unsigned char*,
                                          unsigned char*, RSA*, int);

/* ── HOOK: BF_set_key (inline detour on libcrypto-1_1_orig.dll) ── */
static void OSSL_CC hook_BF_set_key(BF_KEY *key, int len,
                                     const unsigned char *data) {
    InterlockedIncrement(&g_bf_export_calls);
    /* Always output to debugger — file may not be open yet */
    {
        char dbg[128];
        snprintf(dbg, sizeof(dbg),
                 "[pb_proxy] hook_BF_set_key INLINE called len=%d\n", len);
        OutputDebugStringA(dbg);
    }
    if (data && len > 0) {
        /* Open a fallback log in case g_log_crypto is NULL */
        FILE *f = g_log_crypto;
        FILE *fb = NULL;
        if (!f) {
            char fb_path[MAX_PATH];
            make_path(fb_path, "pb_key_fallback.log");
            fb = fopen(fb_path, "a");
            f = fb;
        }
        if (f) {
            log_time(f);
            fprintf(f,
                "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
                "  BF_set_key INLINE — BLOWFISH SESSION KEY\n"
                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            log_hex(f, "SESSION KEY (ham)", data, len);
            fprintf(f, "  Key uzunlugu: %d byte (%d bit)\n", len, len * 8);
            int all_print = 1;
            for (int i = 0; i < len; i++)
                if (data[i] < 0x20 || data[i] > 0x7e) { all_print = 0; break; }
            if (all_print)
                fprintf(f, "  ASCII: %.*s\n", len, (const char*)data);
            fprintf(f,
                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
            fflush(f);
            if (fb) fclose(fb);
        }
    }
    ((fn_BF_set_key_t)d_BF_set_key.orig_fn)(key, len, data);
}

/* ── HOOK: BF_cfb64_encrypt (inline, VMProtect bypass) ── */
static void OSSL_CC hook_BF_cfb64_inline(
        const unsigned char *in, unsigned char *out,
        long length, const BF_KEY *key,
        unsigned char *ivec, int *num, int enc) {

    /* İlk çağrıda tam BF_KEY yapısını Python proxy'ye ilet.
     * Bu en güvenilir yoldur: fonksiyon çağrıldığında anahtar
     * belleğe tam olarak yazılmıştır. */
    if (key && InterlockedCompareExchange(&g_key_forwarded, 1, 0) == 0) {
        px_forward_key((const uint8_t*)key);
        px_forward_challenge(); /* kayıtlı challenge varsa anahtarla birlikte gönder */
    }

    if (g_log_crypto) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto, "BF_cfb64 [inline] — %s len=%ld\n",
                enc == 1 ? "ENC" : "DEC", length);
        log_hex(g_log_crypto, "ivec", ivec, 8);
        log_ivec_endian(g_log_crypto, ivec);
        log_hex(g_log_crypto, "in", in, (int)length);
        /* BF_KEY: ilk 72 byte = P-array */
        log_hex(g_log_crypto, "key(P[0:8])",
                (const unsigned char*)key, 32);
        fflush(g_log_crypto);
    }

    ((fn_BF_cfb64_t)d_BF_cfb64_inline.orig_fn)(
        in, out, length, key, ivec, num, enc);

    if (g_log_crypto && enc == 0) {
        log_hex(g_log_crypto, "out(dec)", out, (int)length);
        fflush(g_log_crypto);
    }
}

/* ── HOOK: RSA_public_encrypt (inline) — session key RSA'dan önce ── */
static int OSSL_CC hook_RSA_pub_inline(int flen, const unsigned char *from,
                                        unsigned char *to, RSA *rsa, int pad) {
    if (g_log_crypto && from && flen > 0) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto,
            "\n*** RSA_public_encrypt [inline] ***\n"
            "    flen=%d (bu Blowfish key boyutu!)\n", flen);
        log_hex(g_log_crypto, "PLAINTEXT KEY", from, flen);
        fflush(g_log_crypto);
    }
    int ret = ((fn_RSA_pub_enc_t)d_RSA_public_inline.orig_fn)(
                  flen, from, to, rsa, pad);
    if (g_log_crypto) {
        log_hex(g_log_crypto, "RSA ciphertext", to, ret > 0 ? ret : flen);
        fflush(g_log_crypto);
    }
    return ret;
}

/* ── OpenSSL detour'larını kur (libcrypto-1_1_orig.dll üzerinde) ── */
static void install_crypto_hooks(void) {
    if (!g_real_crypto) return;

#define CHOOK(dtor, name, hfn) do { \
    void *fn = (void*)GetProcAddress(g_real_crypto, name); \
    if (fn) { \
        if (detour_install(&dtor, fn, (void*)hfn)) { \
            if (g_log_crypto) fprintf(g_log_crypto, \
                "  CRYPTO DETOUR OK: %s @ %p\n", name, fn); \
        } else { \
            if (g_log_crypto) fprintf(g_log_crypto, \
                "  CRYPTO DETOUR FAIL: %s\n", name); \
        } \
    } else { \
        if (g_log_crypto) fprintf(g_log_crypto, \
            "  CRYPTO NOT FOUND: %s\n", name); \
    } \
} while(0)

    if (g_log_crypto) {
        fprintf(g_log_crypto,
            "\n--- OpenSSL Inline Detour Kurulum ---\n"
            "libcrypto_orig base: %p\n", (void*)g_real_crypto);
        fflush(g_log_crypto);
    }

    /* BF_set_key: session key'i ham olarak yakala */
    CHOOK(d_BF_set_key,      "BF_set_key",        hook_BF_set_key);
    /* BF_cfb64_encrypt: her paket şifreleme/çözme */
    CHOOK(d_BF_cfb64_inline, "BF_cfb64_encrypt",  hook_BF_cfb64_inline);
    /* RSA_public_encrypt: session key RSA ile şifrelenmeden önce */
    CHOOK(d_RSA_public_inline,"RSA_public_encrypt",hook_RSA_pub_inline);

#undef CHOOK

    if (g_log_crypto) {
        fprintf(g_log_crypto, "--- OpenSSL Inline Detour Bitti ---\n\n");
        fflush(g_log_crypto);
    }
}

/* ── WinSock detour'larını kur ── */
static void install_winsock_hooks(void) {
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) {
        /* WinSock henüz yüklenmemiş, yükle */
        ws2 = LoadLibraryA("ws2_32.dll");
    }
    if (!ws2) {
        if (g_log_net)
            fprintf(g_log_net, "UYARI: ws2_32.dll bulunamadi\n");
        return;
    }

    /* Adları ve ordinal ID'leri ile al */
#define HOOK(dtor, name, hfn) do { \
    void *fn = (void*)GetProcAddress(ws2, name); \
    if (fn) { \
        if (detour_install(&dtor, fn, (void*)hfn)) { \
            if (g_log_net) fprintf(g_log_net, "  DETOUR OK: %s @ %p\n", name, fn); \
        } else { \
            if (g_log_net) fprintf(g_log_net, "  DETOUR FAIL: %s\n", name); \
        } \
    } else { \
        if (g_log_net) fprintf(g_log_net, "  NOT FOUND: %s\n", name); \
    } \
} while(0)

    if (g_log_net) {
        fprintf(g_log_net, "\n--- WinSock Detour Kurulum ---\n");
        fprintf(g_log_net, "ws2_32.dll base: %p\n", (void*)ws2);
    }

    HOOK(d_connect,      "connect",           hook_connect);
    HOOK(d_send,         "send",              hook_send);
    HOOK(d_recv,         "recv",              hook_recv);
    HOOK(d_sendto,       "sendto",            hook_sendto);
    HOOK(d_recvfrom,     "recvfrom",          hook_recvfrom);
    HOOK(d_WSASend,      "WSASend",           hook_WSASend);
    HOOK(d_WSARecv,      "WSARecv",           hook_WSARecv);
    HOOK(d_WSASendTo,    "WSASendTo",         hook_WSASendTo);
    HOOK(d_WSARecvFrom,  "WSARecvFrom",       hook_WSARecvFrom);
    HOOK(d_WSAConnByName,"WSAConnectByNameW", hook_WSAConnByName);
#undef HOOK

    if (g_log_net) {
        fprintf(g_log_net, "--- Detour Kurulum Bitti ---\n\n");
        fflush(g_log_net);
    }
}

/* ══════════════════════════════════════════════════════
 *  OPENSSL PROXY — fonksiyon pointer'ları
 * ══════════════════════════════════════════════════════ */

typedef void (OSSL_CC *fn_BF_set_key)(BF_KEY*, int, const unsigned char*);
typedef void (OSSL_CC *fn_BF_cfb64_encrypt)(
    const unsigned char*, unsigned char*, long,
    const BF_KEY*, unsigned char*, int*, int);
typedef void (OSSL_CC *fn_BF_encrypt)(uint32_t*, const BF_KEY*);
typedef void (OSSL_CC *fn_BF_decrypt)(uint32_t*, const BF_KEY*);
typedef int  (OSSL_CC *fn_RSA_public_encrypt)(
    int, const unsigned char*, unsigned char*, RSA*, int);
typedef int  (OSSL_CC *fn_RSA_size)(const RSA*);
typedef RSA* (OSSL_CC *fn_PEM_read_bio_RSAPublicKey)(BIO*, RSA**, void*, void*);
typedef BIO* (OSSL_CC *fn_BIO_new_mem_buf)(const void*, int);
typedef int  (OSSL_CC *fn_BIO_free)(BIO*);
typedef void (OSSL_CC *fn_RSA_free)(RSA*);
typedef void (OSSL_CC *fn_RAND_seed)(const void*, int);

static fn_BF_set_key             real_BF_set_key             = NULL;
static fn_BF_cfb64_encrypt       real_BF_cfb64_encrypt       = NULL;
static fn_BF_encrypt             real_BF_encrypt             = NULL;
static fn_BF_decrypt             real_BF_decrypt             = NULL;
static fn_RSA_public_encrypt     real_RSA_public_encrypt     = NULL;
static fn_RSA_size               real_RSA_size               = NULL;
static fn_PEM_read_bio_RSAPublicKey real_PEM_read_bio_RSAPublicKey = NULL;
static fn_BIO_new_mem_buf        real_BIO_new_mem_buf        = NULL;
static fn_BIO_free               real_BIO_free               = NULL;
static fn_RSA_free               real_RSA_free               = NULL;
static fn_RAND_seed              real_RAND_seed              = NULL;

/* ══════════════════════════════════════════════════════
 *  LAZY INIT (DllMain'den çağrılmaz — loader-lock güvenli)
 * ══════════════════════════════════════════════════════ */

static BOOL CALLBACK do_init(PINIT_ONCE p, PVOID param, PVOID *ctx) {
    (void)p; (void)param; (void)ctx;

    /* Kendi modül yolundan base dir hesapla */
    char dll_path[MAX_PATH] = {0};
    HMODULE hSelf = NULL;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)do_init, &hSelf);
    if (hSelf) GetModuleFileNameA(hSelf, dll_path, MAX_PATH);

    /* Son '\' veya '/' konumunu bul → dizin */
    char *last = dll_path;
    for (char *p = dll_path; *p; p++)
        if (*p == '\\' || *p == '/') last = p + 1;
    size_t dir_len = (size_t)(last - dll_path);
    if (dir_len < MAX_PATH - 2)
        memcpy(g_base_dir, dll_path, dir_len);

    /* Log dosyalarını aç */
    g_log_crypto = open_log("pb_crypto.log");
    g_log_net    = open_log("pb_net.log");
    g_log_plain  = open_log("pb_plain.log");
    if (g_log_plain) {
        fprintf(g_log_plain,
            "# ========================================\n"
            "# pb_plain.log — PointBlank plaintext log\n"
            "# PID %lu\n"
            "# Kolon: #seq  YON  total  len_field  proto  op  payload\n"
            "# SEND → enc=1 in=plaintext  /  RECV ← enc=0 out=plaintext\n"
            "# Paket fmt: [1B len][1B 0x0D][1B opcode][payload]\n"
            "# ========================================\n",
            GetCurrentProcessId());
        fflush(g_log_plain);
    }

    if (g_log_crypto) {
        fprintf(g_log_crypto,
            "\n========================================\n"
            "  libcrypto proxy yuklendi — PID %lu\n"
            "  Dizin: %s\n"
            "========================================\n",
            GetCurrentProcessId(), g_base_dir);
        fflush(g_log_crypto);
    }
    if (g_log_net) {
        fprintf(g_log_net,
            "\n========================================\n"
            "  WinSock detour yukleniyor — PID %lu\n"
            "========================================\n",
            GetCurrentProcessId());
        fflush(g_log_net);
    }

    /* OpenSSL gerçek DLL */
    g_real_crypto = LoadLibraryA("libcrypto-1_1_orig.dll");
    if (!g_real_crypto && g_log_crypto) {
        fprintf(g_log_crypto, "HATA: libcrypto-1_1_orig.dll yuklenemedi (err=%lu)\n",
                GetLastError());
        fflush(g_log_crypto);
    }
    if (g_real_crypto) {
/* void* ara cast — GetProcAddress dönüşüm uyarısını bastırır */
#define LOAD(name) do { \
    void *_p = (void*)(uintptr_t)GetProcAddress(g_real_crypto, #name); \
    memcpy(&real_##name, &_p, sizeof(_p)); \
} while(0)
        LOAD(BF_set_key); LOAD(BF_cfb64_encrypt);
        LOAD(BF_encrypt); LOAD(BF_decrypt);
        LOAD(RSA_public_encrypt);
        LOAD(RSA_size); LOAD(PEM_read_bio_RSAPublicKey);
        LOAD(BIO_new_mem_buf); LOAD(BIO_free);
        LOAD(RSA_free); LOAD(RAND_seed);
#undef LOAD
        if (g_log_crypto) {
            fprintf(g_log_crypto, "OpenSSL DLL: %p\n", (void*)g_real_crypto);
            fprintf(g_log_crypto, "BF_cfb64_encrypt   : %p\n",
                    (void*)real_BF_cfb64_encrypt);
            fprintf(g_log_crypto, "RSA_public_encrypt : %p\n",
                    (void*)real_RSA_public_encrypt);
            fflush(g_log_crypto);
        }
    }

    /* Tarama thread'i için graceful shutdown event'i oluştur */
    g_scan_shutdown = CreateEventA(NULL, TRUE, FALSE, NULL);

    /* Paylaşılan tampon için kritik bölüm başlat */
    InitializeCriticalSection(&g_scan_cs);
    g_scan_cs_init = TRUE;

    /* OpenSSL inline detour'ları kur (BF_set_key → session key yakalama) */
    install_crypto_hooks();

    /* WinSock inline detour'ları kur */
    install_winsock_hooks();

    /* ── Python Proxy köprüsü ── */
    InitializeCriticalSection(&g_px_cs);
    g_px_cs_ok = TRUE;
    /* Send queue başlat */
    InitializeCriticalSection(&g_pxq_cs);
    g_pxq_cs_ok = TRUE;
    g_pxq_sem = CreateSemaphoreA(NULL, 0, PXQ_SLOTS, NULL);
    /* Key-ready event (manual-reset, başlangıçta sinyalsiz) */
    g_px_key_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (px_read_cfg()) {
        g_px_enabled = TRUE;
        if (g_log_net) {
            log_time(g_log_net);
            fprintf(g_log_net,
                "PROXY: Config okundu → %ls:%u%ls  tls=%d\n",
                g_px_host, (unsigned)g_px_port, g_px_path, (int)g_px_tls);
            fflush(g_log_net);
        }
        px_init();
    } else {
        if (g_log_net) {
            log_time(g_log_net);
            fprintf(g_log_net,
                "PROXY: pb_proxy.cfg bulunamadı — proxy devre dışı\n"
                "       Dosyayı oyun dizininde oluşturun:\n"
                "         server_url=wss://HOST/dll\n");
            fflush(g_log_net);
        }
    }

    return TRUE;
}

static void ensure_init(void) {
    InitOnceExecuteOnce(&g_init, do_init, NULL, NULL);
}

/* ══════════════════════════════════════════════════════
 *  OPENSSL EXPORT HOOK'LARI
 * ══════════════════════════════════════════════════════ */

/* ── EXPORT STUB: BF_set_key — game calls this to set the session key ── */
__declspec(dllexport) void OSSL_CC
BF_set_key(BF_KEY *key, int len, const unsigned char *data) {
    ensure_init();
    InterlockedIncrement(&g_bf_export_calls);
    /* Always log — use OutputDebugStringA as fallback if file is unavailable */
    {
        char dbg[128];
        snprintf(dbg, sizeof(dbg),
                 "[pb_proxy] BF_set_key EXPORT called len=%d\n", len);
        OutputDebugStringA(dbg);
    }
    if (g_log_crypto && data && len > 0) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto,
            "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
            "  BF_set_key EXPORT — BLOWFISH SESSION KEY\n"
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        log_hex(g_log_crypto, "SESSION KEY (ham)", data, len);
        fprintf(g_log_crypto, "  Key uzunlugu: %d byte (%d bit)\n",
                len, len * 8);
        int all_print = 1;
        for (int i = 0; i < len; i++)
            if (data[i] < 0x20 || data[i] > 0x7e) { all_print = 0; break; }
        if (all_print)
            fprintf(g_log_crypto, "  ASCII: %.*s\n", len, (const char*)data);
        fprintf(g_log_crypto,
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
        fflush(g_log_crypto);
    }
    if (real_BF_set_key)
        real_BF_set_key(key, len, data);
}

__declspec(dllexport) void OSSL_CC
BF_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                 long length, const BF_KEY *key,
                 unsigned char *ivec, int *num, int enc) {
    ensure_init();
    InterlockedIncrement(&g_bf_export_calls);

    /* ── pb_plain.log: SEND plaintext (enc=1 → 'in' = şifrelenmemiş veri) ── */
    if (enc == 1 && g_log_plain && in && length > 0) {
        int seq = (int)InterlockedIncrement(&g_plain_call_seq);
        log_pb_plain_pkt(g_log_plain, "SEND \xe2\x86\x92",
                         in, (int)length, seq);
        log_pb_hexdump(g_log_plain, in, (int)length);
    }

    /* ── pb_crypto.log: teknik detay (ivec, key özeti, ham 'in') ── */
    if (g_log_crypto) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto, "BF_cfb64_encrypt EXPORT — %s, len=%ld  [call#%ld]\n",
                enc == 1 ? "ENCRYPT" : "DECRYPT", length,
                (long)g_bf_export_calls);
        log_hex(g_log_crypto, "ivec", ivec, 8);
        log_ivec_endian(g_log_crypto, ivec);
        log_hex(g_log_crypto, "in", in, (int)length);
        log_hex(g_log_crypto, "key P-array[0:32]",
                (const unsigned char*)key, 32);
        fflush(g_log_crypto);
    }

    if (real_BF_cfb64_encrypt)
        real_BF_cfb64_encrypt(in, out, length, key, ivec, num, enc);

    /* ── pb_plain.log: RECV plaintext (enc=0 → 'out' = çözülmüş veri) ── */
    if (enc == 0 && g_log_plain && out && length > 0) {
        int seq = (int)InterlockedIncrement(&g_plain_call_seq);
        log_pb_plain_pkt(g_log_plain, "RECV \xe2\x86\x90",
                         out, (int)length, seq);
        log_pb_hexdump(g_log_plain, out, (int)length);
    }

    /* ── pb_crypto.log: çözülmüş çıktı (sadece DEC) ── */
    if (g_log_crypto && enc == 0) {
        log_hex(g_log_crypto, "out (decrypted)", out, (int)length);
        fflush(g_log_crypto);
    }
}

/* ── EXPORT STUB: BF_encrypt / BF_decrypt (block-level ECB mode) ── */
__declspec(dllexport) void OSSL_CC
BF_encrypt(uint32_t *data, const BF_KEY *key) {
    ensure_init();
    InterlockedIncrement(&g_bf_export_calls);
    OutputDebugStringA("[pb_proxy] BF_encrypt EXPORT called\n");
    if (g_log_crypto) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto, "BF_encrypt EXPORT — block  [call#%ld]\n",
                (long)g_bf_export_calls);
        log_hex(g_log_crypto, "in block", (const unsigned char*)data, 8);
        log_hex(g_log_crypto, "key P-array[0:32]",
                (const unsigned char*)key, 32);
        fflush(g_log_crypto);
    }
    if (real_BF_encrypt) real_BF_encrypt(data, key);
    if (g_log_crypto) {
        log_hex(g_log_crypto, "out block", (const unsigned char*)data, 8);
        fflush(g_log_crypto);
    }
}

__declspec(dllexport) void OSSL_CC
BF_decrypt(uint32_t *data, const BF_KEY *key) {
    ensure_init();
    InterlockedIncrement(&g_bf_export_calls);
    OutputDebugStringA("[pb_proxy] BF_decrypt EXPORT called\n");
    if (g_log_crypto) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto, "BF_decrypt EXPORT — block  [call#%ld]\n",
                (long)g_bf_export_calls);
        log_hex(g_log_crypto, "in block", (const unsigned char*)data, 8);
        log_hex(g_log_crypto, "key P-array[0:32]",
                (const unsigned char*)key, 32);
        fflush(g_log_crypto);
    }
    if (real_BF_decrypt) real_BF_decrypt(data, key);
    if (g_log_crypto) {
        log_hex(g_log_crypto, "out block", (const unsigned char*)data, 8);
        fflush(g_log_crypto);
    }
}

__declspec(dllexport) int OSSL_CC
RSA_public_encrypt(int flen, const unsigned char *from,
                   unsigned char *to, RSA *rsa, int padding) {
    ensure_init();
    if (g_log_crypto) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto,
                "RSA_public_encrypt — flen=%d padding=%d\n", flen, padding);
        log_hex(g_log_crypto, "*** BLOWFISH SESSION KEY (plaintext)", from, flen);
        fflush(g_log_crypto);
    }
    int ret = real_RSA_public_encrypt
            ? real_RSA_public_encrypt(flen, from, to, rsa, padding) : -1;
    if (g_log_crypto) {
        log_hex(g_log_crypto, "RSA encrypted out", to, ret > 0 ? ret : flen);
        fflush(g_log_crypto);
    }
    return ret;
}

__declspec(dllexport) RSA* OSSL_CC
PEM_read_bio_RSAPublicKey(BIO *bp, RSA **x, void *cb, void *u) {
    ensure_init();
    if (g_log_crypto) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto, "PEM_read_bio_RSAPublicKey — sunucu RSA key okunuyor\n");
        fflush(g_log_crypto);
    }
    RSA *ret = real_PEM_read_bio_RSAPublicKey
             ? real_PEM_read_bio_RSAPublicKey(bp, x, cb, u) : NULL;
    if (g_log_crypto && ret) {
        int bits = real_RSA_size ? real_RSA_size(ret) * 8 : -1;
        fprintf(g_log_crypto, "  -> RSA*=%p  %d bit\n", (void*)ret, bits);
        fflush(g_log_crypto);
    }
    return ret;
}

__declspec(dllexport) int  OSSL_CC RSA_size(const RSA *r) {
    ensure_init(); return real_RSA_size ? real_RSA_size(r) : 0; }
__declspec(dllexport) BIO* OSSL_CC BIO_new_mem_buf(const void *b, int l) {
    ensure_init(); return real_BIO_new_mem_buf ? real_BIO_new_mem_buf(b,l) : NULL; }
__declspec(dllexport) int  OSSL_CC BIO_free(BIO *a) {
    ensure_init(); return real_BIO_free ? real_BIO_free(a) : 0; }
__declspec(dllexport) void OSSL_CC RSA_free(RSA *r) {
    ensure_init(); if (real_RSA_free) real_RSA_free(r); }
__declspec(dllexport) void OSSL_CC RAND_seed(const void *b, int n) {
    ensure_init(); if (real_RAND_seed) real_RAND_seed(b, n); }

/* ══════════════════════════════════════════════════════
 *  DllMain — sadece DisableThreadLibraryCalls
 * ══════════════════════════════════════════════════════ */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        /* Ağır iş ensure_init() ile lazy yapılır */
    } else if (reason == DLL_PROCESS_DETACH) {
        /* Proxy köprüsünü durdur (önce — WS thread'i log'a yazmayı bırakmalı) */
        px_shutdown();

        /* Tarama thread'ini durdur */
        if (g_scan_shutdown) {
            SetEvent(g_scan_shutdown);
            /* Thread tamamen bitmeden log handle'larını kapatma */
            if (g_scan_thread) {
                WaitForSingleObject(g_scan_thread, 2000);  /* en fazla 2s bekle */
                CloseHandle(g_scan_thread);
                g_scan_thread = NULL;
            }
            CloseHandle(g_scan_shutdown);
            g_scan_shutdown = NULL;
        }
        /* Join immediate scan threads so they don't write to closed logs */
        {
            LONG cnt = g_imm_thread_cnt;
            if (cnt > MAX_IMM_THREADS) cnt = MAX_IMM_THREADS;
            for (LONG i = 0; i < cnt; i++) {
                if (g_imm_threads[i]) {
                    WaitForSingleObject(g_imm_threads[i], 2000);
                    CloseHandle(g_imm_threads[i]);
                    g_imm_threads[i] = NULL;
                }
            }
        }
        if (g_scan_cs_init) { DeleteCriticalSection(&g_scan_cs); g_scan_cs_init = FALSE; }
        if (g_log_plain) {
            fprintf(g_log_plain, "# proxy kaldirildi.\n");
            fclose(g_log_plain); g_log_plain = NULL;
        }
        if (g_log_crypto) {
            fprintf(g_log_crypto, "proxy kaldirildi.\n");
            fclose(g_log_crypto); g_log_crypto = NULL;
        }
        if (g_log_net) {
            fprintf(g_log_net, "proxy kaldirildi.\n");
            fclose(g_log_net); g_log_net = NULL;
        }
        if (g_real_crypto) { FreeLibrary(g_real_crypto); g_real_crypto = NULL; }
    }
    return TRUE;
}
