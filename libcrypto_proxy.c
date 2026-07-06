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
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ══════════════════════════════════════════════════════
 *  ORTAK YARDIMCILAR
 * ══════════════════════════════════════════════════════ */

#define OSSL_CC __cdecl

typedef void BF_KEY;
typedef void RSA;
typedef void BIO;

static FILE *g_log_crypto = NULL;   /* pb_crypto.log */
static FILE *g_log_net    = NULL;   /* pb_net.log    */

/* Diagnostic: counts every BF export call — visible in pb_net.log lines */
static volatile LONG g_bf_export_calls = 0;

static INIT_ONCE  g_init        = INIT_ONCE_STATIC_INIT;
static HMODULE    g_real_crypto  = NULL;

/* Oyunun yükleme dizinini bir kere hesapla */
static char g_base_dir[MAX_PATH] = {0};

static void make_path(char *out, const char *filename) {
    snprintf(out, MAX_PATH, "%s%s", g_base_dir, filename);
}

static FILE *open_log(const char *filename) {
    char path[MAX_PATH];
    make_path(path, filename);
    return fopen(path, "a");
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
static volatile LONG g_scan_triggered = 0;
static volatile LONG g_scan_running   = 0;
static HANDLE        g_scan_shutdown  = NULL;  /* DLL_PROCESS_DETACH'ta sinyallenir */

/* Forward declaration */
static void ensure_init(void);

/*
 * Sıkı S-box testi — 4 byte pozisyonunun her birinde
 * histogram oluşturur; max frekans < 8 olmalı.
 * Grafik RGBA bufferlarda alpha=0xFF →256 kez tekrar → elenir.
 * Ses PCM bufferlarda üst 16 bit=0 →256 kez tekrar → elenir.
 */
static BOOL sbox_strict(const uint32_t *sbox) {
    uint8_t h0[256], h1[256], h2[256], h3[256];
    memset(h0,0,256); memset(h1,0,256);
    memset(h2,0,256); memset(h3,0,256);

    for (int i = 0; i < 256; i++) {
        uint32_t v = sbox[i];
        h0[(uint8_t)(v >> 24)]++;
        h1[(uint8_t)(v >> 16)]++;
        h2[(uint8_t)(v >>  8)]++;
        h3[(uint8_t)(v      )]++;
    }
    for (int b = 0; b < 256; b++) {
        if (h0[b] > 7 || h1[b] > 7 || h2[b] > 7 || h3[b] > 7)
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
    log_hex(f, "S[0] (1024B)", (const uint8_t*)(dw + BF_P_DWORDS),               1024);
    log_hex(f, "S[1] (1024B)", (const uint8_t*)(dw + BF_P_DWORDS + 256),         1024);
    log_hex(f, "S[2] (1024B)", (const uint8_t*)(dw + BF_P_DWORDS + 512),         1024);
    log_hex(f, "S[3] (1024B)", (const uint8_t*)(dw + BF_P_DWORDS + 768),         1024);

    /* Tek satır P-array (Python kopyala/yapıştır için) */
    fprintf(f, "  [FULL_KEY] P:");
    for (int i = 0; i < BF_P_DWORDS; i++) fprintf(f, "%08x", dw[i]);
    fprintf(f, "\n");
    fflush(f);
}

/* Tek geçiş — belirli adres aralığını tara */
static int run_one_pass(FILE *f, int pass_num) {
    int candidates = 0, pages = 0;

    /* Sadece oyun özel belleği: 1 MB – 1 GB arası */
    uint8_t *scan_lo = (uint8_t *)0x00100000;
    uint8_t *scan_hi = (uint8_t *)0x40000000;

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = scan_lo;

    while (addr < scan_hi &&
           VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {

        uint8_t *base = (uint8_t *)mbi.BaseAddress;
        size_t   rsz  = mbi.RegionSize;

        /* Sonraki adres — taşma koruması */
        uint8_t *next = base + rsz;
        if (next <= base) break;

        /* Filtre: commit, özel, R/W, Guard değil, boyut uygun */
        if (mbi.State   == MEM_COMMIT              &&
            mbi.Type    == MEM_PRIVATE             &&
            (mbi.Protect & (PAGE_READWRITE |
                            PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)            &&
            rsz         >= (size_t)BF_KEY_SIZE     &&
            rsz         <= 16u * 1024u * 1024u) {  /* max 16 MB */

            pages++;

            /* Tampon yeterince büyükse doğrudan oku */
            static uint8_t tmp[16 * 1024 * 1024];
            SIZE_T copied = 0;
            if (!ReadProcessMemory(GetCurrentProcess(),
                                   base, tmp, rsz, &copied) || copied < BF_KEY_SIZE) {
                addr = next; continue;
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
                log_bf_candidate(f, candidates, base + off, &mbi, dw);

                off += BF_KEY_SIZE - 4;  /* örtüşen eşleşmeleri atla */
            }
        }
        addr = next;
    }

    log_time(f);
    fprintf(f, "=== GEÇİŞ %d TAMAM: %d sayfa, %d aday ===\n\n",
            pass_num, pages, candidates);
    fflush(f);
    return candidates;
}

static DWORD WINAPI scan_thread(LPVOID param) {
    (void)param;

    /* 3 geçiş: login key (1s) + game server key (5s) + yedek (10s) */
    static const DWORD delays[] = {1000, 5000, 10000};

    for (int pass = 0; pass < 3; pass++) {
        Sleep(delays[pass]);

        FILE *f = g_log_crypto;
        FILE *fb = NULL;
        if (!f) {
            char path[MAX_PATH];
            make_path(path, "pb_key_fallback.log");
            fb = fopen(path, "a");
            f = fb;
        }
        if (!f) continue;

        log_time(f);
        fprintf(f, "\n=== BELLEK TARAMASI v2 — GEÇİŞ %d ===\n", pass + 1);
        fflush(f);

        run_one_pass(f, pass + 1);

        if (fb) { fclose(fb); fb = NULL; }
    }

    InterlockedExchange(&g_scan_running, 0);
    return 0;
}

/* Oyun sunucusuna bağlanınca taramayı bir kere tetikle */
static void trigger_memscan(void) {
    if (InterlockedCompareExchange(&g_scan_triggered, 1, 0) == 0) {
        InterlockedExchange(&g_scan_running, 1);
        HANDLE t = CreateThread(NULL, 0, scan_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
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
            trigger_memscan();
        }
    }

    return ((fn_connect_t)d_connect.orig_fn)(s, name, namelen);
}

/* ── HOOK: send (TCP) ── */
static int WINAPI hook_send(SOCKET s, const char *buf, int len, int flags) {
    int ret = ((fn_send_t)d_send.orig_fn)(s, buf, len, flags);
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
    if (g_log_net && ret > 0) {
        char peer[64];
        socket_peer(s, peer, sizeof(peer));
        log_time(g_log_net);
        fprintf(g_log_net, "TCP RECV ← %-22s  bf_calls=%ld  ",
                peer, (long)g_bf_export_calls);
        log_hex(g_log_net, "", (const unsigned char*)buf, ret);
        fflush(g_log_net);
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

    if (g_log_crypto) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto, "BF_cfb64 [inline] — %s len=%ld\n",
                enc == 1 ? "ENC" : "DEC", length);
        log_hex(g_log_crypto, "ivec", ivec, 8);
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
#define LOAD(name) real_##name = (fn_##name)GetProcAddress(g_real_crypto, #name)
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

    /* OpenSSL inline detour'ları kur (BF_set_key → session key yakalama) */
    install_crypto_hooks();

    /* WinSock inline detour'ları kur */
    install_winsock_hooks();

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
    OutputDebugStringA("[pb_proxy] BF_cfb64_encrypt EXPORT called\n");
    if (g_log_crypto) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto, "BF_cfb64_encrypt EXPORT — %s, len=%ld  [call#%ld]\n",
                enc == 1 ? "ENCRYPT" : "DECRYPT", length,
                (long)g_bf_export_calls);
        log_hex(g_log_crypto, "ivec", ivec, 8);
        log_hex(g_log_crypto, "in", in, (int)length);
        log_hex(g_log_crypto, "key P-array[0:32]",
                (const unsigned char*)key, 32);
        fflush(g_log_crypto);
    }
    if (real_BF_cfb64_encrypt)
        real_BF_cfb64_encrypt(in, out, length, key, ivec, num, enc);
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
