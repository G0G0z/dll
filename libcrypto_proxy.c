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
    return ((fn_connect_t)d_connect.orig_fn)(s, name, namelen);
}

/* ── HOOK: send (TCP) ── */
static int WINAPI hook_send(SOCKET s, const char *buf, int len, int flags) {
    int ret = ((fn_send_t)d_send.orig_fn)(s, buf, len, flags);
    if (g_log_net && ret > 0) {
        char peer[64];
        socket_peer(s, peer, sizeof(peer));
        log_time(g_log_net);
        fprintf(g_log_net, "TCP SEND → %-22s  ", peer);
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
        fprintf(g_log_net, "TCP RECV ← %-22s  ", peer);
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

/* ── HOOK: BF_set_key — session key ham haliyle burada! ── */
static void OSSL_CC hook_BF_set_key(BF_KEY *key, int len,
                                     const unsigned char *data) {
    if (g_log_crypto && data && len > 0) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto,
            "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
            "  BF_set_key — BLOWFISH SESSION KEY\n"
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        log_hex(g_log_crypto, "SESSION KEY (ham)", data, len);
        fprintf(g_log_crypto, "  Key uzunlugu: %d byte (%d bit)\n", len, len * 8);
        /* ASCII okunabilir mi? */
        int all_print = 1;
        for (int i = 0; i < len; i++)
            if (data[i] < 0x20 || data[i] > 0x7e) { all_print = 0; break; }
        if (all_print) {
            fprintf(g_log_crypto, "  ASCII: %.*s\n", len, (const char*)data);
        }
        fprintf(g_log_crypto,
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
        fflush(g_log_crypto);
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

typedef void (OSSL_CC *fn_BF_cfb64_encrypt)(
    const unsigned char*, unsigned char*, long,
    const BF_KEY*, unsigned char*, int*, int);
typedef int  (OSSL_CC *fn_RSA_public_encrypt)(
    int, const unsigned char*, unsigned char*, RSA*, int);
typedef int  (OSSL_CC *fn_RSA_size)(const RSA*);
typedef RSA* (OSSL_CC *fn_PEM_read_bio_RSAPublicKey)(BIO*, RSA**, void*, void*);
typedef BIO* (OSSL_CC *fn_BIO_new_mem_buf)(const void*, int);
typedef int  (OSSL_CC *fn_BIO_free)(BIO*);
typedef void (OSSL_CC *fn_RSA_free)(RSA*);
typedef void (OSSL_CC *fn_RAND_seed)(const void*, int);

static fn_BF_cfb64_encrypt       real_BF_cfb64_encrypt       = NULL;
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
        LOAD(BF_cfb64_encrypt); LOAD(RSA_public_encrypt);
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

__declspec(dllexport) void OSSL_CC
BF_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                 long length, const BF_KEY *key,
                 unsigned char *ivec, int *num, int enc) {
    ensure_init();
    if (g_log_crypto) {
        log_time(g_log_crypto);
        fprintf(g_log_crypto, "BF_cfb64_encrypt — %s, len=%ld\n",
                enc == 1 ? "ENCRYPT" : "DECRYPT", length);
        log_hex(g_log_crypto, "ivec", ivec, 8);
        log_hex(g_log_crypto, "in (plaintext)", in, (int)length);
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
