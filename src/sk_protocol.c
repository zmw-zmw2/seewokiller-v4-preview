#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sk_protocol.h"

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#define SK_OK(s) (((NTSTATUS)(s)) >= 0)

int sk_hmac_sha256(const uint8_t* key, size_t keyLen,
                   const uint8_t* data, size_t dataLen, uint8_t out[SK_HMAC_LEN]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                     BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!SK_OK(st)) return -1;

    st = BCryptCreateHash(alg, &h, NULL, 0, (PUCHAR)key, (ULONG)keyLen, 0);
    if (!SK_OK(st)) { BCryptCloseAlgorithmProvider(alg, 0); return -1; }

    st = BCryptHashData(h, (PUCHAR)data, (ULONG)dataLen, 0);
    if (SK_OK(st)) st = BCryptFinishHash(h, out, SK_HMAC_LEN, 0);

    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return SK_OK(st) ? 0 : -1;
}

static int sk_secure_memcmp(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= (uint8_t)(a[i] ^ b[i]);
    return d ? -1 : 0;
}

size_t sk_build_packet(uint8_t msg_type, const char* json,
                       const uint8_t key[SK_HMAC_LEN],
                       uint8_t* out, size_t outCap) {
    size_t jl = strlen(json);
    if (jl > SK_MAX_JSON) return 0;
    if (outCap < SK_PKT_OVERHEAD + jl) return 0;

    memset(out, 0, SK_PKT_OVERHEAD + jl);
    uint32_t magic = SK_MAGIC;
    memcpy(out + 0, &magic, 4);
    out[4] = SK_PROTO_VERSION;
    out[5] = msg_type;
    uint16_t jl16 = (uint16_t)jl;
    memcpy(out + 6, &jl16, 2);
    memcpy(out + SK_PKT_OVERHEAD, json, jl);

    /* sign everything with the hmac field zeroed */
    if (sk_hmac_sha256(key, SK_HMAC_LEN, out, SK_PKT_OVERHEAD + jl,
                       out + SK_HDR_LEN) != 0)
        return 0;
    return SK_PKT_OVERHEAD + jl;
}

int sk_parse_packet(const uint8_t* buf, size_t len, const uint8_t key[SK_HMAC_LEN],
                    uint8_t* msg_type, char* jsonOut, size_t jsonCap) {
    if (len < SK_PKT_OVERHEAD || len > SK_MAX_PACKET) return -1;

    uint32_t magic;
    memcpy(&magic, buf, 4);
    if (magic != SK_MAGIC) return -1;
    if (buf[4] != SK_PROTO_VERSION) return -1;

    uint16_t jl;
    memcpy(&jl, buf + 6, 2);
    if ((size_t)jl + SK_PKT_OVERHEAD != len) return -1;
    if ((size_t)jl + 1 > jsonCap) return -1;

    /* MAC is computed over the packet with the hmac field zeroed */
    uint8_t tmp[SK_MAX_PACKET];
    memcpy(tmp, buf, len);
    memset(tmp + SK_HDR_LEN, 0, SK_HMAC_LEN);
    uint8_t mac[SK_HMAC_LEN];
    if (sk_hmac_sha256(key, SK_HMAC_LEN, tmp, len, mac) != 0) return -1;
    if (sk_secure_memcmp(mac, buf + SK_HDR_LEN, SK_HMAC_LEN) != 0) return -1;

    *msg_type = buf[5];
    memcpy(jsonOut, buf + SK_PKT_OVERHEAD, jl);
    jsonOut[jl] = '\0';
    return 0;
}

/* ---------- minimal flat JSON ---------- */

static const char* sk_find_key(const char* json, const char* key) {
    char pat[64];
    _snprintf(pat, sizeof(pat), "\"%s\"", key);
    pat[sizeof(pat) - 1] = '\0';
    const char* p = strstr(json, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static int sk_read_string(const char* p, char* out, size_t outCap) {
    if (*p != '"') return -1;
    p++;
    size_t n = 0;
    while (*p && *p != '"') {
        char c = *p;
        if (c == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            default:  c = *p;  break;   /* covers \" \\ \/ */
            }
        }
        if (outCap && n + 1 < outCap) out[n++] = c;
        else if (outCap) { out[outCap - 1] = '\0'; return -1; }
        p++;
    }
    if (*p != '"') return -1;
    if (outCap) out[n] = '\0';
    return 0;
}

int sk_json_get_str(const char* json, const char* key, char* out, size_t outCap) {
    const char* p = sk_find_key(json, key);
    if (!p) return -1;
    return sk_read_string(p, out, outCap);
}

long long sk_json_get_int(const char* json, const char* key, long long defval) {
    const char* p = sk_find_key(json, key);
    if (!p) return defval;
    if (*p == '"') { /* number written as string */
        char tmp[32];
        if (sk_read_string(p, tmp, sizeof(tmp)) == 0) return _atoi64(tmp);
        return defval;
    }
    return _atoi64(p);
}

int sk_json_escape(const char* in, char* out, size_t outCap) {
    size_t n = 0;
    for (const unsigned char* p = (const unsigned char*)in; *p; p++) {
        char tmp[8];
        const char* rep = NULL;
        size_t rl = 0;
        switch (*p) {
        case '"':  rep = "\\\""; rl = 2; break;
        case '\\': rep = "\\\\"; rl = 2; break;
        case '\n': rep = "\\n";  rl = 2; break;
        case '\r': rep = "\\r";  rl = 2; break;
        case '\t': rep = "\\t";  rl = 2; break;
        default:
            if (*p < 0x20) {
                _snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
                rep = tmp; rl = 6;
            }
            break;
        }
        if (rep) {
            if (n + rl + 1 > outCap) return -1;
            memcpy(out + n, rep, rl); n += rl;
        } else {
            if (n + 2 > outCap) return -1;
            out[n++] = (char)*p;
        }
    }
    out[n] = '\0';
    return 0;
}

/* ---------- utilities ---------- */

void sk_cur_time_utc(int64_t* secs) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    *secs = (int64_t)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

uint32_t sk_rand32(void) {
    uint32_t v = 0;
    if (!SK_OK(BCryptGenRandom(NULL, (PUCHAR)&v, sizeof(v),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        v = (uint32_t)GetTickCount();
    return v;
}
