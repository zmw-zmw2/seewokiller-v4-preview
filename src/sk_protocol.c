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

#ifndef BCRYPT_ECDSA_P256_ALGORITHM
#define BCRYPT_ECDSA_P256_ALGORITHM L"ECDSA_P256"
#endif
#ifndef BCRYPT_ECCPUBLIC_BLOB
#define BCRYPT_ECCPUBLIC_BLOB L"ECCPUBLICBLOB"
#endif
#ifndef BCRYPT_ECCPRIVATE_BLOB
#define BCRYPT_ECCPRIVATE_BLOB L"ECCPRIVATEBLOB"
#endif

/* ---------- SHA-256 ---------- */

int sk_sha256(const uint8_t* data, size_t dataLen, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!SK_OK(st)) return -1;

    st = BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0);
    if (SK_OK(st)) {
        st = BCryptHashData(h, (PUCHAR)data, (ULONG)dataLen, 0);
        if (SK_OK(st)) st = BCryptFinishHash(h, out, 32, 0);
    }
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return SK_OK(st) ? 0 : -1;
}

/* ---------- ECDSA P-256 via CNG ---------- */

int sk_ecdsa_genkeypair(uint8_t priv[SK_PRIV_LEN], uint8_t pub[SK_PUB_LEN]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS st;
    int rc = -1;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!SK_OK(st)) return -1;

    st = BCryptGenerateKeyPair(alg, &key, 256, 0);
    if (SK_OK(st)) st = BCryptFinalizeKeyPair(key, 0);

    ULONG cb = 0;
    if (SK_OK(st)) {
        st = BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB,
                             NULL, 0, &cb, 0);
        if (SK_OK(st) && cb != SK_PRIV_LEN) st = (NTSTATUS)0xC0000009BL;
        else if (SK_OK(st))
            st = BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 (PUCHAR)priv, SK_PRIV_LEN, &cb, 0);
    }
    if (SK_OK(st)) {
        st = BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB,
                             NULL, 0, &cb, 0);
        if (SK_OK(st) && cb != SK_PUB_LEN) st = (NTSTATUS)0xC0000009BL;
        else if (SK_OK(st))
            st = BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                 (PUCHAR)pub, SK_PUB_LEN, &cb, 0);
    }
    rc = SK_OK(st) ? 0 : -1;

    if (key) BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}

int sk_ecdsa_sign(const uint8_t priv[SK_PRIV_LEN], const uint8_t hash[32],
                  uint8_t sig[SK_SIG_LEN]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS st;
    ULONG cb = 0;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!SK_OK(st)) return -1;

    st = BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPRIVATE_BLOB, &key,
                             (PUCHAR)priv, SK_PRIV_LEN, 0);
    if (SK_OK(st))
        st = BCryptSignHash(key, NULL, (PUCHAR)hash, 32,
                            sig, SK_SIG_LEN, &cb, 0);
    if (key) BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return SK_OK(st) ? 0 : -1;
}

int sk_ecdsa_verify(const uint8_t pub[SK_PUB_LEN], const uint8_t hash[32],
                    const uint8_t sig[SK_SIG_LEN]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!SK_OK(st)) return -1;

    st = BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &key,
                             (PUCHAR)pub, SK_PUB_LEN, 0);
    if (SK_OK(st))
        st = BCryptVerifySignature(key, NULL, (PUCHAR)hash, 32,
                                   (PUCHAR)sig, SK_SIG_LEN, 0);
    if (key) BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return SK_OK(st) ? 0 : -1;
}

/* ---------- packet build / parse ---------- */

size_t sk_build_packet(uint8_t msg_type, const char* json,
                       const uint8_t* privKey,
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

    /* signature over the whole packet with the sig field zeroed */
    if (privKey) {
        uint8_t h[32];
        if (sk_sha256(out, SK_PKT_OVERHEAD + jl, h) != 0) return 0;
        if (sk_ecdsa_sign(privKey, h, out + SK_HDR_LEN) != 0) return 0;
    }
    return SK_PKT_OVERHEAD + jl;
}

int sk_parse_packet(const uint8_t* buf, size_t len,
                    const uint8_t* pubKey,
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

    if (pubKey) {
        /* verify over the packet with the sig field zeroed */
        uint8_t tmp[SK_MAX_PACKET];
        memcpy(tmp, buf, len);
        memset(tmp + SK_HDR_LEN, 0, SK_SIG_LEN);
        uint8_t h[32];
        if (sk_sha256(tmp, len, h) != 0) return -1;
        if (sk_ecdsa_verify(pubKey, h, buf + SK_HDR_LEN) != 0) return -1;
    }

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
