#pragma once
// Shared wire protocol for SeewoKiller <-> skagent (pure C, no deps).
//
// Packet layout v2 (little-endian):
//   [0..4)    magic "SKAG"
//   [4]       protocol version (2)
//   [5]       msg type (1=command, 2=reply)
//   [6..8)    json length
//   [8..72)   ECDSA P-256 signature (r||s, 32+32 bytes LE) over the WHOLE
//             packet with this field zeroed. Commands are signed by the
//             controller's private key; agents hold only the public key.
//             Agent replies carry a zero signature (agents hold no private
//             key; forged replies are harmless by design).
//   [72..)    JSON payload (UTF-8, flat key/value only)

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SK_MAGIC            0x47414B53u   /* "SKAG" */
#define SK_PROTO_VERSION    2
#define SK_SIG_LEN          64
#define SK_PRIV_LEN         104           /* BCRYPT_ECCPRIVATE_BLOB, P-256 */
#define SK_PUB_LEN          72            /* BCRYPT_ECCPUBLIC_BLOB, P-256 */
#define SK_HDR_LEN          8
#define SK_PKT_OVERHEAD     (SK_HDR_LEN + SK_SIG_LEN)
#define SK_MAX_JSON         2048
#define SK_MAX_PACKET       (SK_PKT_OVERHEAD + SK_MAX_JSON)

#define SK_MSG_COMMAND      1
#define SK_MSG_REPLY        2

/* Fixed agent-side listener (multicast) */
#define SK_MCAST_GROUP      "239.255.17.23"
#define SK_MCAST_PORT       47381

/* Accepted clock skew for the anti-replay window, seconds */
#define SK_REPLAY_WINDOW    900

typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  msg_type;
    uint16_t json_len;
} SkHeader;

/* Plain SHA-256 (no key). Returns 0 on success. */
int sk_sha256(const uint8_t* data, size_t dataLen, uint8_t out[32]);

/* Generate an ECDSA P-256 keypair (raw CNG blobs). Returns 0 on success. */
int sk_ecdsa_genkeypair(uint8_t priv[SK_PRIV_LEN], uint8_t pub[SK_PUB_LEN]);

/* Sign a 32-byte digest. Returns 0 on success. */
int sk_ecdsa_sign(const uint8_t priv[SK_PRIV_LEN], const uint8_t hash[32],
                  uint8_t sig[SK_SIG_LEN]);

/* Verify a signature over a 32-byte digest. Returns 0 if valid, -1 if not. */
int sk_ecdsa_verify(const uint8_t pub[SK_PUB_LEN], const uint8_t hash[32],
                    const uint8_t sig[SK_SIG_LEN]);

/* Build a packet. privKey=NULL emits a zero signature (agent replies).
 * Returns total length, or 0 on error/too long. */
size_t sk_build_packet(uint8_t msg_type, const char* json,
                       const uint8_t* privKey /*nullable, SK_PRIV_LEN*/,
                       uint8_t* out, size_t outCap);

/* Verify signature and parse. pubKey=NULL skips the signature check
 * (controller reading unsigned agent replies). Returns 0 on success
 * (jsonOut is NUL-terminated), -1 on bad packet/signature. */
int sk_parse_packet(const uint8_t* buf, size_t len,
                    const uint8_t* pubKey /*nullable, SK_PUB_LEN*/,
                    uint8_t* msg_type, char* jsonOut, size_t jsonCap);

/* Flat-JSON helpers (objects of scalars only). */
int    sk_json_get_str(const char* json, const char* key, char* out, size_t outCap);
long long sk_json_get_int(const char* json, const char* key, long long defval);

/* Escape a byte string for embedding as a JSON string value. Returns 0/-1. */
int sk_json_escape(const char* in, char* out, size_t outCap);

/* Utilities */
void     sk_cur_time_utc(int64_t* secs);
uint32_t sk_rand32(void);

#ifdef __cplusplus
}
#endif
