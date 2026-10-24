#pragma once
// Shared wire protocol for SeewoKiller <-> skagent (pure C, no deps).
//
// Packet layout (little-endian):
//   [0..4)   magic "SKAG"
//   [4]      protocol version
//   [5]      msg type (1=command, 2=reply)
//   [6..8)   json length
//   [8..40)  HMAC-SHA256 over the WHOLE packet with this field zeroed
//   [40..)   JSON payload (UTF-8, flat key/value only)

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SK_MAGIC            0x47414B53u   /* "SKAG" */
#define SK_PROTO_VERSION    1
#define SK_HMAC_LEN         32
#define SK_HDR_LEN          8
#define SK_PKT_OVERHEAD     (SK_HDR_LEN + SK_HMAC_LEN)
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

/* HMAC-SHA256 via CNG. Returns 0 on success. */
int sk_hmac_sha256(const uint8_t* key, size_t keyLen,
                   const uint8_t* data, size_t dataLen, uint8_t out[SK_HMAC_LEN]);

/* Build a signed packet. Returns total length, or 0 on error/too long. */
size_t sk_build_packet(uint8_t msg_type, const char* json,
                       const uint8_t key[SK_HMAC_LEN],
                       uint8_t* out, size_t outCap);

/* Verify signature and parse. Returns 0 on success (jsonOut is
 * NUL-terminated), -1 on bad packet/signature. */
int sk_parse_packet(const uint8_t* buf, size_t len, const uint8_t key[SK_HMAC_LEN],
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
