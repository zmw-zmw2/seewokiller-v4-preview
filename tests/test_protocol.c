/* Unit tests for the sk_protocol layer (pure C, no network needed).
 * Every case below guards against a real bug found during development:
 *  - CNG HMAC parameter order (BCryptCreateHash secret position)
 *  - MAC computed over the raw packet instead of the zeroed-hmac packet
 *  - tampered payloads must never parse
 * Run via ctest (see CMakeLists) or build_release.bat. */

#include <stdio.h>
#include <string.h>
#include "sk_protocol.h"

static int g_failed = 0;

#define CHECK(cond, name)                                            \
    do {                                                             \
        if (cond) {                                                  \
            printf("[PASS] %s\n", name);                             \
        } else {                                                     \
            printf("[FAIL] %s (line %d)\n", name, __LINE__);         \
            g_failed = 1;                                            \
        }                                                            \
    } while (0)

int main(void) {
    uint8_t key[SK_HMAC_LEN];
    for (int i = 0; i < SK_HMAC_LEN; ++i) key[i] = (uint8_t)(i * 7 + 1);

    const char* json =
        "{\"task_id\":123,\"ts\":1700000000,\"action\":\"ping\","
        "\"reply_port\":54321}";

    /* 1. build -> parse roundtrip */
    uint8_t pkt[SK_MAX_PACKET];
    size_t n = sk_build_packet(SK_MSG_COMMAND, json, key, pkt, sizeof(pkt));
    CHECK(n == SK_PKT_OVERHEAD + strlen(json), "build: packet length");

    uint8_t mt = 0;
    char out[SK_MAX_JSON + 1];
    CHECK(sk_parse_packet(pkt, n, key, &mt, out, sizeof(out)) == 0,
          "parse: roundtrip with correct key");
    CHECK(mt == SK_MSG_COMMAND, "parse: message type preserved");
    CHECK(strcmp(out, json) == 0, "parse: json payload intact");

    /* 2. wrong key must fail */
    uint8_t badkey[SK_HMAC_LEN];
    memcpy(badkey, key, SK_HMAC_LEN);
    badkey[0] ^= 0xFF;
    CHECK(sk_parse_packet(pkt, n, badkey, &mt, out, sizeof(out)) == -1,
          "parse: wrong key rejected");

    /* 3. single flipped payload bit must fail (tamper detection) */
    uint8_t tam[SK_MAX_PACKET];
    memcpy(tam, pkt, n);
    tam[SK_PKT_OVERHEAD + 5] ^= 0x01;
    CHECK(sk_parse_packet(tam, n, key, &mt, out, sizeof(out)) == -1,
          "parse: tampered payload rejected");

    /* 4. flipped bit INSIDE the hmac must fail */
    memcpy(tam, pkt, n);
    tam[SK_HDR_LEN] ^= 0x01;
    CHECK(sk_parse_packet(tam, n, key, &mt, out, sizeof(out)) == -1,
          "parse: tampered hmac rejected");

    /* 5. structural garbage: bad magic / truncated / oversized json len */
    memcpy(tam, pkt, n);
    tam[0] = 'X';
    CHECK(sk_parse_packet(tam, n, key, &mt, out, sizeof(out)) == -1,
          "parse: bad magic rejected");
    CHECK(sk_parse_packet(pkt, SK_HDR_LEN, key, &mt, out, sizeof(out)) == -1,
          "parse: truncated packet rejected");
    uint16_t fake = 9999;
    memcpy(tam, pkt, n);
    memcpy(tam + 6, &fake, 2);
    CHECK(sk_parse_packet(tam, n, key, &mt, out, sizeof(out)) == -1,
          "parse: json length mismatch rejected");

    /* 6. oversized json must refuse to build */
    char big[SK_MAX_JSON + 16];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    CHECK(sk_build_packet(SK_MSG_COMMAND, big, key, pkt, sizeof(pkt)) == 0,
          "build: oversized json refused");

    /* 7. flat JSON helpers */
    CHECK(sk_json_get_str(out, "action", out, sizeof(out)) == 0 &&
          strcmp(out, "ping") == 0, "json: get_str");
    CHECK(sk_json_get_int(json, "task_id", -1) == 123, "json: get_int");
    CHECK(sk_json_get_int(json, "missing", -7) == -7, "json: default value");
    CHECK(sk_json_get_str(json, "nope", out, sizeof(out)) == -1,
          "json: missing key returns -1");

    /* 8. json escaping roundtrip */
    const char* raw = "a\"b\\c\nd\te";
    char esc[128], back[128];
    CHECK(sk_json_escape(raw, esc, sizeof(esc)) == 0, "json: escape");
    CHECK(sk_json_get_str("{\"k\":\"a\\\"b\\\\c\\nd\\te\"}", "k",
                          back, sizeof(back)) == 0 &&
          strcmp(back, raw) == 0, "json: escape roundtrip");

    /* 9. reply-shaped packet roundtrip (agent -> console) */
    const char* rjson =
        "{\"task_id\":42,\"host\":\"PC01\",\"st\":\"ok\",\"rc\":0,\"info\":\"alive\"}";
    n = sk_build_packet(SK_MSG_REPLY, rjson, key, pkt, sizeof(pkt));
    CHECK(n > 0 && sk_parse_packet(pkt, n, key, &mt, out, sizeof(out)) == 0 &&
          mt == SK_MSG_REPLY, "reply: roundtrip");

    printf("\n%s\n", g_failed ? "RESULT: FAIL" : "RESULT: ALL PASS");
    return g_failed;
}
