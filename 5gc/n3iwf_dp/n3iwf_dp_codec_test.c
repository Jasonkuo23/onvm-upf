/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_codec.h"
#include "n3iwf_dp_wire.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static uint64_t
to_be64(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

static void
test_gtpu_round_trip(uint16_t protocol, enum n3iwf_dp_direction direction,
                     uint8_t qfi, bool rqi)
{
    uint8_t inner[64] = {0};
    uint8_t gtpu[128] = {0};
    uint8_t gre[128] = {0};
    size_t gtpu_len = 0;
    size_t gre_len = 0;
    struct n3iwf_dp_gtpu_view gtp_view;
    struct n3iwf_dp_gre_view gre_view;

    inner[0] = protocol == N3IWF_DP_GRE_PROTO_IPV4 ? 0x45 : 0x60;
    inner[1] = qfi;

    assert(n3iwf_dp_gre_build(gre, sizeof(gre), protocol, qfi, rqi,
                              direction, inner, sizeof(inner), &gre_len) == 0);
    assert(n3iwf_dp_gre_parse(gre, gre_len, direction, &gre_view) == 0);
    assert(gre_view.qfi == qfi);
    assert(gre_view.rqi == rqi);
    assert(gre_view.key == (((uint32_t)qfi << 24) |
                            (rqi ? UINT32_C(0x80) : 0)));
    assert(gre_view.protocol == protocol);
    assert(gre_view.payload_len == sizeof(inner));

    assert(n3iwf_dp_gtpu_build(gtpu, sizeof(gtpu), 0x01020304U, qfi, rqi,
                               direction, gre_view.payload,
                               gre_view.payload_len, &gtpu_len) == 0);
    assert(n3iwf_dp_gtpu_parse(gtpu, gtpu_len, &gtp_view) == 0);
    assert(gtp_view.teid == 0x01020304U);
    assert(gtp_view.qfi == qfi);
    assert(gtp_view.rqi == rqi);
    assert(gtp_view.direction == direction);
    assert(gtp_view.payload_len == sizeof(inner));
    assert(memcmp(gtp_view.payload, inner, sizeof(inner)) == 0);
}

static void
test_directional_golden_headers(void)
{
    static const uint8_t expected_dl_gtpu[] = {
        0x34, 0xff, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x49, 0x00,
    };
    static const uint8_t expected_ul_gtpu[] = {
        0x34, 0xff, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x00, 0x00, 0x85, 0x01, 0x10, 0x09, 0x00,
    };
    static const uint8_t expected_dl_gre[] = {
        0x20, 0x00, 0x08, 0x00, 0x09, 0x00, 0x00, 0x80,
    };
    static const uint8_t expected_ul_gre[] = {
        0x20, 0x00, 0x86, 0xdd, 0x09, 0x00, 0x00, 0x00,
    };
    uint8_t packet[32] = {0};
    size_t encoded_len = 0;

    assert(n3iwf_dp_gtpu_build(packet, sizeof(packet), 0x01020304U, 9, true,
                               N3IWF_DP_DOWNLINK, NULL, 0,
                               &encoded_len) == 0);
    assert(encoded_len == sizeof(expected_dl_gtpu));
    assert(memcmp(packet, expected_dl_gtpu, sizeof(expected_dl_gtpu)) == 0);

    assert(n3iwf_dp_gtpu_build(packet, sizeof(packet), 0x01020304U, 9, false,
                               N3IWF_DP_UPLINK, NULL, 0,
                               &encoded_len) == 0);
    assert(memcmp(packet, expected_ul_gtpu, sizeof(expected_ul_gtpu)) == 0);

    assert(n3iwf_dp_gre_build(packet, sizeof(packet),
                              N3IWF_DP_GRE_PROTO_IPV4, 9, true,
                              N3IWF_DP_DOWNLINK, NULL, 0,
                              &encoded_len) == 0);
    assert(memcmp(packet, expected_dl_gre, sizeof(expected_dl_gre)) == 0);

    assert(n3iwf_dp_gre_build(packet, sizeof(packet),
                              N3IWF_DP_GRE_PROTO_IPV6, 9, false,
                              N3IWF_DP_UPLINK, NULL, 0,
                              &encoded_len) == 0);
    assert(memcmp(packet, expected_ul_gre, sizeof(expected_ul_gre)) == 0);
}

static void
test_gtpu_extension_chain_preserves_rqi(void)
{
    /* A UDP-Port extension precedes the PSC. This exercises traversal rather
     * than assuming that the PSC is the first extension header. */
    static const uint8_t packet[] = {
        0x34, 0xff, 0x00, 0x0c, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x00, 0x00, 0x40,
        0x01, 0x08, 0x68, 0x85,
        0x01, 0x00, 0x49, 0x00,
    };
    struct n3iwf_dp_gtpu_view view;

    assert(n3iwf_dp_gtpu_parse(packet, sizeof(packet), &view) == 0);
    assert(view.header_len == sizeof(packet));
    assert(view.teid == 0x01020304U);
    assert(view.direction == N3IWF_DP_DOWNLINK);
    assert(view.qfi == 9 && view.rqi);
}

static void
test_malformed_packets(void)
{
    static const uint8_t duplicate_psc[] = {
        0x34, 0xff, 0x00, 0x0c, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x00, 0x00, 0x85,
        0x01, 0x00, 0x09, 0x85,
        0x01, 0x00, 0x09, 0x00,
    };
    uint8_t buffer[32] = {0};
    size_t encoded_len = 0;
    struct n3iwf_dp_gtpu_view view;
    struct n3iwf_dp_gre_view gre_view;

    assert(n3iwf_dp_gtpu_build(buffer, sizeof(buffer), 1, 0, false,
                               N3IWF_DP_UPLINK, buffer, 1,
                               &encoded_len) == -EINVAL);
    assert(n3iwf_dp_gtpu_build(buffer, sizeof(buffer), 1, 64, false,
                               N3IWF_DP_UPLINK, buffer, 1,
                               &encoded_len) == -EINVAL);
    assert(n3iwf_dp_gtpu_build(buffer, sizeof(buffer), 1, 9, true,
                               N3IWF_DP_UPLINK, buffer, 1,
                               &encoded_len) == -EINVAL);
    assert(n3iwf_dp_gtpu_parse(buffer, 7, &view) == -EINVAL);
    assert(n3iwf_dp_gtpu_parse(duplicate_psc, sizeof(duplicate_psc),
                               &view) == -EPROTO);

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 0x00;
    buffer[2] = 0x08;
    buffer[3] = 0x00;
    assert(n3iwf_dp_gre_parse(buffer, 8, N3IWF_DP_UPLINK,
                              &gre_view) == -EPROTO);

    assert(n3iwf_dp_gtpu_build(buffer, sizeof(buffer), 1, 9, false,
                               N3IWF_DP_UPLINK, NULL, 0,
                               &encoded_len) == 0);
    buffer[14] |= 0x40U; /* New-IE flag in UL, not RQI. */
    assert(n3iwf_dp_gtpu_parse(buffer, encoded_len, &view) == -EOPNOTSUPP);

    assert(n3iwf_dp_gre_build(buffer, sizeof(buffer),
                              N3IWF_DP_GRE_PROTO_IPV4, 9, false,
                              N3IWF_DP_UPLINK, NULL, 0,
                              &encoded_len) == 0);
    buffer[7] |= 0x80U;
    assert(n3iwf_dp_gre_parse(buffer, encoded_len, N3IWF_DP_UPLINK,
                              &gre_view) == -EPROTO);
    assert(n3iwf_dp_gre_parse(buffer, encoded_len, N3IWF_DP_DOWNLINK,
                              &gre_view) == 0);
    buffer[7] |= 0x01U;
    assert(n3iwf_dp_gre_parse(buffer, encoded_len, N3IWF_DP_DOWNLINK,
                              &gre_view) == -EPROTO);
}

static void
test_wire_validation(void)
{
    uint8_t message[sizeof(struct n3iwf_dp_wire_header)] = {0};
    struct n3iwf_dp_wire_header header = {0};
    uint16_t type = 0;
    uint64_t generation = 0;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;

    header.magic = htonl(N3IWF_DP_WIRE_MAGIC);
    header.version = htons(N3IWF_DP_WIRE_VERSION);
    header.type = htons(N3IWF_DP_MSG_HELLO);
    header.length = htonl(sizeof(header));
    header.transaction_id = htonl(7);
    header.generation = to_be64(42);
    memcpy(message, &header, sizeof(header));

    assert(n3iwf_dp_wire_validate(message, sizeof(message), &type, &generation,
                                  &payload, &payload_len) == 0);
    assert(type == N3IWF_DP_MSG_HELLO);
    assert(generation == 42);
    assert(payload_len == 0);

    message[0] = 0;
    assert(n3iwf_dp_wire_validate(message, sizeof(message), &type, &generation,
                                  &payload, &payload_len) == -EBADMSG);
}

int
main(void)
{
    test_gtpu_round_trip(N3IWF_DP_GRE_PROTO_IPV4, N3IWF_DP_UPLINK, 1,
                         false);
    test_gtpu_round_trip(N3IWF_DP_GRE_PROTO_IPV4, N3IWF_DP_DOWNLINK, 9,
                         false);
    test_gtpu_round_trip(N3IWF_DP_GRE_PROTO_IPV4, N3IWF_DP_DOWNLINK, 9,
                         true);
    test_gtpu_round_trip(N3IWF_DP_GRE_PROTO_IPV6, N3IWF_DP_UPLINK, 63,
                         false);
    test_gtpu_round_trip(N3IWF_DP_GRE_PROTO_IPV6, N3IWF_DP_DOWNLINK, 17,
                         false);
    test_gtpu_round_trip(N3IWF_DP_GRE_PROTO_IPV6, N3IWF_DP_DOWNLINK, 17,
                         true);
    test_directional_golden_headers();
    test_gtpu_extension_chain_preserves_rqi();
    test_malformed_packets();
    test_wire_validation();
    puts("n3iwf_dp_codec_test: PASS");
    return 0;
}
