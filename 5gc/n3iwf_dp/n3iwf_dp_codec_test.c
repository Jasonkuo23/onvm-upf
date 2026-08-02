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
                     uint8_t qfi)
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

    assert(n3iwf_dp_gre_build(gre, sizeof(gre), protocol, qfi, inner,
                              sizeof(inner), &gre_len) == 0);
    assert(n3iwf_dp_gre_parse(gre, gre_len, &gre_view) == 0);
    assert(gre_view.qfi == qfi);
    assert(gre_view.protocol == protocol);
    assert(gre_view.payload_len == sizeof(inner));

    assert(n3iwf_dp_gtpu_build(gtpu, sizeof(gtpu), 0x01020304U, qfi,
                               direction, gre_view.payload,
                               gre_view.payload_len, &gtpu_len) == 0);
    assert(n3iwf_dp_gtpu_parse(gtpu, gtpu_len, &gtp_view) == 0);
    assert(gtp_view.teid == 0x01020304U);
    assert(gtp_view.qfi == qfi);
    assert(gtp_view.direction == direction);
    assert(gtp_view.payload_len == sizeof(inner));
    assert(memcmp(gtp_view.payload, inner, sizeof(inner)) == 0);
}

static void
test_malformed_packets(void)
{
    uint8_t buffer[32] = {0};
    size_t encoded_len = 0;
    struct n3iwf_dp_gtpu_view view;
    struct n3iwf_dp_gre_view gre_view;

    assert(n3iwf_dp_gtpu_build(buffer, sizeof(buffer), 1, 0,
                               N3IWF_DP_UPLINK, buffer, 1,
                               &encoded_len) == -EINVAL);
    assert(n3iwf_dp_gtpu_build(buffer, sizeof(buffer), 1, 64,
                               N3IWF_DP_UPLINK, buffer, 1,
                               &encoded_len) == -EINVAL);
    assert(n3iwf_dp_gtpu_parse(buffer, 7, &view) == -EINVAL);

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 0x00;
    buffer[2] = 0x08;
    buffer[3] = 0x00;
    assert(n3iwf_dp_gre_parse(buffer, 8, &gre_view) == -EPROTO);
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
    test_gtpu_round_trip(N3IWF_DP_GRE_PROTO_IPV4, N3IWF_DP_UPLINK, 1);
    test_gtpu_round_trip(N3IWF_DP_GRE_PROTO_IPV4, N3IWF_DP_DOWNLINK, 9);
    test_gtpu_round_trip(N3IWF_DP_GRE_PROTO_IPV6, N3IWF_DP_UPLINK, 63);
    test_gtpu_round_trip(N3IWF_DP_GRE_PROTO_IPV6, N3IWF_DP_DOWNLINK, 17);
    test_malformed_packets();
    test_wire_validation();
    puts("n3iwf_dp_codec_test: PASS");
    return 0;
}
