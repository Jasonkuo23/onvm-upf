/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_wire.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

static uint64_t
host_to_be64(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

static uint64_t
be64_to_host(uint64_t value)
{
    return host_to_be64(value);
}

int
n3iwf_dp_wire_validate(const uint8_t *message, size_t message_len,
                       uint16_t *type, uint64_t *generation,
                       const uint8_t **payload, size_t *payload_len)
{
    struct n3iwf_dp_wire_header header;
    size_t declared_len;

    if (message == NULL || type == NULL || generation == NULL ||
        payload == NULL || payload_len == NULL ||
        message_len < sizeof(header)) {
        return -EINVAL;
    }
    memcpy(&header, message, sizeof(header));
    declared_len = ntohl(header.length);
    if (ntohl(header.magic) != N3IWF_DP_WIRE_MAGIC) {
        return -EBADMSG;
    }
    if (ntohs(header.version) != N3IWF_DP_WIRE_VERSION) {
        return -EPROTONOSUPPORT;
    }
    if (declared_len != message_len || declared_len < sizeof(header)) {
        return -EMSGSIZE;
    }

    *type = ntohs(header.type);
    *generation = be64_to_host(header.generation);
    *payload = message + sizeof(header);
    *payload_len = declared_len - sizeof(header);
    return 0;
}

size_t
n3iwf_dp_wire_encode_ack(uint8_t *out, size_t capacity, uint32_t transaction_id,
                         uint64_t generation, enum n3iwf_dp_status status,
                         uint32_t detail)
{
    struct n3iwf_dp_wire_header header;
    struct n3iwf_dp_ack_wire ack;
    const size_t total_len = sizeof(header) + sizeof(ack);

    if (out == NULL || capacity < total_len) {
        return 0;
    }
    memset(&header, 0, sizeof(header));
    header.magic = htonl(N3IWF_DP_WIRE_MAGIC);
    header.version = htons(N3IWF_DP_WIRE_VERSION);
    header.type = htons(N3IWF_DP_MSG_ACK);
    header.length = htonl((uint32_t)total_len);
    header.transaction_id = htonl(transaction_id);
    header.generation = host_to_be64(generation);

    ack.status = htonl((uint32_t)status);
    ack.detail = htonl(detail);
    ack.applied_generation = host_to_be64(generation);
    memcpy(out, &header, sizeof(header));
    memcpy(out + sizeof(header), &ack, sizeof(ack));
    return total_len;
}
