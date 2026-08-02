/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_control.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static uint32_t
read_be32(const uint8_t *data)
{
    uint32_t value;

    memcpy(&value, data, sizeof(value));
    return ntohl(value);
}

static uint16_t
read_be16(const uint8_t *data)
{
    uint16_t value;

    memcpy(&value, data, sizeof(value));
    return ntohs(value);
}

static uint64_t
to_be64(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

static size_t
build_upsert(uint8_t *message, size_t capacity, uint32_t xid,
             uint64_t generation)
{
    struct n3iwf_dp_wire_header header = {0};
    struct n3iwf_dp_session_wire session = {0};
    size_t total = sizeof(header) + sizeof(session);

    assert(capacity >= total);
    header.magic = htonl(N3IWF_DP_WIRE_MAGIC);
    header.version = htons(N3IWF_DP_WIRE_VERSION);
    header.type = htons(N3IWF_DP_MSG_SESSION_UPSERT);
    header.length = htonl((uint32_t)total);
    header.transaction_id = htonl(xid);
    header.generation = to_be64(generation);

    session.ue_id = to_be64(42);
    session.pdu_session_id = htonl(10);
    session.uplink_teid = htonl(100);
    session.downlink_teid = htonl(200);
    session.address_family = N3IWF_DP_AF_IPV4;
    session.qfi_count = 1;
    session.ue_pdu_address[0] = 10;
    session.ue_pdu_address[3] = 42;
    session.ue_nwu_address[0] = 192;
    session.ue_nwu_address[1] = 168;
    session.ue_nwu_address[2] = 127;
    session.ue_nwu_address[3] = 2;
    session.qfi[0] = 5;

    memcpy(message, &header, sizeof(header));
    memcpy(message + sizeof(header), &session, sizeof(session));
    return total;
}

static uint32_t
response_status(const uint8_t *response, size_t length, uint32_t expected_xid)
{
    assert(length == sizeof(struct n3iwf_dp_wire_header) +
                     sizeof(struct n3iwf_dp_ack_wire));
    assert(read_be32(response + 0) == N3IWF_DP_WIRE_MAGIC);
    assert(read_be16(response + 6) == N3IWF_DP_MSG_ACK);
    assert(read_be32(response + 12) == expected_xid);
    return read_be32(response + sizeof(struct n3iwf_dp_wire_header));
}

int
main(void)
{
    int sockets[2];
    struct n3iwf_dp_session_table table;
    struct n3iwf_dp_stats_wire stats = {0};
    struct n3iwf_dp_control control = {0};
    uint8_t request[N3IWF_DP_CONTROL_MAX_MESSAGE];
    uint8_t response[128];
    size_t request_len;
    ssize_t response_len;

    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) == 0);
    n3iwf_dp_session_table_init(&table);
    control.listen_fd = STDIN_FILENO;
    control.client_fd = sockets[0];
    control.sessions = &table;
    control.stats = &stats;

    request_len = build_upsert(request, sizeof(request), 7, 1);
    assert(send(sockets[1], request, request_len, 0) == (ssize_t)request_len);
    assert(n3iwf_dp_control_poll(&control) == 0);
    response_len = recv(sockets[1], response, sizeof(response), 0);
    assert(response_status(response, (size_t)response_len, 7) ==
           N3IWF_DP_STATUS_OK);
    assert(table.count == 1);

    request_len = build_upsert(request, sizeof(request), 8, 1);
    assert(send(sockets[1], request, request_len, 0) == (ssize_t)request_len);
    assert(n3iwf_dp_control_poll(&control) == 0);
    response_len = recv(sockets[1], response, sizeof(response), 0);
    assert(response_status(response, (size_t)response_len, 8) ==
           N3IWF_DP_STATUS_STALE_GENERATION);
    assert(stats.stale_updates == 1);

    close(sockets[0]);
    close(sockets[1]);
    puts("n3iwf_dp_control_test: PASS");
    return 0;
}
