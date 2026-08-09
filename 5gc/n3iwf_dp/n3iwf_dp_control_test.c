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
read_be64(const uint8_t *data)
{
    uint64_t value;

    memcpy(&value, data, sizeof(value));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
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
build_hello(uint8_t *message, size_t capacity, uint32_t xid, uint8_t role)
{
    struct n3iwf_dp_wire_header header = {0};
    struct n3iwf_dp_hello_wire hello = {0};
    size_t total = sizeof(header) + sizeof(hello);
    assert(capacity >= total);
    header.magic = htonl(N3IWF_DP_WIRE_MAGIC);
    header.version = htons(N3IWF_DP_WIRE_VERSION);
    header.type = htons(N3IWF_DP_MSG_HELLO);
    header.length = htonl((uint32_t)total);
    header.transaction_id = htonl(xid);
    hello.role = role;
    memcpy(message, &header, sizeof(header));
    memcpy(message + sizeof(header), &hello, sizeof(hello));
    return total;
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

static size_t
build_stats_get(uint8_t *message, size_t capacity, uint32_t xid)
{
    struct n3iwf_dp_wire_header header = {0};

    assert(capacity >= sizeof(header));
    header.magic = htonl(N3IWF_DP_WIRE_MAGIC);
    header.version = htons(N3IWF_DP_WIRE_VERSION);
    header.type = htons(N3IWF_DP_MSG_STATS_GET);
    header.length = htonl((uint32_t)sizeof(header));
    header.transaction_id = htonl(xid);
    memcpy(message, &header, sizeof(header));
    return sizeof(header);
}

static size_t
build_child_sa_upsert(uint8_t *message, size_t capacity, uint32_t xid,
                      uint64_t generation)
{
    struct n3iwf_dp_wire_header header = {0};
    struct n3iwf_dp_child_sa_wire sa = {0};
    size_t total = sizeof(header) + sizeof(sa);
    assert(capacity >= total);
    header.magic = htonl(N3IWF_DP_WIRE_MAGIC);
    header.version = htons(N3IWF_DP_WIRE_VERSION);
    header.type = htons(N3IWF_DP_MSG_CHILD_SA_UPSERT);
    header.length = htonl((uint32_t)total);
    header.transaction_id = htonl(xid);
    header.generation = to_be64(generation);
    sa.ue_id = to_be64(42);
    sa.pdu_session_id = htonl(10);
    sa.inbound_spi = htonl(1001);
    sa.outbound_spi = htonl(1002);
    sa.encryption_id = htons(12);
    sa.integrity_id = htons(2);
    sa.replay_window = htonl(64);
    sa.address_family = N3IWF_DP_AF_IPV4;
    sa.ip_protocol = 47;
    sa.inbound_encryption_key_len = 16;
    sa.outbound_encryption_key_len = 16;
    sa.inbound_integrity_key_len = 20;
    sa.outbound_integrity_key_len = 20;
    memset(sa.inbound_encryption_key, 1, 16);
    memset(sa.outbound_encryption_key, 2, 16);
    memset(sa.inbound_integrity_key, 3, 20);
    memset(sa.outbound_integrity_key, 4, 20);
    memcpy(message, &header, sizeof(header));
    memcpy(message + sizeof(header), &sa, sizeof(sa));
    memset(&sa, 0, sizeof(sa));
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
    int observer_sockets[2];
    struct n3iwf_dp_session_table table;
    struct n3iwf_dp_child_sa_table child_sas;
    struct n3iwf_dp_stats_wire stats = {0};
    struct n3iwf_dp_control control = {0};
    uint8_t request[N3IWF_DP_CONTROL_MAX_MESSAGE];
    uint8_t response[192];
    size_t request_len;
    ssize_t response_len;

    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) == 0);
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, observer_sockets) == 0);
    n3iwf_dp_session_table_init(&table);
    n3iwf_dp_child_sa_table_init(&child_sas);
    /* A connected seqpacket socket makes accept() return EINVAL, which the
     * non-blocking poller deliberately tolerates in this unit test. */
    control.listen_fd = sockets[0];
    for (size_t index = 0; index < N3IWF_DP_CONTROL_MAX_CLIENTS; ++index) {
        control.client_fds[index] = -1;
    }
    control.client_fds[0] = sockets[0];
    control.client_fds[1] = observer_sockets[0];
    control.sessions = &table;
    control.child_sas = &child_sas;
    control.stats = &stats;

    request_len = build_hello(request, sizeof(request), 1,
                              N3IWF_DP_ROLE_WRITER);
    response_len = send(sockets[1], request, request_len, 0);
    if (response_len != (ssize_t)request_len) {
        perror("send writer hello");
    }
    assert(response_len == (ssize_t)request_len);
    assert(n3iwf_dp_control_poll(&control) == 0);
    response_len = recv(sockets[1], response, sizeof(response), 0);
    assert(response_status(response, (size_t)response_len, 1) ==
           N3IWF_DP_STATUS_OK);

    request_len = build_hello(request, sizeof(request), 2,
                              N3IWF_DP_ROLE_OBSERVER);
    assert(send(observer_sockets[1], request, request_len, 0) ==
           (ssize_t)request_len);
    assert(n3iwf_dp_control_poll(&control) == 0);
    response_len = recv(observer_sockets[1], response, sizeof(response), 0);
    assert(response_status(response, (size_t)response_len, 2) ==
           N3IWF_DP_STATUS_OK);

    request_len = build_hello(request, sizeof(request), 20,
                              N3IWF_DP_ROLE_WRITER);
    assert(send(observer_sockets[1], request, request_len, 0) ==
           (ssize_t)request_len);
    assert(n3iwf_dp_control_poll(&control) == 0);
    response_len = recv(observer_sockets[1], response, sizeof(response), 0);
    assert(response_status(response, (size_t)response_len, 20) ==
           N3IWF_DP_STATUS_CAPACITY);

    request_len = build_child_sa_upsert(request, sizeof(request), 3, 1);
    assert(send(observer_sockets[1], request, request_len, 0) ==
           (ssize_t)request_len);
    assert(n3iwf_dp_control_poll(&control) == 0);
    response_len = recv(observer_sockets[1], response, sizeof(response), 0);
    assert(response_status(response, (size_t)response_len, 3) ==
           N3IWF_DP_STATUS_UNSUPPORTED);
    assert(child_sas.count == 0);

    request_len = build_child_sa_upsert(request, sizeof(request), 4, 1);
    assert(send(sockets[1], request, request_len, 0) == (ssize_t)request_len);
    assert(n3iwf_dp_control_poll(&control) == 0);
    response_len = recv(sockets[1], response, sizeof(response), 0);
    assert(response_status(response, (size_t)response_len, 4) ==
           N3IWF_DP_STATUS_OK);
    assert(child_sas.count == 1);

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

    stats.uplink_packets = 11;
    stats.downlink_packets = 12;
    stats.unknown_teid = 13;
    stats.unknown_qfi = 14;
    stats.malformed_packets = 15;
    stats.replay_drops = 16;
    stats.crypto_failures = 17;
    stats.fragment_drops = 18;
    stats.control_to_cp = 20;
    stats.control_from_cp = 21;
    stats.control_punt_drops = 22;
    stats.access_mac_learns = 23;
    stats.access_mac_changes = 24;
    stats.access_neighbor_drops = 25;
    request_len = build_stats_get(request, sizeof(request), 9);
    assert(send(observer_sockets[1], request, request_len, 0) ==
           (ssize_t)request_len);
    assert(n3iwf_dp_control_poll(&control) == 0);
    response_len = recv(observer_sockets[1], response, sizeof(response), 0);
    assert(response_len == (ssize_t)(sizeof(struct n3iwf_dp_wire_header) +
                                      sizeof(struct n3iwf_dp_stats_wire)));
    assert(read_be32(response + 0) == N3IWF_DP_WIRE_MAGIC);
    assert(read_be16(response + 6) == N3IWF_DP_MSG_STATS);
    assert(read_be32(response + 12) == 9);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 0) == 11);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 8) == 12);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 16) == 13);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 24) == 14);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 32) == 15);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 40) == 16);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 48) == 17);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 56) == 18);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 64) == 1);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 72) == 20);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 80) == 21);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 88) == 22);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 96) == 23);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 104) == 24);
    assert(read_be64(response + sizeof(struct n3iwf_dp_wire_header) + 112) == 25);

    close(sockets[0]);
    close(sockets[1]);
    close(observer_sockets[0]);
    close(observer_sockets[1]);
    puts("n3iwf_dp_control_test: PASS");
    return 0;
}
