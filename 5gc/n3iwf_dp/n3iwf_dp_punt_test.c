/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_punt.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FRAME_CAPACITY 128U

static void
put_be16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

static size_t
build_udp(uint8_t *frame, const char *source, const char *destination,
          uint16_t source_port, uint16_t destination_port,
          const uint8_t *payload, size_t payload_length)
{
    uint8_t *ip = frame + 14;
    uint8_t *udp = ip + 20;
    size_t ip_length = 20 + 8 + payload_length;

    memset(frame, 0, FRAME_CAPACITY);
    put_be16(frame + 12, 0x0800);
    ip[0] = 0x45;
    put_be16(ip + 2, (uint16_t)ip_length);
    ip[8] = 64;
    ip[9] = 17;
    assert(inet_pton(AF_INET, source, ip + 12) == 1);
    assert(inet_pton(AF_INET, destination, ip + 16) == 1);
    put_be16(udp, source_port);
    put_be16(udp + 2, destination_port);
    put_be16(udp + 4, (uint16_t)(8 + payload_length));
    memcpy(udp + 8, payload, payload_length);
    return 14 + ip_length;
}

static size_t
build_esp(uint8_t *frame, const char *source, const char *destination)
{
    uint8_t *ip = frame + 14;

    memset(frame, 0, FRAME_CAPACITY);
    put_be16(frame + 12, 0x0800);
    ip[0] = 0x45;
    put_be16(ip + 2, 28);
    ip[8] = 64;
    ip[9] = 50;
    assert(inet_pton(AF_INET, source, ip + 12) == 1);
    assert(inet_pton(AF_INET, destination, ip + 16) == 1);
    ip[20] = 1;
    return 42;
}

static size_t
build_arp(uint8_t *frame, const char *sender, const char *target)
{
    uint8_t *arp = frame + 14;

    memset(frame, 0, FRAME_CAPACITY);
    put_be16(frame + 12, 0x0806);
    put_be16(arp, 1);
    put_be16(arp + 2, 0x0800);
    arp[4] = 6;
    arp[5] = 4;
    put_be16(arp + 6, 1);
    assert(inet_pton(AF_INET, sender, arp + 14) == 1);
    assert(inet_pton(AF_INET, target, arp + 24) == 1);
    return 42;
}

int
main(void)
{
    uint8_t frame[FRAME_CAPACITY];
    uint8_t received[FRAME_CAPACITY];
    const uint8_t marker[4] = {0};
    const uint8_t esp_payload[8] = {1, 2, 3, 4, 0, 0, 0, 1};
    const uint8_t keepalive[1] = {0xff};
    uint32_t local;
    size_t length;
    int sockets[2];
    struct n3iwf_dp_punt punt = {.fd = -1};

    assert(inet_pton(AF_INET, "192.168.127.1", &local) == 1);

    length = build_arp(frame, "192.168.127.2", "192.168.127.1");
    assert(n3iwf_dp_punt_classify_to_cp(frame, length, local, false) ==
           N3IWF_DP_PUNT_ARP);
    length = build_arp(frame, "192.168.127.1", "192.168.127.2");
    assert(n3iwf_dp_punt_classify_from_cp(frame, length, local, false) ==
           N3IWF_DP_PUNT_ARP);

    length = build_udp(frame, "192.168.127.2", "192.168.127.1", 500, 500,
                       marker, sizeof(marker));
    assert(n3iwf_dp_punt_classify_to_cp(frame, length, local, false) ==
           N3IWF_DP_PUNT_IKE);
    length = build_udp(frame, "192.168.127.1", "192.168.127.2", 500, 500,
                       marker, sizeof(marker));
    assert(n3iwf_dp_punt_classify_from_cp(frame, length, local, false) ==
           N3IWF_DP_PUNT_IKE);

    length = build_udp(frame, "192.168.127.2", "192.168.127.1", 4500, 4500,
                       marker, sizeof(marker));
    assert(n3iwf_dp_punt_classify_to_cp(frame, length, local, false) ==
           N3IWF_DP_PUNT_IKE);
    length = build_udp(frame, "192.168.127.1", "192.168.127.2", 4500, 4500,
                       marker, sizeof(marker));
    assert(n3iwf_dp_punt_classify_from_cp(frame, length, local, false) ==
           N3IWF_DP_PUNT_IKE);
    length = build_udp(frame, "192.168.127.2", "192.168.127.1", 4500, 4500,
                       keepalive, sizeof(keepalive));
    assert(n3iwf_dp_punt_classify_to_cp(frame, length, local, false) ==
           N3IWF_DP_PUNT_IKE);
    length = build_udp(frame, "192.168.127.2", "192.168.127.1", 4500, 4500,
                       esp_payload, sizeof(esp_payload));
    assert(n3iwf_dp_punt_classify_to_cp(frame, length, local, false) ==
           N3IWF_DP_PUNT_NONE);
    assert(n3iwf_dp_punt_classify_to_cp(frame, length, local, true) ==
           N3IWF_DP_PUNT_ESP);
    length = build_udp(frame, "192.168.127.1", "192.168.127.2", 4500, 4500,
                       esp_payload, sizeof(esp_payload));
    assert(n3iwf_dp_punt_classify_from_cp(frame, length, local, false) ==
           N3IWF_DP_PUNT_NONE);
    assert(n3iwf_dp_punt_classify_from_cp(frame, length, local, true) ==
           N3IWF_DP_PUNT_ESP);

    length = build_esp(frame, "192.168.127.2", "192.168.127.1");
    assert(n3iwf_dp_punt_classify_to_cp(frame, length, local, false) ==
           N3IWF_DP_PUNT_NONE);
    assert(n3iwf_dp_punt_classify_to_cp(frame, length, local, true) ==
           N3IWF_DP_PUNT_ESP);
    length = build_esp(frame, "192.168.127.1", "192.168.127.2");
    assert(n3iwf_dp_punt_classify_from_cp(frame, length, local, true) ==
           N3IWF_DP_PUNT_ESP);

    length = build_udp(frame, "192.168.127.99", "192.168.127.2", 500, 500,
                       marker, sizeof(marker));
    assert(n3iwf_dp_punt_classify_from_cp(frame, length, local, true) ==
           N3IWF_DP_PUNT_NONE);

    length = build_udp(frame, "192.168.127.2", "192.168.127.99", 500, 500,
                       marker, sizeof(marker));
    assert(n3iwf_dp_punt_classify_to_cp(frame, length, local, true) ==
           N3IWF_DP_PUNT_NONE);
    assert(n3iwf_dp_punt_classify_to_cp(frame, 10, local, true) == -EMSGSIZE);
    frame[14 + 6] = 0x20;
    assert(n3iwf_dp_punt_classify_to_cp(frame, length, local, true) ==
           -EOPNOTSUPP);

    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0);
    punt.fd = sockets[0];
    assert(n3iwf_dp_punt_write(&punt, frame, length) == (ssize_t)length);
    assert(recv(sockets[1], received, sizeof(received), 0) == (ssize_t)length);
    assert(write(sockets[1], frame, length) == (ssize_t)length);
    assert(n3iwf_dp_punt_read(&punt, received, sizeof(received)) ==
           (ssize_t)length);
    close(sockets[0]);
    close(sockets[1]);

    puts("n3iwf_dp_punt_test: PASS");
    return 0;
}
