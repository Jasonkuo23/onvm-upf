/*
 * SPDX-License-Identifier: Apache-2.0
 */

#define _DEFAULT_SOURCE

#include "n3iwf_dp_punt.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ETHERNET_HEADER_LENGTH 14U
#define ARP_PACKET_LENGTH 28U
#define IPV4_MIN_HEADER_LENGTH 20U
#define UDP_HEADER_LENGTH 8U
#define ETHERTYPE_IPV4 0x0800U
#define ETHERTYPE_ARP 0x0806U
#define IPPROTO_UDP_VALUE 17U
#define IPPROTO_ESP_VALUE 50U
#define IKE_PORT 500U
#define NAT_T_PORT 4500U

static uint16_t
read_be16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static uint32_t
read_be32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) | data[3];
}

static bool
ipv4_matches(const uint8_t *address, uint32_t expected_be)
{
    uint32_t actual;

    memcpy(&actual, address, sizeof(actual));
    return actual == expected_be;
}

static int
classify_arp(const uint8_t *arp, size_t length, uint32_t local_ipv4_be,
             bool to_cp)
{
    const uint8_t *address;

    if (length < ARP_PACKET_LENGTH) {
        return -EMSGSIZE;
    }
    if (read_be16(arp) != 1 || read_be16(arp + 2) != ETHERTYPE_IPV4 ||
        arp[4] != 6 || arp[5] != 4 ||
        (read_be16(arp + 6) != 1 && read_be16(arp + 6) != 2)) {
        return N3IWF_DP_PUNT_NONE;
    }
    address = to_cp ? arp + 24 : arp + 14;
    return ipv4_matches(address, local_ipv4_be) ? N3IWF_DP_PUNT_ARP :
                                                  N3IWF_DP_PUNT_NONE;
}

static int
classify_udp(const uint8_t *udp, size_t length, bool to_cp,
             bool allow_kernel_signalling_esp)
{
    uint16_t port;
    uint16_t udp_length;
    const uint8_t *payload;
    size_t payload_length;

    if (length < UDP_HEADER_LENGTH) {
        return -EMSGSIZE;
    }
    udp_length = read_be16(udp + 4);
    if (udp_length < UDP_HEADER_LENGTH || udp_length > length) {
        return -EMSGSIZE;
    }
    port = read_be16(udp + (to_cp ? 2 : 0));
    if (port == IKE_PORT) {
        return N3IWF_DP_PUNT_IKE;
    }
    if (port != NAT_T_PORT) {
        return N3IWF_DP_PUNT_NONE;
    }

    payload = udp + UDP_HEADER_LENGTH;
    payload_length = udp_length - UDP_HEADER_LENGTH;
    /* RFC 3948: zero Non-ESP Marker identifies IKE; 0xff is keepalive. */
    if ((payload_length >= 4 && read_be32(payload) == 0) ||
        (payload_length == 1 && payload[0] == 0xff)) {
        return N3IWF_DP_PUNT_IKE;
    }
    if (payload_length < 8) {
        return -EMSGSIZE;
    }
    return allow_kernel_signalling_esp ? N3IWF_DP_PUNT_ESP :
                                        N3IWF_DP_PUNT_NONE;
}

static int
classify_ipv4(const uint8_t *ip, size_t length, uint32_t local_ipv4_be,
              bool to_cp, bool allow_kernel_signalling_esp)
{
    size_t header_length;
    uint16_t total_length;
    uint16_t fragment;
    const uint8_t *local_address;

    if (length < IPV4_MIN_HEADER_LENGTH || (ip[0] >> 4) != 4) {
        return -EMSGSIZE;
    }
    header_length = (size_t)(ip[0] & 0x0fU) * 4U;
    total_length = read_be16(ip + 2);
    if (header_length < IPV4_MIN_HEADER_LENGTH || header_length > length ||
        total_length < header_length || total_length > length) {
        return -EMSGSIZE;
    }
    fragment = read_be16(ip + 6);
    if ((fragment & 0x3fffU) != 0) {
        return -EOPNOTSUPP;
    }
    local_address = ip + (to_cp ? 16 : 12);
    if (!ipv4_matches(local_address, local_ipv4_be)) {
        return N3IWF_DP_PUNT_NONE;
    }
    if (ip[9] == IPPROTO_ESP_VALUE) {
        if (total_length - header_length < 8) {
            return -EMSGSIZE;
        }
        return allow_kernel_signalling_esp ? N3IWF_DP_PUNT_ESP :
                                            N3IWF_DP_PUNT_NONE;
    }
    if (ip[9] != IPPROTO_UDP_VALUE) {
        return N3IWF_DP_PUNT_NONE;
    }
    return classify_udp(ip + header_length, total_length - header_length,
                        to_cp, allow_kernel_signalling_esp);
}

static int
classify(const uint8_t *frame, size_t length, uint32_t local_ipv4_be,
         bool to_cp, bool allow_kernel_signalling_esp)
{
    uint16_t ether_type;

    if (frame == NULL || length < ETHERNET_HEADER_LENGTH) {
        return -EMSGSIZE;
    }
    ether_type = read_be16(frame + 12);
    if (ether_type == ETHERTYPE_ARP) {
        return classify_arp(frame + ETHERNET_HEADER_LENGTH,
                            length - ETHERNET_HEADER_LENGTH, local_ipv4_be,
                            to_cp);
    }
    if (ether_type == ETHERTYPE_IPV4) {
        return classify_ipv4(frame + ETHERNET_HEADER_LENGTH,
                             length - ETHERNET_HEADER_LENGTH, local_ipv4_be,
                             to_cp, allow_kernel_signalling_esp);
    }
    return N3IWF_DP_PUNT_NONE;
}

int
n3iwf_dp_punt_classify_to_cp(const uint8_t *frame, size_t length,
                             uint32_t local_ipv4_be,
                             bool allow_kernel_signalling_esp)
{
    return classify(frame, length, local_ipv4_be, true,
                    allow_kernel_signalling_esp);
}

int
n3iwf_dp_punt_classify_from_cp(const uint8_t *frame, size_t length,
                               uint32_t local_ipv4_be,
                               bool allow_kernel_signalling_esp)
{
    return classify(frame, length, local_ipv4_be, false,
                    allow_kernel_signalling_esp);
}

int
n3iwf_dp_punt_open(struct n3iwf_dp_punt *punt, const char *ifname,
                   const char *local_ipv4)
{
    struct ifreq request;
    int fd;
    int flags;

    if (punt == NULL || ifname == NULL || local_ipv4 == NULL ||
        ifname[0] == '\0' || strlen(ifname) >= IF_NAMESIZE) {
        return -EINVAL;
    }
    memset(punt, 0, sizeof(*punt));
    punt->fd = -1;
    if (inet_pton(AF_INET, local_ipv4, &punt->local_ipv4_be) != 1) {
        return -EINVAL;
    }
    fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }
    memset(&request, 0, sizeof(request));
    request.ifr_flags = IFF_TAP | IFF_NO_PI;
    memcpy(request.ifr_name, ifname, strlen(ifname) + 1);
    if (ioctl(fd, TUNSETIFF, &request) < 0) {
        int saved_errno = errno;
        close(fd);
        return -saved_errno;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        int saved_errno = errno;
        close(fd);
        return -saved_errno;
    }
    punt->fd = fd;
    memcpy(punt->ifname, request.ifr_name, strlen(request.ifr_name) + 1);
    return 0;
}

void
n3iwf_dp_punt_close(struct n3iwf_dp_punt *punt)
{
    if (punt != NULL && punt->fd >= 0) {
        close(punt->fd);
        punt->fd = -1;
    }
}

ssize_t
n3iwf_dp_punt_read(struct n3iwf_dp_punt *punt, void *frame, size_t capacity)
{
    ssize_t result;

    if (punt == NULL || punt->fd < 0 || frame == NULL || capacity == 0) {
        return -EINVAL;
    }
    result = read(punt->fd, frame, capacity);
    return result < 0 ? -errno : result;
}

ssize_t
n3iwf_dp_punt_write(struct n3iwf_dp_punt *punt, const void *frame,
                    size_t length)
{
    ssize_t result;

    if (punt == NULL || punt->fd < 0 || frame == NULL || length == 0) {
        return -EINVAL;
    }
    result = write(punt->fd, frame, length);
    return result < 0 ? -errno : result;
}
