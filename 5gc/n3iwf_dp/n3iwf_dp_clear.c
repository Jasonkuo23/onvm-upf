/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_clear.h"

#include "n3iwf_dp_codec.h"
#include "n3iwf_dp_downlink.h"

#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

struct l3_view {
    uint8_t family;
    uint8_t next_header;
    size_t header_len;
    const uint8_t *source;
};

static int
parse_l3(const uint8_t *packet, size_t packet_len, struct l3_view *view)
{
    const struct rte_ether_hdr *ether;
    uint16_t ether_type;

    if (packet == NULL || view == NULL ||
        packet_len < sizeof(struct rte_ether_hdr)) {
        return -EINVAL;
    }
    memset(view, 0, sizeof(*view));
    ether = (const struct rte_ether_hdr *)packet;
    ether_type = rte_be_to_cpu_16(ether->ether_type);

    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        const struct rte_ipv4_hdr *ipv4;
        size_t header_len;

        if (packet_len < sizeof(*ether) + sizeof(*ipv4)) {
            return -EMSGSIZE;
        }
        ipv4 = (const struct rte_ipv4_hdr *)(packet + sizeof(*ether));
        if ((ipv4->version_ihl >> 4) != 4) {
            return -EPROTO;
        }
        header_len = (size_t)(ipv4->version_ihl & 0x0fU) * 4U;
        if (header_len < sizeof(*ipv4) ||
            packet_len < sizeof(*ether) + header_len) {
            return -EMSGSIZE;
        }
        if ((rte_be_to_cpu_16(ipv4->fragment_offset) &
             (RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_OFFSET_MASK)) != 0) {
            return -EINPROGRESS;
        }
        view->family = N3IWF_DP_AF_IPV4;
        view->next_header = ipv4->next_proto_id;
        view->header_len = header_len;
        view->source = (const uint8_t *)&ipv4->src_addr;
        return 0;
    }

    if (ether_type == RTE_ETHER_TYPE_IPV6) {
        const struct rte_ipv6_hdr *ipv6;

        if (packet_len < sizeof(*ether) + sizeof(*ipv6)) {
            return -EMSGSIZE;
        }
        ipv6 = (const struct rte_ipv6_hdr *)(packet + sizeof(*ether));
        if ((rte_be_to_cpu_32(ipv6->vtc_flow) >> 28) != 6) {
            return -EPROTO;
        }
        if (ipv6->proto == IPPROTO_FRAGMENT) {
            return -EINPROGRESS;
        }
        view->family = N3IWF_DP_AF_IPV6;
        view->next_header = ipv6->proto;
        view->header_len = sizeof(*ipv6);
        view->source = ipv6->src_addr.a;
        return 0;
    }
    return -EPROTONOSUPPORT;
}

static int
prepend_gtpu(struct rte_mbuf *packet, const struct n3iwf_dp_session *session,
             uint8_t qfi)
{
    const size_t headers_len = sizeof(struct rte_ether_hdr) +
                               sizeof(struct rte_ipv4_hdr) +
                               sizeof(struct rte_udp_hdr) + 16U;
    size_t inner_len = rte_pktmbuf_pkt_len(packet);
    uint8_t gtpu_header[16];
    size_t gtpu_len = 0;
    uint8_t *headers;
    struct rte_ether_hdr *ether;
    struct rte_ipv4_hdr *ipv4;
    struct rte_udp_hdr *udp;

    if (inner_len > UINT16_MAX - sizeof(struct rte_ipv4_hdr) -
                    sizeof(struct rte_udp_hdr) - sizeof(gtpu_header)) {
        return -EMSGSIZE;
    }
    if (n3iwf_dp_gtpu_build(gtpu_header, sizeof(gtpu_header),
                            session->uplink_teid, qfi, N3IWF_DP_UPLINK,
                            NULL, 0, &gtpu_len) != 0) {
        return -EINVAL;
    }
    gtpu_header[2] = (uint8_t)((inner_len + 8U) >> 8);
    gtpu_header[3] = (uint8_t)(inner_len + 8U);

    headers = (uint8_t *)rte_pktmbuf_prepend(packet, headers_len);
    if (headers == NULL) {
        return -ENOSPC;
    }
    memset(headers, 0, headers_len);
    ether = (struct rte_ether_hdr *)headers;
    ether->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    ipv4 = (struct rte_ipv4_hdr *)(headers + sizeof(*ether));
    udp = (struct rte_udp_hdr *)((uint8_t *)ipv4 + sizeof(*ipv4));
    memcpy((uint8_t *)udp + sizeof(*udp), gtpu_header, gtpu_len);

    ipv4->version_ihl = 0x45;
    ipv4->time_to_live = 64;
    ipv4->next_proto_id = IPPROTO_UDP;
    ipv4->total_length = rte_cpu_to_be_16((uint16_t)(sizeof(*ipv4) +
                                sizeof(*udp) + gtpu_len + inner_len));
    memcpy(&ipv4->src_addr, session->n3iwf_n3_address, 4);
    memcpy(&ipv4->dst_addr, session->upf_n3_address, 4);
    ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);

    udp->src_port = rte_cpu_to_be_16(N3IWF_DP_GTPU_PORT);
    udp->dst_port = rte_cpu_to_be_16(N3IWF_DP_GTPU_PORT);
    udp->dgram_len = rte_cpu_to_be_16((uint16_t)(sizeof(*udp) +
                                  gtpu_len + inner_len));
    udp->dgram_cksum = 0;
    return 0;
}

static int
handle_uplink(struct rte_mbuf *packet, struct onvm_pkt_meta *meta,
              struct n3iwf_dp_session_table *sessions,
              struct n3iwf_dp_stats_wire *stats, uint16_t upf_service_id,
              const struct l3_view *outer,
              const uint8_t access_mac[N3IWF_DP_ETHER_ADDR_LEN])
{
    size_t gre_offset = sizeof(struct rte_ether_hdr) + outer->header_len;
    const uint8_t *data = rte_pktmbuf_mtod(packet, const uint8_t *);
    struct n3iwf_dp_gre_view gre;
    const struct rte_ether_hdr *ether = (const struct rte_ether_hdr *)data;
    struct n3iwf_dp_session *session;
    enum n3iwf_dp_mac_learn_result learn_result;
    size_t inner_offset;

    if (n3iwf_dp_gre_parse(data + gre_offset,
                           rte_pktmbuf_pkt_len(packet) - gre_offset, &gre) != 0) {
        ++stats->malformed_packets;
        return -EINVAL;
    }
    /* N3IWF learns the authenticated UE NWu address during IKE, not the PDU
     * address inside NAS. Clear mode uses NWu source plus QFI as the test-only
     * equivalent of the production Child-SA SPI plus QFI lookup. */
    session = n3iwf_dp_session_find_uplink_mutable(
        sessions, outer->family, outer->source, gre.qfi);
    if (session == NULL) {
        ++stats->unknown_qfi;
        return -ENOENT;
    }
    if (access_mac == NULL ||
        memcmp(ether->dst_addr.addr_bytes, access_mac,
               N3IWF_DP_ETHER_ADDR_LEN) != 0) {
        ++stats->access_neighbor_drops;
        return -EHOSTUNREACH;
    }
    learn_result = n3iwf_dp_session_learn_access_mac(
        session, ether->src_addr.addr_bytes);
    if (learn_result == N3IWF_DP_MAC_INVALID) {
        ++stats->access_neighbor_drops;
        return -EINVAL;
    }
    if (learn_result == N3IWF_DP_MAC_LEARNED) {
        ++stats->access_mac_learns;
    } else if (learn_result == N3IWF_DP_MAC_CHANGED) {
        ++stats->access_mac_changes;
    }
    inner_offset = gre_offset + gre.header_len;
    if (inner_offset > UINT16_MAX ||
        rte_pktmbuf_adj(packet, (uint16_t)inner_offset) == NULL ||
        prepend_gtpu(packet, session, gre.qfi) != 0) {
        ++stats->malformed_packets;
        return -ENOSPC;
    }
    meta->action = ONVM_NF_ACTION_TONF;
    meta->destination = upf_service_id;
    ++stats->uplink_packets;
    return 0;
}

int
n3iwf_dp_handle_clear_packet(
    struct rte_mbuf *packet,
    struct onvm_pkt_meta *meta,
    struct n3iwf_dp_session_table *sessions,
    struct n3iwf_dp_stats_wire *stats,
    uint16_t upf_service_id,
    uint16_t access_port,
    const uint8_t access_mac[N3IWF_DP_ETHER_ADDR_LEN])
{
    const uint8_t *data;
    struct l3_view l3;
    int parse_result;

    if (packet == NULL || meta == NULL || sessions == NULL || stats == NULL ||
        upf_service_id == 0) {
        return -EINVAL;
    }
    meta->action = ONVM_NF_ACTION_DROP;
    data = rte_pktmbuf_mtod(packet, const uint8_t *);
    parse_result = parse_l3(data, rte_pktmbuf_pkt_len(packet), &l3);
    if (parse_result == -EINPROGRESS) {
        ++stats->fragment_drops;
        return parse_result;
    }
    if (parse_result != 0) {
        ++stats->malformed_packets;
        return parse_result;
    }
    if (l3.next_header == IPPROTO_GRE) {
        return handle_uplink(packet, meta, sessions, stats, upf_service_id,
                             &l3, access_mac);
    }
    if (l3.next_header == IPPROTO_UDP) {
        return n3iwf_dp_handle_clear_downlink(packet, meta, sessions, stats,
                                               access_port, access_mac);
    }
    ++stats->malformed_packets;
    return -EPROTONOSUPPORT;
}
