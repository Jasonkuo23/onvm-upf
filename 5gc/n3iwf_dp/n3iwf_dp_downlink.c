/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_downlink.h"

#include "n3iwf_dp_codec.h"

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

static int
outer_view(const uint8_t *data, size_t length, size_t *ip_length,
           uint8_t *next_header)
{
    const struct rte_ether_hdr *ether;
    uint16_t ether_type;

    if (length < sizeof(*ether)) {
        return -EMSGSIZE;
    }
    ether = (const struct rte_ether_hdr *)data;
    ether_type = rte_be_to_cpu_16(ether->ether_type);
    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        const struct rte_ipv4_hdr *ipv4;

        if (length < sizeof(*ether) + sizeof(*ipv4)) {
            return -EMSGSIZE;
        }
        ipv4 = (const struct rte_ipv4_hdr *)(data + sizeof(*ether));
        *ip_length = (size_t)(ipv4->version_ihl & 0x0fU) * 4U;
        if (*ip_length < sizeof(*ipv4) ||
            length < sizeof(*ether) + *ip_length) {
            return -EMSGSIZE;
        }
        *next_header = ipv4->next_proto_id;
        return 0;
    }
    if (ether_type == RTE_ETHER_TYPE_IPV6) {
        const struct rte_ipv6_hdr *ipv6;

        if (length < sizeof(*ether) + sizeof(*ipv6)) {
            return -EMSGSIZE;
        }
        ipv6 = (const struct rte_ipv6_hdr *)(data + sizeof(*ether));
        *ip_length = sizeof(*ipv6);
        *next_header = ipv6->proto;
        return 0;
    }
    return -EPROTONOSUPPORT;
}

static int
prepend_clear_gre(struct rte_mbuf *packet,
                  const struct n3iwf_dp_session *session, uint8_t qfi,
                  uint16_t inner_protocol,
                  const uint8_t access_mac[N3IWF_DP_ETHER_ADDR_LEN])
{
    uint8_t gre_header[8];
    size_t gre_length = 0;
    size_t inner_length = rte_pktmbuf_pkt_len(packet);
    size_t ip_length = session->address_family == N3IWF_DP_AF_IPV4 ?
                       sizeof(struct rte_ipv4_hdr) :
                       sizeof(struct rte_ipv6_hdr);
    size_t headers_length = sizeof(struct rte_ether_hdr) + ip_length +
                            sizeof(gre_header);
    uint8_t *headers;
    struct rte_ether_hdr *ether;

    if (n3iwf_dp_gre_build(gre_header, sizeof(gre_header), inner_protocol, qfi,
                           NULL, 0, &gre_length) != 0) {
        return -EINVAL;
    }
    headers = (uint8_t *)rte_pktmbuf_prepend(packet, headers_length);
    if (headers == NULL) {
        return -ENOSPC;
    }
    memset(headers, 0, headers_length);
    ether = (struct rte_ether_hdr *)headers;
    memcpy(ether->src_addr.addr_bytes, access_mac,
           N3IWF_DP_ETHER_ADDR_LEN);
    memcpy(ether->dst_addr.addr_bytes, session->ue_access_mac,
           N3IWF_DP_ETHER_ADDR_LEN);

    if (session->address_family == N3IWF_DP_AF_IPV4) {
        struct rte_ipv4_hdr *ipv4 =
            (struct rte_ipv4_hdr *)(headers + sizeof(*ether));

        if (inner_length + gre_length + sizeof(*ipv4) > UINT16_MAX) {
            return -EMSGSIZE;
        }
        ether->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        ipv4->version_ihl = 0x45;
        ipv4->time_to_live = 64;
        ipv4->next_proto_id = IPPROTO_GRE;
        ipv4->total_length = rte_cpu_to_be_16((uint16_t)(sizeof(*ipv4) +
                                                   gre_length + inner_length));
        memcpy(&ipv4->src_addr, session->n3iwf_nwu_address, 4);
        memcpy(&ipv4->dst_addr, session->ue_nwu_address, 4);
        ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
        memcpy((uint8_t *)ipv4 + sizeof(*ipv4), gre_header, gre_length);
    } else {
        struct rte_ipv6_hdr *ipv6 =
            (struct rte_ipv6_hdr *)(headers + sizeof(*ether));

        if (inner_length + gre_length > UINT16_MAX) {
            return -EMSGSIZE;
        }
        ether->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
        ipv6->vtc_flow = rte_cpu_to_be_32(UINT32_C(6) << 28);
        ipv6->payload_len =
            rte_cpu_to_be_16((uint16_t)(gre_length + inner_length));
        ipv6->proto = IPPROTO_GRE;
        ipv6->hop_limits = 64;
        memcpy(ipv6->src_addr.a, session->n3iwf_nwu_address, 16);
        memcpy(ipv6->dst_addr.a, session->ue_nwu_address, 16);
        memcpy((uint8_t *)ipv6 + sizeof(*ipv6), gre_header, gre_length);
    }
    return 0;
}

int
n3iwf_dp_handle_clear_downlink(
    struct rte_mbuf *packet,
    struct onvm_pkt_meta *meta,
    const struct n3iwf_dp_session_table *sessions,
    struct n3iwf_dp_stats_wire *stats,
    uint16_t access_port,
    const uint8_t access_mac[N3IWF_DP_ETHER_ADDR_LEN])
{
    const uint8_t *data;
    size_t length;
    size_t ip_length;
    size_t gtp_offset;
    uint8_t next_header;
    const struct rte_udp_hdr *udp;
    struct n3iwf_dp_gtpu_view gtp;
    const struct n3iwf_dp_session *session;
    uint16_t inner_protocol;
    size_t inner_offset;

    if (packet == NULL || meta == NULL || sessions == NULL || stats == NULL) {
        return -EINVAL;
    }
    data = rte_pktmbuf_mtod(packet, const uint8_t *);
    length = rte_pktmbuf_pkt_len(packet);
    if (outer_view(data, length, &ip_length, &next_header) != 0 ||
        next_header != IPPROTO_UDP) {
        ++stats->malformed_packets;
        return -EPROTO;
    }
    gtp_offset = sizeof(struct rte_ether_hdr) + ip_length +
                 sizeof(struct rte_udp_hdr);
    if (length < gtp_offset + 8U) {
        ++stats->malformed_packets;
        return -EMSGSIZE;
    }
    udp = (const struct rte_udp_hdr *)(data + sizeof(struct rte_ether_hdr) +
                                       ip_length);
    if (rte_be_to_cpu_16(udp->src_port) != N3IWF_DP_GTPU_PORT &&
        rte_be_to_cpu_16(udp->dst_port) != N3IWF_DP_GTPU_PORT) {
        ++stats->malformed_packets;
        return -EPROTO;
    }
    if (n3iwf_dp_gtpu_parse(data + gtp_offset, length - gtp_offset, &gtp) != 0) {
        ++stats->malformed_packets;
        return -EPROTO;
    }
    session = n3iwf_dp_session_find_downlink(sessions, gtp.teid, gtp.qfi);
    if (session == NULL) {
        ++stats->unknown_teid;
        return -ENOENT;
    }
    if (!session->ue_access_mac_valid || access_mac == NULL) {
        ++stats->access_neighbor_drops;
        return -EHOSTUNREACH;
    }
    if (gtp.payload_len == 0 ||
        ((gtp.payload[0] >> 4) != 4 && (gtp.payload[0] >> 4) != 6)) {
        ++stats->malformed_packets;
        return -EPROTO;
    }
    inner_protocol = (gtp.payload[0] >> 4) == 4 ?
                     N3IWF_DP_GRE_PROTO_IPV4 :
                     N3IWF_DP_GRE_PROTO_IPV6;
    inner_offset = gtp_offset + gtp.header_len;
    if (inner_offset > UINT16_MAX ||
        rte_pktmbuf_adj(packet, (uint16_t)inner_offset) == NULL ||
        prepend_clear_gre(packet, session, gtp.qfi, inner_protocol,
                          access_mac) != 0) {
        ++stats->malformed_packets;
        return -ENOSPC;
    }
    meta->action = ONVM_NF_ACTION_OUT;
    meta->destination = access_port;
    ++stats->downlink_packets;
    return 0;
}
