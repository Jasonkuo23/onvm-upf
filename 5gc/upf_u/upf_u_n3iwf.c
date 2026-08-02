/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "upf_u_n3iwf.h"

#include <errno.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>

bool
upf_u_n3iwf_peer_matches(bool enabled, uint32_t configured_peer_ip_be,
                          uint32_t packet_peer_ip_be)
{
    return enabled && configured_peer_ip_be != 0 &&
           configured_peer_ip_be == packet_peer_ip_be;
}

int
upf_u_n3iwf_prepend_internal_ethernet(struct rte_mbuf *packet)
{
    const struct rte_ipv4_hdr *ipv4;
    struct rte_ether_hdr *ether;

    if (packet == NULL || rte_pktmbuf_pkt_len(packet) < sizeof(*ipv4)) {
        return -EINVAL;
    }
    ipv4 = rte_pktmbuf_mtod(packet, const struct rte_ipv4_hdr *);
    if ((ipv4->version_ihl >> 4) != 4) {
        return -EPROTONOSUPPORT;
    }
    ether = (struct rte_ether_hdr *)rte_pktmbuf_prepend(packet,
                                                        sizeof(*ether));
    if (ether == NULL) {
        return -ENOSPC;
    }
    memset(ether, 0, sizeof(*ether));
    ether->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    return 0;
}

void
upf_u_n3iwf_set_route(struct onvm_pkt_meta *meta, bool use_n3iwf,
                      uint16_t n3iwf_service_id, uint16_t physical_n3_port)
{
    if (meta == NULL) {
        return;
    }
    meta->action = use_n3iwf ? ONVM_NF_ACTION_TONF : ONVM_NF_ACTION_OUT;
    meta->destination = use_n3iwf ? n3iwf_service_id : physical_n3_port;
}
