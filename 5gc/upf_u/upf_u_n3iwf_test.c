/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "upf_u_n3iwf.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

static void
test_route_selection(void)
{
    struct onvm_pkt_meta meta = {0};

    assert(!upf_u_n3iwf_peer_matches(false, UINT32_C(1), UINT32_C(1)));
    assert(!upf_u_n3iwf_peer_matches(true, 0, 0));
    assert(!upf_u_n3iwf_peer_matches(true, UINT32_C(1), UINT32_C(2)));
    assert(upf_u_n3iwf_peer_matches(true, UINT32_C(1), UINT32_C(1)));

    upf_u_n3iwf_set_route(&meta, true, 14, 0);
    assert(meta.action == ONVM_NF_ACTION_TONF);
    assert(meta.destination == 14);
    upf_u_n3iwf_set_route(&meta, false, 14, 0);
    assert(meta.action == ONVM_NF_ACTION_OUT);
    assert(meta.destination == 0);
}

static void
test_internal_ethernet(struct rte_mempool *pool)
{
    struct rte_mbuf *packet = rte_pktmbuf_alloc(pool);
    struct rte_ipv4_hdr *ipv4;
    struct rte_ether_hdr *ether;
    uint16_t headroom;

    assert(packet != NULL);
    ipv4 = (struct rte_ipv4_hdr *)rte_pktmbuf_append(packet, sizeof(*ipv4));
    assert(ipv4 != NULL);
    memset(ipv4, 0, sizeof(*ipv4));
    ipv4->version_ihl = 0x45;
    headroom = rte_pktmbuf_headroom(packet);

    assert(upf_u_n3iwf_prepend_internal_ethernet(packet) == 0);
    assert(rte_pktmbuf_pkt_len(packet) == sizeof(*ether) + sizeof(*ipv4));
    assert(rte_pktmbuf_headroom(packet) == headroom - sizeof(*ether));
    ether = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
    assert(rte_be_to_cpu_16(ether->ether_type) == RTE_ETHER_TYPE_IPV4);
    assert(rte_is_zero_ether_addr(&ether->src_addr));
    assert(rte_is_zero_ether_addr(&ether->dst_addr));
    rte_pktmbuf_free(packet);

    packet = rte_pktmbuf_alloc(pool);
    assert(packet != NULL);
    packet->data_off = 0;
    ipv4 = (struct rte_ipv4_hdr *)rte_pktmbuf_append(packet, sizeof(*ipv4));
    assert(ipv4 != NULL);
    memset(ipv4, 0, sizeof(*ipv4));
    ipv4->version_ihl = 0x45;
    assert(upf_u_n3iwf_prepend_internal_ethernet(packet) == -ENOSPC);
    rte_pktmbuf_free(packet);
}

int
main(int argc, char **argv)
{
    struct rte_mempool *pool;
    char *eal_argv[] = {
        argv[0], "--no-huge", "--no-pci", "--no-shconf",
        "--file-prefix=n3iwf-upf-route-test",
    };

    (void)argc;
    assert(rte_eal_init(5, eal_argv) >= 0);
    pool = rte_pktmbuf_pool_create("n3iwf_upf_route_pool", 64, 0, 0,
                                   512, rte_socket_id());
    assert(pool != NULL);
    test_route_selection();
    test_internal_ethernet(pool);
    rte_mempool_free(pool);
    assert(rte_eal_cleanup() == 0);
    puts("upf_u_n3iwf_test: PASS");
    return 0;
}
