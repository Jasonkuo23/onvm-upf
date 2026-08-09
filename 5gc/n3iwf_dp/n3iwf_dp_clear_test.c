/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_clear.h"

#include "n3iwf_dp_codec.h"

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#define TEST_QFI 9U
#define TEST_UL_TEID 100U
#define TEST_DL_TEID 200U
#define TEST_UPF_SERVICE 1U
#define TEST_ACCESS_PORT 0U

static const uint8_t test_access_mac[RTE_ETHER_ADDR_LEN] =
    {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t test_ue_mac[RTE_ETHER_ADDR_LEN] =
    {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
static const uint8_t changed_ue_mac[RTE_ETHER_ADDR_LEN] =
    {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};

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
install_session(struct n3iwf_dp_session_table *sessions)
{
    struct n3iwf_dp_session_wire wire = {0};

    wire.ue_id = to_be64(42);
    wire.pdu_session_id = htonl(10);
    wire.uplink_teid = htonl(TEST_UL_TEID);
    wire.downlink_teid = htonl(TEST_DL_TEID);
    wire.address_family = N3IWF_DP_AF_IPV4;
    wire.qfi_count = 1;
    wire.n3iwf_nwu_address[0] = 10;
    wire.n3iwf_nwu_address[3] = 1;
    wire.ue_nwu_address[0] = 10;
    wire.ue_nwu_address[3] = 2;
    wire.n3iwf_n3_address[0] = 192;
    wire.n3iwf_n3_address[1] = 168;
    wire.n3iwf_n3_address[2] = 2;
    wire.n3iwf_n3_address[3] = 1;
    wire.upf_n3_address[0] = 192;
    wire.upf_n3_address[1] = 168;
    wire.upf_n3_address[2] = 2;
    wire.upf_n3_address[3] = 2;
    wire.qfi[0] = TEST_QFI;
    assert(n3iwf_dp_session_upsert_wire(sessions, &wire, 1) ==
           N3IWF_DP_STATUS_OK);
}

static void
build_inner_ipv4(uint8_t out[sizeof(struct rte_ipv4_hdr)])
{
    struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)out;

    memset(out, 0, sizeof(*ipv4));
    ipv4->version_ihl = 0x45;
    ipv4->time_to_live = 32;
    ipv4->next_proto_id = IPPROTO_ICMP;
    ipv4->total_length = rte_cpu_to_be_16(sizeof(*ipv4));
    ipv4->src_addr = rte_cpu_to_be_32(RTE_IPV4(10, 60, 0, 1));
    ipv4->dst_addr = rte_cpu_to_be_32(RTE_IPV4(10, 60, 0, 2));
    ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
}

static struct rte_mbuf *
build_uplink(struct rte_mempool *pool, uint8_t qfi,
             const uint8_t inner[sizeof(struct rte_ipv4_hdr)],
             const uint8_t ue_mac[RTE_ETHER_ADDR_LEN])
{
    struct rte_mbuf *packet = rte_pktmbuf_alloc(pool);
    const size_t length = sizeof(struct rte_ether_hdr) +
                          sizeof(struct rte_ipv4_hdr) + 8U +
                          sizeof(struct rte_ipv4_hdr);
    uint8_t *data;
    struct rte_ether_hdr *ether;
    struct rte_ipv4_hdr *outer;
    size_t gre_length = 0;

    assert(packet != NULL);
    data = (uint8_t *)rte_pktmbuf_append(packet, length);
    assert(data != NULL);
    memset(data, 0, length);
    ether = (struct rte_ether_hdr *)data;
    memcpy(ether->src_addr.addr_bytes, ue_mac, RTE_ETHER_ADDR_LEN);
    memcpy(ether->dst_addr.addr_bytes, test_access_mac,
           RTE_ETHER_ADDR_LEN);
    ether->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    outer = (struct rte_ipv4_hdr *)(data + sizeof(*ether));
    outer->version_ihl = 0x45;
    outer->time_to_live = 64;
    outer->next_proto_id = IPPROTO_GRE;
    outer->total_length = rte_cpu_to_be_16((uint16_t)(length - sizeof(*ether)));
    outer->src_addr = rte_cpu_to_be_32(RTE_IPV4(10, 0, 0, 2));
    outer->dst_addr = rte_cpu_to_be_32(RTE_IPV4(10, 0, 0, 1));
    outer->hdr_checksum = rte_ipv4_cksum(outer);
    assert(n3iwf_dp_gre_build((uint8_t *)outer + sizeof(*outer), 8,
                              N3IWF_DP_GRE_PROTO_IPV4, qfi, NULL, 0,
                              &gre_length) == 0);
    assert(gre_length == 8);
    memcpy((uint8_t *)outer + sizeof(*outer) + gre_length, inner,
           sizeof(struct rte_ipv4_hdr));
    return packet;
}

static struct rte_mbuf *
build_downlink(struct rte_mempool *pool,
               const uint8_t inner[sizeof(struct rte_ipv4_hdr)])
{
    struct rte_mbuf *packet = rte_pktmbuf_alloc(pool);
    uint8_t gtpu[64];
    size_t gtpu_length = 0;
    size_t length;
    uint8_t *data;
    struct rte_ether_hdr *ether;
    struct rte_ipv4_hdr *outer;
    struct rte_udp_hdr *udp;

    assert(packet != NULL);
    assert(n3iwf_dp_gtpu_build(gtpu, sizeof(gtpu), TEST_DL_TEID, TEST_QFI,
                               N3IWF_DP_DOWNLINK, inner,
                               sizeof(struct rte_ipv4_hdr), &gtpu_length) == 0);
    length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
             sizeof(struct rte_udp_hdr) + gtpu_length;
    data = (uint8_t *)rte_pktmbuf_append(packet, length);
    assert(data != NULL);
    memset(data, 0, length);
    ether = (struct rte_ether_hdr *)data;
    ether->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    outer = (struct rte_ipv4_hdr *)(data + sizeof(*ether));
    udp = (struct rte_udp_hdr *)((uint8_t *)outer + sizeof(*outer));
    outer->version_ihl = 0x45;
    outer->time_to_live = 64;
    outer->next_proto_id = IPPROTO_UDP;
    outer->total_length = rte_cpu_to_be_16((uint16_t)(length - sizeof(*ether)));
    outer->src_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 2, 2));
    outer->dst_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 2, 1));
    outer->hdr_checksum = rte_ipv4_cksum(outer);
    udp->src_port = rte_cpu_to_be_16(N3IWF_DP_GTPU_PORT);
    udp->dst_port = rte_cpu_to_be_16(N3IWF_DP_GTPU_PORT);
    udp->dgram_len = rte_cpu_to_be_16((uint16_t)(sizeof(*udp) + gtpu_length));
    memcpy((uint8_t *)udp + sizeof(*udp), gtpu, gtpu_length);
    return packet;
}

static void
test_uplink(struct rte_mempool *pool,
            struct n3iwf_dp_session_table *sessions,
            struct n3iwf_dp_stats_wire *stats,
            const uint8_t inner[sizeof(struct rte_ipv4_hdr)],
            const uint8_t ue_mac[RTE_ETHER_ADDR_LEN])
{
    struct rte_mbuf *packet = build_uplink(pool, TEST_QFI, inner, ue_mac);
    struct onvm_pkt_meta meta = {0};
    const uint8_t *data;
    const struct rte_ipv4_hdr *outer;
    struct n3iwf_dp_gtpu_view gtp;
    size_t gtp_offset;

    assert(n3iwf_dp_handle_clear_packet(packet, &meta, sessions, stats,
                                         TEST_UPF_SERVICE,
                                         TEST_ACCESS_PORT,
                                         test_access_mac) == 0);
    assert(meta.action == ONVM_NF_ACTION_TONF);
    assert(meta.destination == TEST_UPF_SERVICE);
    assert(stats->uplink_packets > 0);
    data = rte_pktmbuf_mtod(packet, const uint8_t *);
    outer = (const struct rte_ipv4_hdr *)(data + sizeof(struct rte_ether_hdr));
    assert(outer->src_addr == rte_cpu_to_be_32(RTE_IPV4(192, 168, 2, 1)));
    assert(outer->dst_addr == rte_cpu_to_be_32(RTE_IPV4(192, 168, 2, 2)));
    gtp_offset = sizeof(struct rte_ether_hdr) + sizeof(*outer) +
                 sizeof(struct rte_udp_hdr);
    assert(n3iwf_dp_gtpu_parse(data + gtp_offset,
                               rte_pktmbuf_pkt_len(packet) - gtp_offset,
                               &gtp) == 0);
    assert(gtp.teid == TEST_UL_TEID);
    assert(gtp.qfi == TEST_QFI);
    assert(gtp.direction == N3IWF_DP_UPLINK);
    assert(gtp.payload_len == sizeof(struct rte_ipv4_hdr));
    assert(memcmp(gtp.payload, inner, sizeof(struct rte_ipv4_hdr)) == 0);
    rte_pktmbuf_free(packet);
}

static void
test_downlink_before_learning(
    struct rte_mempool *pool,
    struct n3iwf_dp_session_table *sessions,
    struct n3iwf_dp_stats_wire *stats,
    const uint8_t inner[sizeof(struct rte_ipv4_hdr)])
{
    struct rte_mbuf *packet = build_downlink(pool, inner);
    struct onvm_pkt_meta meta = {0};

    assert(n3iwf_dp_handle_clear_packet(packet, &meta, sessions, stats,
                                         TEST_UPF_SERVICE,
                                         TEST_ACCESS_PORT,
                                         test_access_mac) != 0);
    assert(meta.action == ONVM_NF_ACTION_DROP);
    assert(stats->downlink_packets == 0);
    assert(stats->access_neighbor_drops == 1);
    rte_pktmbuf_free(packet);
}

static void
test_downlink(struct rte_mempool *pool,
              struct n3iwf_dp_session_table *sessions,
              struct n3iwf_dp_stats_wire *stats,
              const uint8_t inner[sizeof(struct rte_ipv4_hdr)])
{
    struct rte_mbuf *packet = build_downlink(pool, inner);
    struct onvm_pkt_meta meta = {0};
    const uint8_t *data;
    const struct rte_ipv4_hdr *outer;
    struct n3iwf_dp_gre_view gre;
    size_t gre_offset;

    assert(n3iwf_dp_handle_clear_packet(packet, &meta, sessions, stats,
                                         TEST_UPF_SERVICE,
                                         TEST_ACCESS_PORT,
                                         test_access_mac) == 0);
    assert(meta.action == ONVM_NF_ACTION_OUT);
    assert(meta.destination == TEST_ACCESS_PORT);
    assert(stats->downlink_packets == 1);
    data = rte_pktmbuf_mtod(packet, const uint8_t *);
    assert(memcmp(((const struct rte_ether_hdr *)data)->src_addr.addr_bytes,
                  test_access_mac, RTE_ETHER_ADDR_LEN) == 0);
    assert(memcmp(((const struct rte_ether_hdr *)data)->dst_addr.addr_bytes,
                  changed_ue_mac, RTE_ETHER_ADDR_LEN) == 0);
    outer = (const struct rte_ipv4_hdr *)(data + sizeof(struct rte_ether_hdr));
    assert(outer->src_addr == rte_cpu_to_be_32(RTE_IPV4(10, 0, 0, 1)));
    assert(outer->dst_addr == rte_cpu_to_be_32(RTE_IPV4(10, 0, 0, 2)));
    assert(outer->next_proto_id == IPPROTO_GRE);
    gre_offset = sizeof(struct rte_ether_hdr) + sizeof(*outer);
    assert(n3iwf_dp_gre_parse(data + gre_offset,
                              rte_pktmbuf_pkt_len(packet) - gre_offset,
                              &gre) == 0);
    assert(gre.qfi == TEST_QFI);
    assert(gre.protocol == N3IWF_DP_GRE_PROTO_IPV4);
    assert(gre.payload_len == sizeof(struct rte_ipv4_hdr));
    assert(memcmp(gre.payload, inner, sizeof(struct rte_ipv4_hdr)) == 0);
    rte_pktmbuf_free(packet);
}

static void
test_unknown_qfi(struct rte_mempool *pool,
                 struct n3iwf_dp_session_table *sessions,
                 struct n3iwf_dp_stats_wire *stats,
                 const uint8_t inner[sizeof(struct rte_ipv4_hdr)])
{
    struct rte_mbuf *packet = build_uplink(pool, TEST_QFI + 1, inner,
                                           test_ue_mac);
    struct onvm_pkt_meta meta = {0};

    assert(n3iwf_dp_handle_clear_packet(packet, &meta, sessions, stats,
                                         TEST_UPF_SERVICE,
                                         TEST_ACCESS_PORT,
                                         test_access_mac) != 0);
    assert(meta.action == ONVM_NF_ACTION_DROP);
    assert(stats->unknown_qfi == 1);
    rte_pktmbuf_free(packet);
}

int
main(int argc, char **argv)
{
    struct rte_mempool *pool;
    struct n3iwf_dp_session_table sessions;
    struct n3iwf_dp_stats_wire stats = {0};
    uint8_t inner[sizeof(struct rte_ipv4_hdr)];
    char *eal_argv[] = {
        argv[0], "--no-huge", "--no-pci", "--no-shconf",
        "--file-prefix=n3iwf-clear-path-test",
    };

    (void)argc;
    assert(rte_eal_init(5, eal_argv) >= 0);
    pool = rte_pktmbuf_pool_create("n3iwf_clear_path_pool", 64, 0, 0,
                                   1024, rte_socket_id());
    assert(pool != NULL);
    n3iwf_dp_session_table_init(&sessions);
    install_session(&sessions);
    build_inner_ipv4(inner);
    test_downlink_before_learning(pool, &sessions, &stats, inner);
    test_uplink(pool, &sessions, &stats, inner, test_ue_mac);
    assert(stats.access_mac_learns == 1);
    test_uplink(pool, &sessions, &stats, inner, changed_ue_mac);
    assert(stats.access_mac_changes == 1);
    assert(stats.uplink_packets == 2);
    test_downlink(pool, &sessions, &stats, inner);
    test_unknown_qfi(pool, &sessions, &stats, inner);
    assert(stats.malformed_packets == 0);
    rte_mempool_free(pool);
    assert(rte_eal_cleanup() == 0);
    puts("n3iwf_dp_clear_test: PASS");
    return 0;
}
