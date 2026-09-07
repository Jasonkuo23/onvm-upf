/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_clear.h"

#include "n3iwf_dp_codec.h"
#include "n3iwf_dp_downlink.h"
#include "n3iwf_dp_mtu.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
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

static struct n3iwf_dp_session *
install_ambiguous_session(struct n3iwf_dp_session_table *sessions)
{
    struct n3iwf_dp_session_wire wire = {0};
    const struct n3iwf_dp_session *session;

    wire.ue_id = to_be64(42);
    wire.pdu_session_id = htonl(20);
    wire.uplink_teid = htonl(TEST_UL_TEID + 1U);
    wire.downlink_teid = htonl(TEST_DL_TEID + 1U);
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
    session = n3iwf_dp_session_find_identity_for_control(
        sessions, 42, 20, NULL);
    assert(session != NULL);
    return (struct n3iwf_dp_session *)session;
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

static void
build_inner_ipv6(uint8_t out[sizeof(struct rte_ipv6_hdr)])
{
    struct rte_ipv6_hdr *ipv6 = (struct rte_ipv6_hdr *)out;

    memset(out, 0, sizeof(*ipv6));
    ipv6->vtc_flow = rte_cpu_to_be_32(UINT32_C(6) << 28);
    ipv6->hop_limits = 32;
    ipv6->proto = IPPROTO_NONE;
    ipv6->src_addr.a[0] = 0x20;
    ipv6->src_addr.a[1] = 0x01;
    ipv6->src_addr.a[2] = 0x0d;
    ipv6->src_addr.a[3] = 0xb8;
    ipv6->src_addr.a[15] = 1;
    ipv6->dst_addr.a[0] = 0x20;
    ipv6->dst_addr.a[1] = 0x01;
    ipv6->dst_addr.a[2] = 0x0d;
    ipv6->dst_addr.a[3] = 0xb8;
    ipv6->dst_addr.a[15] = 2;
}

static struct rte_mbuf *
build_uplink_sized(struct rte_mempool *pool, uint8_t qfi,
                   const uint8_t *inner, size_t inner_length,
                   const uint8_t ue_mac[RTE_ETHER_ADDR_LEN],
                   bool zero_headroom)
{
    struct rte_mbuf *packet = rte_pktmbuf_alloc(pool);
    const size_t length = sizeof(struct rte_ether_hdr) +
                          sizeof(struct rte_ipv4_hdr) + 8U +
                          inner_length;
    uint8_t *data;
    struct rte_ether_hdr *ether;
    struct rte_ipv4_hdr *outer;
    size_t gre_length = 0;

    assert(packet != NULL);
    if (zero_headroom) {
        packet->data_off = 0;
    }
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
                              N3IWF_DP_GRE_PROTO_IPV4, qfi, false,
                              N3IWF_DP_UPLINK, NULL, 0, &gre_length) == 0);
    assert(gre_length == 8);
    memcpy((uint8_t *)outer + sizeof(*outer) + gre_length, inner,
           inner_length);
    return packet;
}

static struct rte_mbuf *
build_uplink(struct rte_mempool *pool, uint8_t qfi,
             const uint8_t inner[sizeof(struct rte_ipv4_hdr)],
             const uint8_t ue_mac[RTE_ETHER_ADDR_LEN])
{
    return build_uplink_sized(pool, qfi, inner, sizeof(struct rte_ipv4_hdr),
                              ue_mac, false);
}

static struct rte_mbuf *
build_downlink_with_headroom(struct rte_mempool *pool,
                             uint32_t downlink_teid,
                             bool rqi, bool extension_chain,
                             const uint8_t *inner, size_t inner_length,
                             bool zero_headroom)
{
    struct rte_mbuf *packet = rte_pktmbuf_alloc(pool);
    uint8_t *gtpu;
    size_t gtpu_capacity = inner_length + 20U;
    size_t gtpu_length = 0;
    size_t length;
    uint8_t *data;
    struct rte_ether_hdr *ether;
    struct rte_ipv4_hdr *outer;
    struct rte_udp_hdr *udp;

    assert(packet != NULL);
    if (zero_headroom) {
        packet->data_off = 0;
    }
    gtpu = malloc(gtpu_capacity);
    assert(gtpu != NULL);
    assert(n3iwf_dp_gtpu_build(gtpu, gtpu_capacity, downlink_teid, TEST_QFI,
                               rqi,
                               N3IWF_DP_DOWNLINK, inner,
                               inner_length, &gtpu_length) == 0);
    if (extension_chain) {
        /* Put a UDP-Port extension before the PSC to verify that the actual
         * downlink path does not assume PSC is first in the chain. */
        assert(gtpu_length + 4U <= gtpu_capacity);
        memmove(gtpu + 16, gtpu + 12, gtpu_length - 12U);
        gtpu[11] = 0x40;
        gtpu[12] = 1;
        gtpu[13] = 0x08;
        gtpu[14] = 0x68;
        gtpu[15] = N3IWF_DP_GTPU_PSC;
        gtpu_length += 4U;
        gtpu[2] = (uint8_t)((gtpu_length - 8U) >> 8);
        gtpu[3] = (uint8_t)(gtpu_length - 8U);
    }
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
    free(gtpu);
    return packet;
}

static struct rte_mbuf *
build_downlink(struct rte_mempool *pool, uint32_t downlink_teid,
               bool rqi, bool extension_chain,
               const uint8_t *inner, size_t inner_length)
{
    return build_downlink_with_headroom(pool, downlink_teid, rqi,
                                        extension_chain, inner, inner_length,
                                        false);
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
    struct rte_mbuf *packet = build_downlink(
        pool, TEST_DL_TEID, false, false, inner, sizeof(struct rte_ipv4_hdr));
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
    struct rte_mbuf *packet = build_downlink(
        pool, TEST_DL_TEID, false, false, inner, sizeof(struct rte_ipv4_hdr));
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
                              N3IWF_DP_DOWNLINK,
                              &gre) == 0);
    assert(gre.qfi == TEST_QFI);
    assert(!gre.rqi);
    assert(gre.protocol == N3IWF_DP_GRE_PROTO_IPV4);
    assert(gre.payload_len == sizeof(struct rte_ipv4_hdr));
    assert(memcmp(gre.payload, inner, sizeof(struct rte_ipv4_hdr)) == 0);
    rte_pktmbuf_free(packet);
}

static void
test_downlink_rqi_variant(
    struct rte_mempool *pool, struct n3iwf_dp_session_table *sessions,
    struct n3iwf_dp_stats_wire *stats, const uint8_t *inner,
    size_t inner_length, uint16_t expected_protocol, bool rqi,
    bool extension_chain)
{
    struct rte_mbuf *packet = build_downlink(
        pool, TEST_DL_TEID, rqi, extension_chain, inner, inner_length);
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
    data = rte_pktmbuf_mtod(packet, const uint8_t *);
    outer = (const struct rte_ipv4_hdr *)(data + sizeof(struct rte_ether_hdr));
    gre_offset = sizeof(struct rte_ether_hdr) + sizeof(*outer);
    assert(n3iwf_dp_gre_parse(data + gre_offset,
                              rte_pktmbuf_pkt_len(packet) - gre_offset,
                              N3IWF_DP_DOWNLINK, &gre) == 0);
    assert(gre.protocol == expected_protocol);
    assert(gre.qfi == TEST_QFI && gre.rqi == rqi);
    assert(gre.key == (((uint32_t)TEST_QFI << 24) |
                       (rqi ? UINT32_C(0x80) : 0)));
    assert(gre.payload_len == inner_length);
    assert(memcmp(gre.payload, inner, inner_length) == 0);
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

static void
test_directional_rejections_are_counted(
    struct rte_mempool *pool, struct n3iwf_dp_session_table *sessions,
    struct n3iwf_dp_stats_wire *stats,
    const uint8_t inner[sizeof(struct rte_ipv4_hdr)])
{
    struct rte_mbuf *packet;
    struct onvm_pkt_meta meta = {0};
    uint8_t *data;
    size_t gtp_offset = sizeof(struct rte_ether_hdr) +
                        sizeof(struct rte_ipv4_hdr) +
                        sizeof(struct rte_udp_hdr);
    size_t gre_offset = sizeof(struct rte_ether_hdr) +
                        sizeof(struct rte_ipv4_hdr);
    uint64_t malformed_before = stats->malformed_packets;

    packet = build_downlink(pool, TEST_DL_TEID, false, false, inner,
                            sizeof(struct rte_ipv4_hdr));
    data = rte_pktmbuf_mtod(packet, uint8_t *);
    data[gtp_offset + 13U] = 0x10U; /* UL PSC on the downlink path. */
    assert(n3iwf_dp_handle_clear_packet(packet, &meta, sessions, stats,
                                         TEST_UPF_SERVICE,
                                         TEST_ACCESS_PORT,
                                         test_access_mac) != 0);
    assert(meta.action == ONVM_NF_ACTION_DROP);
    assert(stats->malformed_packets == malformed_before + 1U);
    rte_pktmbuf_free(packet);

    packet = build_uplink(pool, TEST_QFI, inner, test_ue_mac);
    data = rte_pktmbuf_mtod(packet, uint8_t *);
    data[gre_offset + 7U] |= 0x80U; /* RQI is not defined for uplink GRE. */
    assert(n3iwf_dp_handle_clear_packet(packet, &meta, sessions, stats,
                                         TEST_UPF_SERVICE,
                                         TEST_ACCESS_PORT,
                                         test_access_mac) != 0);
    assert(meta.action == ONVM_NF_ACTION_DROP);
    assert(stats->malformed_packets == malformed_before + 2U);
    rte_pktmbuf_free(packet);
}

static void
test_authenticated_uplink_disambiguates_session(
    struct rte_mempool *pool, struct n3iwf_dp_session *session,
    struct n3iwf_dp_stats_wire *stats,
    const uint8_t inner[sizeof(struct rte_ipv4_hdr)])
{
    struct rte_mbuf *packet = build_uplink(pool, TEST_QFI, inner, test_ue_mac);
    struct onvm_pkt_meta meta = {0};
    const uint8_t *data;
    struct n3iwf_dp_gtpu_view gtp;
    size_t gtp_offset = sizeof(struct rte_ether_hdr) +
                        sizeof(struct rte_ipv4_hdr) +
                        sizeof(struct rte_udp_hdr);

    assert(n3iwf_dp_handle_authenticated_uplink(
               packet, &meta, session, stats, TEST_UPF_SERVICE,
               test_access_mac) == 0);
    assert(meta.action == ONVM_NF_ACTION_TONF);
    data = rte_pktmbuf_mtod(packet, const uint8_t *);
    assert(n3iwf_dp_gtpu_parse(data + gtp_offset,
                               rte_pktmbuf_pkt_len(packet) - gtp_offset,
                               &gtp) == 0);
    assert(gtp.teid == TEST_UL_TEID + 1U && gtp.qfi == TEST_QFI);
    assert(session->ue_access_mac_valid);
    rte_pktmbuf_free(packet);
}

static void
test_downlink_preserves_teid_selected_session(
    struct rte_mempool *pool, struct n3iwf_dp_session_table *sessions,
    const struct n3iwf_dp_session *expected,
    struct n3iwf_dp_stats_wire *stats,
    const uint8_t inner[sizeof(struct rte_ipv4_hdr)])
{
    struct rte_mbuf *packet = build_downlink(
        pool, TEST_DL_TEID + 1U, false, false, inner,
        sizeof(struct rte_ipv4_hdr));
    struct onvm_pkt_meta meta = {0};
    const struct n3iwf_dp_session *selected = NULL;

    assert(n3iwf_dp_handle_clear_downlink_selected(
               packet, &meta, sessions, stats, TEST_ACCESS_PORT,
               test_access_mac, &selected) == 0);
    assert(selected == expected && selected->pdu_session_id == 20);
    assert(meta.action == ONVM_NF_ACTION_OUT);
    rte_pktmbuf_free(packet);
}

static void
build_sized_inner_ipv4(uint8_t *out, size_t length, uint8_t protocol)
{
    struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)out;

    assert(length >= sizeof(*ipv4) && length <= UINT16_MAX);
    memset(out, 0xa5, length);
    ipv4->version_ihl = 0x45;
    ipv4->type_of_service = 0;
    ipv4->total_length = rte_cpu_to_be_16((uint16_t)length);
    ipv4->packet_id = rte_cpu_to_be_16(7);
    ipv4->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
    ipv4->time_to_live = 32;
    ipv4->next_proto_id = protocol;
    ipv4->src_addr = rte_cpu_to_be_32(RTE_IPV4(10, 60, 0, 1));
    ipv4->dst_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 3, 2));
    ipv4->hdr_checksum = 0;
    ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
    if (protocol == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp;

        assert(length >= sizeof(*ipv4) + sizeof(*tcp));
        tcp = (struct rte_tcp_hdr *)(out + sizeof(*ipv4));
        memset(tcp, 0, sizeof(*tcp));
        tcp->src_port = rte_cpu_to_be_16(40000);
        tcp->dst_port = rte_cpu_to_be_16(5503);
        tcp->data_off = (uint8_t)(sizeof(*tcp) / 4U) << 4;
        tcp->tcp_flags = RTE_TCP_ACK_FLAG;
        tcp->rx_win = rte_cpu_to_be_16(65535);
    }
}

static void
assert_uplink_boundary(struct rte_mempool *pool,
                       struct n3iwf_dp_session_table *sessions,
                       struct n3iwf_dp_stats_wire *stats,
                       const uint8_t *inner, size_t inner_length,
                       bool accepted)
{
    struct rte_mbuf *packet = build_uplink_sized(
        pool, TEST_QFI, inner, inner_length, changed_ue_mac, false);
    struct onvm_pkt_meta meta = {0};
    uint64_t uplink_before = stats->uplink_packets;
    uint64_t oversize_before = stats->oversize_drops;
    size_t original_length = rte_pktmbuf_pkt_len(packet);
    uint8_t *original = malloc(original_length);
    int result;

    assert(original != NULL);
    memcpy(original, rte_pktmbuf_mtod(packet, const uint8_t *),
           original_length);
    result = n3iwf_dp_handle_clear_packet(
        packet, &meta, sessions, stats, TEST_UPF_SERVICE, TEST_ACCESS_PORT,
        test_access_mac);
    if (accepted) {
        const uint8_t *data = rte_pktmbuf_mtod(packet, const uint8_t *);
        size_t gtp_offset = sizeof(struct rte_ether_hdr) +
                            sizeof(struct rte_ipv4_hdr) +
                            sizeof(struct rte_udp_hdr);
        struct n3iwf_dp_gtpu_view gtp;

        assert(result == 0 && meta.action == ONVM_NF_ACTION_TONF);
        assert(stats->uplink_packets == uplink_before + 1U);
        assert(stats->oversize_drops == oversize_before);
        assert(n3iwf_dp_gtpu_parse(data + gtp_offset,
                                   rte_pktmbuf_pkt_len(packet) - gtp_offset,
                                   &gtp) == 0);
        assert(gtp.payload_len == inner_length);
        assert(memcmp(gtp.payload, inner, inner_length) == 0);
        assert(rte_pktmbuf_pkt_len(packet) ==
               N3IWF_DP_ETHERNET_HEADER_LEN +
                   n3iwf_dp_n3_outer_ipv4_len(inner_length));
    } else {
        assert(result == -EMSGSIZE && meta.action == ONVM_NF_ACTION_DROP);
        assert(stats->uplink_packets == uplink_before);
        assert(stats->oversize_drops == oversize_before + 1U);
        assert(rte_pktmbuf_pkt_len(packet) == original_length);
        assert(memcmp(rte_pktmbuf_mtod(packet, const uint8_t *), original,
                      original_length) == 0);
    }
    free(original);
    rte_pktmbuf_free(packet);
}

static void
assert_downlink_boundary(struct rte_mempool *pool,
                         struct n3iwf_dp_session_table *sessions,
                         struct n3iwf_dp_stats_wire *stats,
                         const uint8_t *inner, size_t inner_length,
                         bool accepted)
{
    struct rte_mbuf *packet = build_downlink(
        pool, TEST_DL_TEID, false, false, inner, inner_length);
    struct onvm_pkt_meta meta = {0};
    uint64_t downlink_before = stats->downlink_packets;
    uint64_t oversize_before = stats->oversize_drops;
    size_t original_length = rte_pktmbuf_pkt_len(packet);
    uint8_t *original = malloc(original_length);
    int result;

    assert(original != NULL);
    memcpy(original, rte_pktmbuf_mtod(packet, const uint8_t *),
           original_length);
    result = n3iwf_dp_handle_clear_packet(
        packet, &meta, sessions, stats, TEST_UPF_SERVICE, TEST_ACCESS_PORT,
        test_access_mac);
    if (accepted) {
        const uint8_t *data = rte_pktmbuf_mtod(packet, const uint8_t *);
        size_t gre_offset = sizeof(struct rte_ether_hdr) +
                            sizeof(struct rte_ipv4_hdr);
        struct n3iwf_dp_gre_view gre;

        assert(result == 0 && meta.action == ONVM_NF_ACTION_OUT);
        assert(stats->downlink_packets == downlink_before + 1U);
        assert(stats->oversize_drops == oversize_before);
        assert(n3iwf_dp_gre_parse(data + gre_offset,
                                  rte_pktmbuf_pkt_len(packet) - gre_offset,
                                  N3IWF_DP_DOWNLINK, &gre) == 0);
        assert(gre.payload_len == inner_length);
        assert(memcmp(gre.payload, inner, inner_length) == 0);
    } else {
        assert(result == -EMSGSIZE && meta.action == ONVM_NF_ACTION_DROP);
        assert(stats->downlink_packets == downlink_before);
        assert(stats->oversize_drops == oversize_before + 1U);
        assert(rte_pktmbuf_pkt_len(packet) == original_length);
        assert(memcmp(rte_pktmbuf_mtod(packet, const uint8_t *), original,
                      original_length) == 0);
    }
    free(original);
    rte_pktmbuf_free(packet);
}

static void
test_mtu_boundaries(struct rte_mempool *pool,
                    struct n3iwf_dp_session_table *sessions,
                    struct n3iwf_dp_stats_wire *stats)
{
    uint8_t below[N3IWF_DP_MAX_INNER_PACKET_LEN - 1U];
    uint8_t exact[N3IWF_DP_MAX_INNER_PACKET_LEN];
    uint8_t above[N3IWF_DP_MAX_INNER_PACKET_LEN + 1U];

    build_sized_inner_ipv4(below, sizeof(below), IPPROTO_ICMP);
    build_sized_inner_ipv4(exact, sizeof(exact), IPPROTO_TCP);
    build_sized_inner_ipv4(above, sizeof(above), IPPROTO_ICMP);
    assert(sizeof(exact) - sizeof(struct rte_ipv4_hdr) -
               sizeof(struct rte_tcp_hdr) ==
           1370U);
    assert(n3iwf_dp_esp_outer_ipv4_len(sizeof(below)) == 1496U);
    assert(n3iwf_dp_esp_outer_ipv4_len(sizeof(exact)) == 1496U);
    assert(n3iwf_dp_esp_outer_ipv4_len(sizeof(above)) == 1512U);
    assert(n3iwf_dp_inner_packet_supported(sizeof(below)));
    assert(n3iwf_dp_inner_packet_supported(sizeof(exact)));
    assert(!n3iwf_dp_inner_packet_supported(sizeof(above)));

    assert_uplink_boundary(pool, sessions, stats, below, sizeof(below), true);
    assert_uplink_boundary(pool, sessions, stats, exact, sizeof(exact), true);
    assert_uplink_boundary(pool, sessions, stats, above, sizeof(above), false);
    assert_downlink_boundary(pool, sessions, stats, below, sizeof(below), true);
    assert_downlink_boundary(pool, sessions, stats, exact, sizeof(exact), true);
    assert_downlink_boundary(pool, sessions, stats, above, sizeof(above),
                             false);
}

static void
test_buffer_and_fragment_drops(struct rte_mempool *pool,
                               struct n3iwf_dp_session_table *sessions,
                               struct n3iwf_dp_stats_wire *stats,
                               const uint8_t *inner)
{
    struct rte_mbuf *packet;
    struct onvm_pkt_meta meta = {0};
    uint64_t buffer_before = stats->buffer_drops;
    uint64_t fragments_before = stats->fragment_drops;
    size_t original_length;
    uint8_t *data;

    packet = build_uplink_sized(pool, TEST_QFI, inner,
                                sizeof(struct rte_ipv4_hdr), changed_ue_mac,
                                true);
    original_length = rte_pktmbuf_pkt_len(packet);
    assert(n3iwf_dp_handle_clear_packet(
               packet, &meta, sessions, stats, TEST_UPF_SERVICE,
               TEST_ACCESS_PORT, test_access_mac) == -ENOSPC);
    assert(meta.action == ONVM_NF_ACTION_DROP);
    assert(stats->buffer_drops == buffer_before + 1U);
    assert(rte_pktmbuf_pkt_len(packet) == original_length);
    rte_pktmbuf_free(packet);

    packet = build_downlink_with_headroom(
        pool, TEST_DL_TEID, false, false, inner,
        sizeof(struct rte_ipv4_hdr), true);
    original_length = rte_pktmbuf_pkt_len(packet);
    assert(n3iwf_dp_handle_clear_packet(
               packet, &meta, sessions, stats, TEST_UPF_SERVICE,
               TEST_ACCESS_PORT, test_access_mac) == -ENOSPC);
    assert(meta.action == ONVM_NF_ACTION_DROP);
    assert(stats->buffer_drops == buffer_before + 2U);
    assert(rte_pktmbuf_pkt_len(packet) == original_length);
    rte_pktmbuf_free(packet);

    packet = build_uplink(pool, TEST_QFI, inner, changed_ue_mac);
    data = rte_pktmbuf_mtod(packet, uint8_t *);
    ((struct rte_ipv4_hdr *)(data + sizeof(struct rte_ether_hdr)))
        ->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_MF_FLAG);
    assert(n3iwf_dp_handle_clear_packet(
               packet, &meta, sessions, stats, TEST_UPF_SERVICE,
               TEST_ACCESS_PORT, test_access_mac) == -EINPROGRESS);
    assert(stats->fragment_drops == fragments_before + 1U);
    rte_pktmbuf_free(packet);

    packet = build_downlink(pool, TEST_DL_TEID, false, false, inner,
                            sizeof(struct rte_ipv4_hdr));
    data = rte_pktmbuf_mtod(packet, uint8_t *);
    ((struct rte_ipv4_hdr *)(data + sizeof(struct rte_ether_hdr)))
        ->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_MF_FLAG);
    assert(n3iwf_dp_handle_clear_packet(
               packet, &meta, sessions, stats, TEST_UPF_SERVICE,
               TEST_ACCESS_PORT, test_access_mac) == -EINPROGRESS);
    assert(stats->fragment_drops == fragments_before + 2U);
    rte_pktmbuf_free(packet);
}

int
main(int argc, char **argv)
{
    struct rte_mempool *pool;
    struct n3iwf_dp_session_table sessions;
    struct n3iwf_dp_session *ambiguous_session;
    struct n3iwf_dp_stats_wire stats = {0};
    uint8_t inner[sizeof(struct rte_ipv4_hdr)];
    uint8_t inner_ipv6[sizeof(struct rte_ipv6_hdr)];
    char *eal_argv[] = {
        argv[0], "--no-huge", "--no-pci", "--no-shconf",
        "--file-prefix=n3iwf-clear-path-test",
    };

    (void)argc;
    assert(rte_eal_init(5, eal_argv) >= 0);
    pool = rte_pktmbuf_pool_create("n3iwf_clear_path_pool", 64, 0, 0,
                                   2048, rte_socket_id());
    assert(pool != NULL);
    n3iwf_dp_session_table_init(&sessions);
    install_session(&sessions);
    build_inner_ipv4(inner);
    build_inner_ipv6(inner_ipv6);
    test_downlink_before_learning(pool, &sessions, &stats, inner);
    test_uplink(pool, &sessions, &stats, inner, test_ue_mac);
    assert(stats.access_mac_learns == 1);
    test_uplink(pool, &sessions, &stats, inner, changed_ue_mac);
    assert(stats.access_mac_changes == 1);
    assert(stats.uplink_packets == 2);
    test_downlink(pool, &sessions, &stats, inner);
    test_downlink_rqi_variant(
        pool, &sessions, &stats, inner, sizeof(inner),
        N3IWF_DP_GRE_PROTO_IPV4, true, false);
    test_downlink_rqi_variant(
        pool, &sessions, &stats, inner_ipv6, sizeof(inner_ipv6),
        N3IWF_DP_GRE_PROTO_IPV6, false, false);
    test_downlink_rqi_variant(
        pool, &sessions, &stats, inner_ipv6, sizeof(inner_ipv6),
        N3IWF_DP_GRE_PROTO_IPV6, true, true);
    test_unknown_qfi(pool, &sessions, &stats, inner);
    test_directional_rejections_are_counted(pool, &sessions, &stats, inner);
    ambiguous_session = install_ambiguous_session(&sessions);
    test_authenticated_uplink_disambiguates_session(
        pool, ambiguous_session, &stats, inner);
    test_downlink_preserves_teid_selected_session(
        pool, &sessions, ambiguous_session, &stats, inner);
    test_mtu_boundaries(pool, &sessions, &stats);
    test_buffer_and_fragment_drops(pool, &sessions, &stats, inner);
    assert(stats.malformed_packets == 2);
    assert(stats.oversize_drops == 2);
    assert(stats.buffer_drops == 2);
    rte_mempool_free(pool);
    assert(rte_eal_cleanup() == 0);
    puts("n3iwf_dp_clear_test: PASS");
    return 0;
}
