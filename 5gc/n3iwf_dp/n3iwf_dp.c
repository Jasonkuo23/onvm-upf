/*
 * L25GC+ N3IWF user-plane ONVM NF.
 *
 * The initial dataplane is deliberately fail-closed. Production packets are
 * accepted only after a cryptodev backend is connected. The -t option enables
 * a clear-GRE integration mode for deterministic ONVM/GTP-U testing.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_codec.h"
#include "n3iwf_dp_control.h"
#include "n3iwf_dp_downlink.h"
#include "n3iwf_dp_session.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_udp.h>

#include "onvm_nflib.h"

#define NF_TAG "n3iwf_dp"
#define DEFAULT_CONTROL_SOCKET "/run/l25gc/n3iwf-dp.sock"
#define DEFAULT_UPF_SERVICE_ID 1U
#define DEFAULT_ACCESS_PORT 0U

struct n3iwf_dp_state {
    struct n3iwf_dp_session_table sessions;
    struct n3iwf_dp_control control;
    struct n3iwf_dp_stats_wire stats;
    uint16_t upf_service_id;
    uint16_t access_port;
    bool cleartext_test;
    char control_socket[108];
};

struct l3_view {
    uint8_t family;
    uint8_t next_header;
    size_t header_len;
    const uint8_t *source;
    const uint8_t *destination;
};

static void
usage(const char *program)
{
    printf("Usage: %s [DPDK args] -- [ONVM args] -- "
           "[-c socket] [-s upf-service] [-a access-port] [-t]\n", program);
    puts("  -t enables clear-GRE test mode; without it user traffic is dropped");
}

static int
parse_args(int argc, char **argv, struct n3iwf_dp_state *state)
{
    int option;

    optind = 1;
    while ((option = getopt(argc, argv, "c:s:a:th")) != -1) {
        switch (option) {
        case 'c':
            if (strlen(optarg) >= sizeof(state->control_socket)) {
                return -1;
            }
            strcpy(state->control_socket, optarg);
            break;
        case 's':
            state->upf_service_id = (uint16_t)strtoul(optarg, NULL, 10);
            if (state->upf_service_id == 0) {
                return -1;
            }
            break;
        case 'a':
            state->access_port = (uint16_t)strtoul(optarg, NULL, 10);
            break;
        case 't':
            state->cleartext_test = true;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return -1;
        }
    }
    return 0;
}

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
        view->destination = (const uint8_t *)&ipv4->dst_addr;
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
        /* Extension/fragment headers are rejected until bounded reassembly is
         * wired to rte_ip_frag. */
        if (ipv6->proto == IPPROTO_FRAGMENT) {
            return -EINPROGRESS;
        }
        view->family = N3IWF_DP_AF_IPV6;
        view->next_header = ipv6->proto;
        view->header_len = sizeof(*ipv6);
        view->source = ipv6->src_addr.a;
        view->destination = ipv6->dst_addr.a;
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
    /* Account for the inner packet omitted from the header-only builder. */
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
    /* Current ONVM-UPF N3 parsing is IPv4-only. The first four address octets
     * are used until its Release 18 dual-stack gap is closed. */
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
handle_clear_uplink(struct rte_mbuf *packet, struct onvm_pkt_meta *meta,
                    struct n3iwf_dp_state *state, const struct l3_view *outer)
{
    size_t gre_offset = sizeof(struct rte_ether_hdr) + outer->header_len;
    const uint8_t *data = rte_pktmbuf_mtod(packet, const uint8_t *);
    struct n3iwf_dp_gre_view gre;
    const struct n3iwf_dp_session *session;
    size_t inner_offset;

    if (n3iwf_dp_gre_parse(data + gre_offset,
                           rte_pktmbuf_pkt_len(packet) - gre_offset, &gre) != 0) {
        ++state->stats.malformed_packets;
        return -EINVAL;
    }
    /* The N3IWF learns the UE NWu address during IKE; it does not decode the
     * NAS PDU address assigned by the SMF. Production ESP lookup will bind
     * this identity to the authenticated Child SA. Clear mode uses the outer
     * NWu source plus QFI as the deterministic test equivalent. */
    session = n3iwf_dp_session_find_uplink(&state->sessions, outer->family,
                                            outer->source, gre.qfi);
    if (session == NULL) {
        ++state->stats.unknown_qfi;
        return -ENOENT;
    }
    inner_offset = gre_offset + gre.header_len;
    if (rte_pktmbuf_adj(packet, (uint16_t)inner_offset) == NULL ||
        prepend_gtpu(packet, session, gre.qfi) != 0) {
        return -ENOSPC;
    }
    meta->action = ONVM_NF_ACTION_TONF;
    meta->destination = state->upf_service_id;
    ++state->stats.uplink_packets;
    return 0;
}

static int
packet_handler(struct rte_mbuf *packet, struct onvm_pkt_meta *meta,
               struct onvm_nf_local_ctx *local_context)
{
    struct n3iwf_dp_state *state = local_context->nf->data;
    const uint8_t *data;
    struct l3_view l3;
    int parse_result;

    meta->action = ONVM_NF_ACTION_DROP;
    if (!state->cleartext_test) {
        /* Never forward clear user traffic when IPsec is unavailable. */
        ++state->stats.crypto_failures;
        return 0;
    }
    data = rte_pktmbuf_mtod(packet, const uint8_t *);
    parse_result = parse_l3(data, rte_pktmbuf_pkt_len(packet), &l3);
    if (parse_result == -EINPROGRESS) {
        ++state->stats.fragment_drops;
        return 0;
    }
    if (parse_result != 0) {
        ++state->stats.malformed_packets;
        return 0;
    }
    if (l3.next_header == IPPROTO_GRE) {
        (void)handle_clear_uplink(packet, meta, state, &l3);
        return 0;
    }

    if (l3.next_header == IPPROTO_UDP) {
        (void)n3iwf_dp_handle_clear_downlink(packet, meta, &state->sessions,
                                              &state->stats, state->access_port);
        return 0;
    }
    ++state->stats.malformed_packets;
    return 0;
}

static int
periodic_action(struct onvm_nf_local_ctx *local_context)
{
    struct n3iwf_dp_state *state = local_context->nf->data;

    (void)n3iwf_dp_control_poll(&state->control);
    return 0;
}

int
main(int argc, char **argv)
{
    struct onvm_nf_local_ctx *local_context;
    struct onvm_nf_function_table *functions;
    struct n3iwf_dp_state *state;
    int argument_offset;

    local_context = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(local_context, NULL);
    functions = onvm_nflib_init_nf_function_table();
    functions->pkt_handler = packet_handler;
    functions->user_actions = periodic_action;

    argument_offset = onvm_nflib_init(argc, argv, NF_TAG, local_context,
                                      functions);
    if (argument_offset < 0) {
        onvm_nflib_stop(local_context);
        return argument_offset == ONVM_SIGNAL_TERMINATION ? 0 : EXIT_FAILURE;
    }
    argc -= argument_offset;
    argv += argument_offset;

    state = rte_zmalloc("n3iwf_dp_state", sizeof(*state), RTE_CACHE_LINE_SIZE);
    if (state == NULL) {
        rte_exit(EXIT_FAILURE, "N3IWF-DP state allocation failed\n");
    }
    state->upf_service_id = DEFAULT_UPF_SERVICE_ID;
    state->access_port = DEFAULT_ACCESS_PORT;
    strcpy(state->control_socket, DEFAULT_CONTROL_SOCKET);
    n3iwf_dp_session_table_init(&state->sessions);
    local_context->nf->data = state;

    if (parse_args(argc, argv, state) != 0) {
        usage(argv[0]);
        onvm_nflib_stop(local_context);
        return EXIT_FAILURE;
    }
    if (n3iwf_dp_control_open(&state->control, state->control_socket,
                              &state->sessions, &state->stats) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot open N3IWF-DP control socket %s\n",
                 state->control_socket);
    }

    printf("N3IWF-DP control=%s upf_service=%u access_port=%u mode=%s\n",
           state->control_socket, state->upf_service_id, state->access_port,
           state->cleartext_test ? "cleartext-test" : "fail-closed");
    onvm_nflib_run(local_context);

    n3iwf_dp_control_close(&state->control);
    rte_free(state);
    local_context->nf->data = NULL;
    onvm_nflib_stop(local_context);
    return 0;
}
