/*
 * L25GC+ N3IWF user-plane ONVM NF.
 *
 * The initial dataplane is deliberately fail-closed. Production packets are
 * accepted only after a cryptodev backend is connected. The -t option enables
 * a clear-GRE integration mode for deterministic ONVM/GTP-U testing.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_clear.h"
#include "n3iwf_dp_control.h"
#include "n3iwf_dp_punt.h"
#include "n3iwf_dp_session.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>

#include "onvm_nflib.h"

#define NF_TAG "n3iwf_dp"
#define DEFAULT_CONTROL_SOCKET "/run/l25gc/n3iwf-dp.sock"
#define DEFAULT_UPF_SERVICE_ID 1U
#define DEFAULT_ACCESS_PORT 0U
#define CONTROL_FRAME_CAPACITY 4096U
#define CONTROL_RX_BURST 32U

struct n3iwf_dp_state {
    struct n3iwf_dp_session_table sessions;
    struct n3iwf_dp_child_sa_table child_sas;
    struct n3iwf_dp_control control;
    struct n3iwf_dp_punt punt;
    struct n3iwf_dp_stats_wire stats;
    struct rte_mempool *pktmbuf_pool;
    uint16_t upf_service_id;
    uint16_t access_port;
    bool cleartext_test;
    bool punt_enabled;
    bool allow_kernel_signalling_esp;
    char control_socket[108];
    char punt_ifname[IF_NAMESIZE];
    char nwu_ipv4[INET_ADDRSTRLEN];
    uint8_t access_mac[N3IWF_DP_ETHER_ADDR_LEN];
};

static void
usage(const char *program)
{
    printf("Usage: %s [DPDK args] -- [ONVM args] -- "
           "[-c socket] [-s upf-service] [-a access-port] "
           "[-p tap -i NWu-IPv4] [-k] [-t]\n", program);
    puts("  -p/-i enable the strict ARP/IKE TAP control-packet boundary");
    puts("  -k also punts kernel signalling ESP (temporary transition only)");
    puts("  -t enables clear-GRE test mode; without it user traffic is dropped");
}

static int
parse_args(int argc, char **argv, struct n3iwf_dp_state *state)
{
    int option;

    optind = 1;
    while ((option = getopt(argc, argv, "c:s:a:p:i:kth")) != -1) {
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
        case 'p':
            if (strlen(optarg) >= sizeof(state->punt_ifname)) {
                return -1;
            }
            strcpy(state->punt_ifname, optarg);
            break;
        case 'i':
            if (strlen(optarg) >= sizeof(state->nwu_ipv4)) {
                return -1;
            }
            strcpy(state->nwu_ipv4, optarg);
            break;
        case 'k':
            state->allow_kernel_signalling_esp = true;
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
    if ((state->punt_ifname[0] == '\0') != (state->nwu_ipv4[0] == '\0')) {
        return -1;
    }
    return 0;
}

static int
punt_packet_to_cp(struct rte_mbuf *packet, struct n3iwf_dp_state *state)
{
    uint8_t frame[CONTROL_FRAME_CAPACITY];
    const uint8_t *data;
    uint32_t length = rte_pktmbuf_pkt_len(packet);
    int kind;

    if (!state->punt_enabled || packet->port != state->access_port) {
        return N3IWF_DP_PUNT_NONE;
    }
    if (length > sizeof(frame)) {
        ++state->stats.control_punt_drops;
        return -EMSGSIZE;
    }
    data = rte_pktmbuf_read(packet, 0, length, frame);
    if (data == NULL) {
        ++state->stats.control_punt_drops;
        return -EMSGSIZE;
    }
    kind = n3iwf_dp_punt_classify_to_cp(
        data, length, state->punt.local_ipv4_be,
        state->allow_kernel_signalling_esp);
    if (kind > N3IWF_DP_PUNT_NONE) {
        if (n3iwf_dp_punt_write(&state->punt, data, length) ==
            (ssize_t)length) {
            ++state->stats.control_to_cp;
        } else {
            ++state->stats.control_punt_drops;
        }
    } else if (kind < 0) {
        ++state->stats.control_punt_drops;
        if (kind == -EOPNOTSUPP) {
            ++state->stats.fragment_drops;
        }
    }
    return kind;
}

static int
packet_handler(struct rte_mbuf *packet, struct onvm_pkt_meta *meta,
               struct onvm_nf_local_ctx *local_context)
{
    struct n3iwf_dp_state *state = local_context->nf->data;

    meta->action = ONVM_NF_ACTION_DROP;
    if (punt_packet_to_cp(packet, state) != N3IWF_DP_PUNT_NONE) {
        return 0;
    }
    if (!state->cleartext_test) {
        /* Never forward clear user traffic when IPsec is unavailable. */
        ++state->stats.crypto_failures;
        return 0;
    }
    (void)n3iwf_dp_handle_clear_packet(packet, meta, &state->sessions,
                                       &state->stats, state->upf_service_id,
                                       state->access_port, state->access_mac);
    return 0;
}

static void
return_control_packets(struct onvm_nf_local_ctx *local_context,
                       struct n3iwf_dp_state *state)
{
    uint8_t frame[CONTROL_FRAME_CAPACITY];
    unsigned int count;

    if (!state->punt_enabled) {
        return;
    }
    for (count = 0; count < CONTROL_RX_BURST; ++count) {
        struct rte_mbuf *packet;
        struct onvm_pkt_meta *meta;
        void *data;
        ssize_t length = n3iwf_dp_punt_read(&state->punt, frame,
                                             sizeof(frame));
        int kind;

        if (length == -EAGAIN || length == -EWOULDBLOCK) {
            break;
        }
        if (length <= 0) {
            if (length < 0) {
                ++state->stats.control_punt_drops;
            }
            break;
        }
        kind = n3iwf_dp_punt_classify_from_cp(
            frame, (size_t)length, state->punt.local_ipv4_be,
            state->allow_kernel_signalling_esp);
        if (kind <= N3IWF_DP_PUNT_NONE) {
            ++state->stats.control_punt_drops;
            if (kind == -EOPNOTSUPP) {
                ++state->stats.fragment_drops;
            }
            continue;
        }
        packet = rte_pktmbuf_alloc(state->pktmbuf_pool);
        if (packet == NULL) {
            ++state->stats.control_punt_drops;
            continue;
        }
        data = rte_pktmbuf_append(packet, (uint16_t)length);
        if (data == NULL) {
            rte_pktmbuf_free(packet);
            ++state->stats.control_punt_drops;
            continue;
        }
        memcpy(data, frame, (size_t)length);
        packet->port = state->access_port;
        meta = onvm_get_pkt_meta(packet, local_context->nf->dynfield_offset);
        meta->destination = state->access_port;
        meta->action = ONVM_NF_ACTION_OUT;
        if (onvm_nflib_return_pkt(local_context->nf, packet) == 0) {
            ++state->stats.control_from_cp;
        } else {
            ++state->stats.control_punt_drops;
        }
    }
}

static int
periodic_action(struct onvm_nf_local_ctx *local_context)
{
    struct n3iwf_dp_state *state = local_context->nf->data;

    (void)n3iwf_dp_control_poll(&state->control);
    return_control_packets(local_context, state);
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

    /* Newly allocated TAP-return mbufs do not arrive through the normal RX
     * callback, so their ONVM metadata must be addressed with the manager's
     * registered dynamic-field offset. This is process-local DPDK state and
     * is not initialized in struct onvm_nf by onvm_nflib_init(). */
    local_context->nf->dynfield_offset =
        onvm_nflib_get_onvm_config()->dynfield_offset;

    state = rte_zmalloc("n3iwf_dp_state", sizeof(*state), RTE_CACHE_LINE_SIZE);
    if (state == NULL) {
        rte_exit(EXIT_FAILURE, "N3IWF-DP state allocation failed\n");
    }
    state->upf_service_id = DEFAULT_UPF_SERVICE_ID;
    state->access_port = DEFAULT_ACCESS_PORT;
    state->punt.fd = -1;
    strcpy(state->control_socket, DEFAULT_CONTROL_SOCKET);
    n3iwf_dp_session_table_init(&state->sessions);
    n3iwf_dp_child_sa_table_init(&state->child_sas);
    local_context->nf->data = state;

    if (parse_args(argc, argv, state) != 0) {
        usage(argv[0]);
        onvm_nflib_stop(local_context);
        return EXIT_FAILURE;
    }
    if (state->cleartext_test) {
        struct rte_ether_addr access_mac;

        if (!rte_eth_dev_is_valid_port(state->access_port) ||
            rte_eth_macaddr_get(state->access_port, &access_mac) != 0 ||
            !rte_is_valid_assigned_ether_addr(&access_mac)) {
            rte_exit(EXIT_FAILURE,
                     "Cannot resolve a valid MAC for access port %u\n",
                     state->access_port);
        }
        memcpy(state->access_mac, access_mac.addr_bytes,
               sizeof(state->access_mac));
    }
    if (n3iwf_dp_control_open(&state->control, state->control_socket,
                              &state->sessions, &state->child_sas,
                              &state->stats) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot open N3IWF-DP control socket %s\n",
                 state->control_socket);
    }
    if (state->punt_ifname[0] != '\0') {
        int punt_result = n3iwf_dp_punt_open(&state->punt,
                                             state->punt_ifname,
                                             state->nwu_ipv4);

        if (punt_result != 0) {
            rte_exit(EXIT_FAILURE, "Cannot open N3IWF CP TAP %s: %s\n",
                     state->punt_ifname, strerror(-punt_result));
        }
        state->pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if (state->pktmbuf_pool == NULL) {
            rte_exit(EXIT_FAILURE, "Cannot find ONVM packet mbuf pool\n");
        }
        state->punt_enabled = true;
    }

    printf("N3IWF-DP control=%s upf_service=%u access_port=%u mode=%s "
           "cp_tap=%s kernel_signalling_esp=%s access_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           state->control_socket, state->upf_service_id, state->access_port,
           state->cleartext_test ? "cleartext-test" : "fail-closed",
           state->punt_enabled ? state->punt.ifname : "disabled",
           state->allow_kernel_signalling_esp ? "enabled" : "disabled",
           state->access_mac[0], state->access_mac[1], state->access_mac[2],
           state->access_mac[3], state->access_mac[4], state->access_mac[5]);
    onvm_nflib_run(local_context);

    n3iwf_dp_control_close(&state->control);
    n3iwf_dp_child_sa_table_clear(&state->child_sas);
    n3iwf_dp_punt_close(&state->punt);
    rte_free(state);
    local_context->nf->data = NULL;
    onvm_nflib_stop(local_context);
    return 0;
}
