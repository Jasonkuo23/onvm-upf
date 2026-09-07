/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef N3IWF_DP_CLEAR_H
#define N3IWF_DP_CLEAR_H

#include "n3iwf_dp_session.h"
#include "n3iwf_dp_wire.h"

#include <stdint.h>

#include <rte_mbuf.h>

#include "onvm_common.h"

/*
 * Test-only clear user-plane packet handler shared by the ONVM NF and the
 * deterministic EAL acceptance test. Production mode must never call it.
 */
int
n3iwf_dp_handle_clear_packet(
    struct rte_mbuf *packet,
    struct onvm_pkt_meta *meta,
    struct n3iwf_dp_session_table *sessions,
    struct n3iwf_dp_stats_wire *stats,
    uint16_t upf_service_id,
    uint16_t access_port,
    const uint8_t access_mac[N3IWF_DP_ETHER_ADDR_LEN]);

/* Secure uplink entry after ESP authentication.  The caller supplies the
 * session selected directly from the authenticated Child SA; this function
 * parses and validates GRE/QFI without performing the ambiguous clear-mode
 * NWu-address lookup. */
int
n3iwf_dp_handle_authenticated_uplink(
    struct rte_mbuf *packet,
    struct onvm_pkt_meta *meta,
    struct n3iwf_dp_session *session,
    struct n3iwf_dp_stats_wire *stats,
    uint16_t upf_service_id,
    const uint8_t access_mac[N3IWF_DP_ETHER_ADDR_LEN]);

#endif
