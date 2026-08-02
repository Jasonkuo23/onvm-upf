/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef N3IWF_DP_DOWNLINK_H
#define N3IWF_DP_DOWNLINK_H

#include "n3iwf_dp_session.h"
#include "n3iwf_dp_wire.h"

#include <stdint.h>

#include <rte_mbuf.h>

#include "onvm_common.h"

/*
 * Clear-GRE integration path only. Production downlink will call the same
 * strict GTP/session parser, then submit GRE to the selected ESP cryptodev SA.
 */
int
n3iwf_dp_handle_clear_downlink(
    struct rte_mbuf *packet,
    struct onvm_pkt_meta *meta,
    const struct n3iwf_dp_session_table *sessions,
    struct n3iwf_dp_stats_wire *stats,
    uint16_t access_port);

#endif
