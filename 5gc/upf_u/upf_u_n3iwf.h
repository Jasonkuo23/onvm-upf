/*
 * Same-server ONVM N3IWF routing helpers.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UPF_U_N3IWF_H
#define UPF_U_N3IWF_H

#include <stdbool.h>
#include <stdint.h>

#include <rte_mbuf.h>

#include "onvm_common.h"

bool
upf_u_n3iwf_peer_matches(bool enabled, uint32_t configured_peer_ip_be,
                          uint32_t packet_peer_ip_be);

/* Host-order two-octet base DL PDU Session Information value. */
uint16_t
upf_u_n3iwf_dl_pdu_session_information(uint8_t qfi, bool rqi);

/* Add the Ethernet framing expected by n3iwf-dp without physical ARP/L2. */
int
upf_u_n3iwf_prepend_internal_ethernet(struct rte_mbuf *packet);

void
upf_u_n3iwf_set_route(struct onvm_pkt_meta *meta, bool use_n3iwf,
                      uint16_t n3iwf_service_id, uint16_t physical_n3_port);

#endif
