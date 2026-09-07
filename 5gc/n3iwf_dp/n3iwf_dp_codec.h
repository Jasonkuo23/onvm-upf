/*
 * Copyright 2026 University of California, Riverside and
 * National Yang Ming Chiao Tung University
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef N3IWF_DP_CODEC_H
#define N3IWF_DP_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define N3IWF_DP_GTPU_PORT 2152U
#define N3IWF_DP_GTPU_TPDU 0xffU
#define N3IWF_DP_GTPU_PSC  0x85U

#define N3IWF_DP_GRE_PROTO_IPV4 0x0800U
#define N3IWF_DP_GRE_PROTO_IPV6 0x86ddU

enum n3iwf_dp_direction {
    N3IWF_DP_DOWNLINK = 0,
    N3IWF_DP_UPLINK = 1,
};

struct n3iwf_dp_gtpu_view {
    uint32_t teid;
    uint8_t qfi;
    bool rqi;
    enum n3iwf_dp_direction direction;
    const uint8_t *payload;
    size_t payload_len;
    size_t header_len;
};

struct n3iwf_dp_gre_view {
    uint16_t protocol;
    uint32_t key;
    uint8_t qfi;
    bool rqi;
    const uint8_t *payload;
    size_t payload_len;
    size_t header_len;
};

/*
 * Build and parse the G-PDU portion beginning at the first GTP-U octet.
 * The builder always includes a PDU Session Container so QFI is never lost.
 */
int
n3iwf_dp_gtpu_build(uint8_t *out, size_t capacity, uint32_t teid, uint8_t qfi,
                    bool rqi, enum n3iwf_dp_direction direction,
                    const uint8_t *payload, size_t payload_len,
                    size_t *encoded_len);

int
n3iwf_dp_gtpu_parse(const uint8_t *packet, size_t packet_len,
                    struct n3iwf_dp_gtpu_view *view);

/*
 * TS 24.502 section 9.3.3 carries QFI in bits 24..29 and downlink RQI in bit
 * 7 of the 32-bit GRE Key field. Direction is explicit so an uplink caller
 * cannot accidentally originate or accept RQI, which is defined only for a
 * downlink user-data packet. Reserved key bits are rejected.
 */
int
n3iwf_dp_gre_build(uint8_t *out, size_t capacity, uint16_t protocol,
                   uint8_t qfi, bool rqi,
                   enum n3iwf_dp_direction direction, const uint8_t *payload,
                   size_t payload_len, size_t *encoded_len);

int
n3iwf_dp_gre_parse(const uint8_t *packet, size_t packet_len,
                   enum n3iwf_dp_direction direction,
                   struct n3iwf_dp_gre_view *view);

#endif
