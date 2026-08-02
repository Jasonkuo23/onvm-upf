/*
 * Copyright 2026 University of California, Riverside and
 * National Yang Ming Chiao Tung University
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef N3IWF_DP_CODEC_H
#define N3IWF_DP_CODEC_H

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
    enum n3iwf_dp_direction direction;
    const uint8_t *payload;
    size_t payload_len;
    size_t header_len;
};

struct n3iwf_dp_gre_view {
    uint16_t protocol;
    uint32_t key;
    uint8_t qfi;
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
                    enum n3iwf_dp_direction direction, const uint8_t *payload,
                    size_t payload_len, size_t *encoded_len);

int
n3iwf_dp_gtpu_parse(const uint8_t *packet, size_t packet_len,
                    struct n3iwf_dp_gtpu_view *view);

/*
 * The GRE Key field carries QFI in its least-significant six bits. The full
 * key is returned so future Release 18 key bits can be preserved.
 */
int
n3iwf_dp_gre_build(uint8_t *out, size_t capacity, uint16_t protocol,
                   uint32_t key, const uint8_t *payload, size_t payload_len,
                   size_t *encoded_len);

int
n3iwf_dp_gre_parse(const uint8_t *packet, size_t packet_len,
                   struct n3iwf_dp_gre_view *view);

#endif
