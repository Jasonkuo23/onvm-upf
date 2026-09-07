/*
 * Copyright 2026 University of California, Riverside and
 * National Yang Ming Chiao Tung University
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_codec.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

#define GTPU_BASE_LEN 8U
#define GTPU_OPTIONAL_LEN 4U
#define GTPU_PSC_LEN 4U
#define GTPU_FLAGS_V1_PT_E 0x34U
#define GTPU_FLAG_E 0x04U
#define GTPU_FLAG_OPTIONAL_MASK 0x07U

#define GRE_BASE_LEN 4U
#define GRE_KEY_LEN 4U
#define GRE_FLAG_KEY 0x2000U
#define GRE_QFI_MASK UINT32_C(0x3f000000)
#define GRE_RQI_MASK UINT32_C(0x00000080)

static uint16_t
read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t
read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void
write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void
write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

int
n3iwf_dp_gtpu_build(uint8_t *out, size_t capacity, uint32_t teid, uint8_t qfi,
                    bool rqi, enum n3iwf_dp_direction direction,
                    const uint8_t *payload, size_t payload_len,
                    size_t *encoded_len)
{
    const size_t header_len = GTPU_BASE_LEN + GTPU_OPTIONAL_LEN + GTPU_PSC_LEN;
    const size_t after_mandatory = GTPU_OPTIONAL_LEN + GTPU_PSC_LEN + payload_len;

    if (out == NULL || encoded_len == NULL || (payload == NULL && payload_len != 0) ||
        teid == 0 || qfi == 0 || qfi > 63 ||
        (direction != N3IWF_DP_DOWNLINK && direction != N3IWF_DP_UPLINK) ||
        (direction == N3IWF_DP_UPLINK && rqi)) {
        return -EINVAL;
    }
    if (after_mandatory > UINT16_MAX || capacity < header_len + payload_len) {
        return -EMSGSIZE;
    }

    out[0] = GTPU_FLAGS_V1_PT_E;
    out[1] = N3IWF_DP_GTPU_TPDU;
    write_be16(out + 2, (uint16_t)after_mandatory);
    write_be32(out + 4, teid);

    /* Sequence number and N-PDU number are absent, but the optional row is
     * mandatory whenever E is set. */
    out[8] = 0;
    out[9] = 0;
    out[10] = 0;
    out[11] = N3IWF_DP_GTPU_PSC;

    /* TS 29.281 extension length is expressed in four-octet units. The
     * first content nibble is the PDU type: 0=DL, 1=UL. */
    out[12] = 1;
    out[13] = direction == N3IWF_DP_UPLINK ? 0x10U : 0x00U;
    out[14] = (qfi & 0x3fU) |
              (direction == N3IWF_DP_DOWNLINK && rqi ? 0x40U : 0U);
    out[15] = 0;

    if (payload_len != 0) {
        memcpy(out + header_len, payload, payload_len);
    }
    *encoded_len = header_len + payload_len;
    return 0;
}

int
n3iwf_dp_gtpu_parse(const uint8_t *packet, size_t packet_len,
                    struct n3iwf_dp_gtpu_view *view)
{
    size_t offset = GTPU_BASE_LEN;
    size_t declared_len;
    uint8_t next_extension = 0;
    uint8_t qfi = 0;
    bool rqi = false;
    bool psc_seen = false;
    enum n3iwf_dp_direction direction = N3IWF_DP_DOWNLINK;

    if (packet == NULL || view == NULL || packet_len < GTPU_BASE_LEN) {
        return -EINVAL;
    }
    memset(view, 0, sizeof(*view));

    if ((packet[0] & 0xf0U) != 0x30U || packet[1] != N3IWF_DP_GTPU_TPDU) {
        return -EPROTO;
    }
    declared_len = (size_t)read_be16(packet + 2) + GTPU_BASE_LEN;
    if (declared_len > packet_len) {
        return -EMSGSIZE;
    }

    if ((packet[0] & GTPU_FLAG_OPTIONAL_MASK) != 0) {
        if (declared_len < offset + GTPU_OPTIONAL_LEN) {
            return -EMSGSIZE;
        }
        next_extension = packet[offset + 3];
        offset += GTPU_OPTIONAL_LEN;
    }

    if ((packet[0] & GTPU_FLAG_E) == 0 && next_extension != 0) {
        return -EPROTO;
    }

    while (next_extension != 0) {
        size_t extension_len;
        uint8_t current_type = next_extension;

        if (offset >= declared_len) {
            return -EMSGSIZE;
        }
        extension_len = (size_t)packet[offset] * 4U;
        if (extension_len < 4 || extension_len > declared_len - offset) {
            return -EMSGSIZE;
        }

        next_extension = packet[offset + extension_len - 1];
        if (current_type == N3IWF_DP_GTPU_PSC) {
            uint8_t pdu_type;
            uint8_t qos_octet;

            if (psc_seen) {
                return -EPROTO;
            }
            psc_seen = true;
            pdu_type = packet[offset + 1] >> 4;
            qos_octet = packet[offset + 2];

            /* This dataplane supports the base DL/UL PSC formats. Optional
             * timestamp, sequence, paging-policy, and delay fields are not
             * silently ignored when their presence bits are asserted. */
            if ((packet[offset + 1] & 0x0fU) != 0) {
                return -EOPNOTSUPP;
            }
            if (pdu_type == N3IWF_DP_DOWNLINK) {
                if ((qos_octet & 0x80U) != 0) {
                    return -EOPNOTSUPP;
                }
                direction = N3IWF_DP_DOWNLINK;
                rqi = (qos_octet & 0x40U) != 0;
            } else if (pdu_type == N3IWF_DP_UPLINK) {
                if ((qos_octet & 0xc0U) != 0) {
                    return -EOPNOTSUPP;
                }
                direction = N3IWF_DP_UPLINK;
                rqi = false;
            } else {
                return -EPROTONOSUPPORT;
            }
            qfi = qos_octet & 0x3fU;
        }
        offset += extension_len;
    }

    if (qfi == 0) {
        return -ENOMSG;
    }

    view->teid = read_be32(packet + 4);
    if (view->teid == 0) {
        return -EPROTO;
    }
    view->qfi = qfi;
    view->rqi = rqi;
    view->direction = direction;
    view->payload = packet + offset;
    view->payload_len = declared_len - offset;
    view->header_len = offset;
    return 0;
}

int
n3iwf_dp_gre_build(uint8_t *out, size_t capacity, uint16_t protocol,
                   uint8_t qfi, bool rqi,
                   enum n3iwf_dp_direction direction, const uint8_t *payload,
                   size_t payload_len, size_t *encoded_len)
{
    const size_t header_len = GRE_BASE_LEN + GRE_KEY_LEN;

    if (out == NULL || encoded_len == NULL || (payload == NULL && payload_len != 0) ||
        (protocol != N3IWF_DP_GRE_PROTO_IPV4 &&
         protocol != N3IWF_DP_GRE_PROTO_IPV6) ||
        qfi == 0 || qfi > 63 ||
        (direction != N3IWF_DP_DOWNLINK && direction != N3IWF_DP_UPLINK) ||
        (direction == N3IWF_DP_UPLINK && rqi)) {
        return -EINVAL;
    }
    if (capacity < header_len + payload_len) {
        return -EMSGSIZE;
    }

    write_be16(out, GRE_FLAG_KEY);
    write_be16(out + 2, protocol);
    write_be32(out + 4, ((uint32_t)(qfi & 0x3fU) << 24) |
                          (rqi ? GRE_RQI_MASK : 0));
    if (payload_len != 0) {
        memcpy(out + header_len, payload, payload_len);
    }
    *encoded_len = header_len + payload_len;
    return 0;
}

int
n3iwf_dp_gre_parse(const uint8_t *packet, size_t packet_len,
                   enum n3iwf_dp_direction direction,
                   struct n3iwf_dp_gre_view *view)
{
    uint16_t flags;

    if (packet == NULL || view == NULL || packet_len < GRE_BASE_LEN + GRE_KEY_LEN ||
        (direction != N3IWF_DP_DOWNLINK && direction != N3IWF_DP_UPLINK)) {
        return -EINVAL;
    }
    memset(view, 0, sizeof(*view));
    flags = read_be16(packet);

    if ((flags & GRE_FLAG_KEY) == 0 ||
        (flags & (uint16_t)~GRE_FLAG_KEY) != 0) {
        return -EPROTO;
    }
    view->protocol = read_be16(packet + 2);
    if (view->protocol != N3IWF_DP_GRE_PROTO_IPV4 &&
        view->protocol != N3IWF_DP_GRE_PROTO_IPV6) {
        return -EPROTONOSUPPORT;
    }
    view->key = read_be32(packet + 4);
    if ((view->key & ~(GRE_QFI_MASK | GRE_RQI_MASK)) != 0 ||
        (direction == N3IWF_DP_UPLINK &&
         (view->key & GRE_RQI_MASK) != 0)) {
        return -EPROTO;
    }
    view->qfi = (uint8_t)((view->key >> 24) & 0x3fU);
    view->rqi = (view->key & GRE_RQI_MASK) != 0;
    if (view->qfi == 0) {
        return -ENOMSG;
    }
    view->header_len = GRE_BASE_LEN + GRE_KEY_LEN;
    view->payload = packet + view->header_len;
    view->payload_len = packet_len - view->header_len;
    return 0;
}
