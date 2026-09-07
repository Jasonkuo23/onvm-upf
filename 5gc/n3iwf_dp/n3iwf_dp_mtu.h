/*
 * Fixed MTU contract for the current production N3IWF dataplane profile.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef N3IWF_DP_MTU_H
#define N3IWF_DP_MTU_H

#include <stdbool.h>
#include <stddef.h>

/* IP MTUs exclude the Ethernet header and FCS. */
#define N3IWF_DP_NWU_IP_MTU 1500U
#define N3IWF_DP_N3_IP_MTU 1500U
#define N3IWF_DP_N6_IP_MTU 1500U

#define N3IWF_DP_ETHERNET_HEADER_LEN 14U
#define N3IWF_DP_IPV4_HEADER_LEN 20U
#define N3IWF_DP_UDP_HEADER_LEN 8U
#define N3IWF_DP_GRE_KEY_HEADER_LEN 8U
#define N3IWF_DP_GTPU_PSC_HEADER_LEN 16U
#define N3IWF_DP_ESP_HEADER_LEN 8U
#define N3IWF_DP_AES_CBC_BLOCK_LEN 16U
#define N3IWF_DP_AES_CBC_IV_LEN_BYTES 16U
#define N3IWF_DP_SHA1_96_ICV_LEN 12U
#define N3IWF_DP_ESP_TRAILER_FIXED_LEN 2U

#define N3IWF_DP_N3_IP_OVERHEAD \
    (N3IWF_DP_IPV4_HEADER_LEN + N3IWF_DP_UDP_HEADER_LEN + \
     N3IWF_DP_GTPU_PSC_HEADER_LEN)

/* DPDK replaces the clear Ethernet header while prepending IPv4/ESP/IV, then
 * cpu_crypto restores Ethernet. Reserve the complete 44-byte expansion. */
#define N3IWF_DP_ESP_OUTBOUND_HEADROOM \
    (N3IWF_DP_IPV4_HEADER_LEN + N3IWF_DP_ESP_HEADER_LEN + \
     N3IWF_DP_AES_CBC_IV_LEN_BYTES)
/* Worst case: 15 padding bytes, the two-byte ESP trailer, and the 12-byte ICV. */
#define N3IWF_DP_ESP_OUTBOUND_TAILROOM \
    (N3IWF_DP_AES_CBC_BLOCK_LEN - 1U + \
     N3IWF_DP_ESP_TRAILER_FIXED_LEN + N3IWF_DP_SHA1_96_ICV_LEN)

/*
 * ESP protects the clear IPv4/GRE/inner-IP packet.  The 1410-byte value is
 * the largest inner packet for which the AES-CBC-padded ESP tunnel remains
 * within the 1500-byte NWu IP MTU.  N3 and N6 are not the limiting links.
 */
#define N3IWF_DP_MAX_INNER_PACKET_LEN 1410U

static inline size_t
n3iwf_dp_align_up(size_t value, size_t alignment)
{
    return ((value + alignment - 1U) / alignment) * alignment;
}

static inline size_t
n3iwf_dp_esp_outer_ipv4_len(size_t inner_len)
{
    const size_t protected_len = N3IWF_DP_IPV4_HEADER_LEN +
                                 N3IWF_DP_GRE_KEY_HEADER_LEN + inner_len;

    return N3IWF_DP_IPV4_HEADER_LEN + N3IWF_DP_ESP_HEADER_LEN +
           N3IWF_DP_AES_CBC_IV_LEN_BYTES +
           n3iwf_dp_align_up(protected_len +
                                 N3IWF_DP_ESP_TRAILER_FIXED_LEN,
                             N3IWF_DP_AES_CBC_BLOCK_LEN) +
           N3IWF_DP_SHA1_96_ICV_LEN;
}

static inline size_t
n3iwf_dp_n3_outer_ipv4_len(size_t inner_len)
{
    return N3IWF_DP_N3_IP_OVERHEAD + inner_len;
}

static inline bool
n3iwf_dp_inner_packet_supported(size_t inner_len)
{
    return inner_len <= N3IWF_DP_MAX_INNER_PACKET_LEN &&
           n3iwf_dp_esp_outer_ipv4_len(inner_len) <= N3IWF_DP_NWU_IP_MTU &&
           n3iwf_dp_n3_outer_ipv4_len(inner_len) <= N3IWF_DP_N3_IP_MTU &&
           inner_len <= N3IWF_DP_N6_IP_MTU;
}

_Static_assert(N3IWF_DP_N3_IP_OVERHEAD + N3IWF_DP_MAX_INNER_PACKET_LEN <=
                   N3IWF_DP_N3_IP_MTU,
               "inner MTU must fit the logical N3 IP MTU");

#endif
