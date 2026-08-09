/*
 * Strict low-rate NWu control-packet boundary between ONVM and Linux.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef N3IWF_DP_PUNT_H
#define N3IWF_DP_PUNT_H

#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum n3iwf_dp_punt_kind {
    N3IWF_DP_PUNT_NONE = 0,
    N3IWF_DP_PUNT_ARP = 1,
    N3IWF_DP_PUNT_IKE = 2,
    N3IWF_DP_PUNT_ESP = 3,
};

struct n3iwf_dp_punt {
    int fd;
    uint32_t local_ipv4_be;
    char ifname[IF_NAMESIZE];
};

int
n3iwf_dp_punt_open(struct n3iwf_dp_punt *punt, const char *ifname,
                   const char *local_ipv4);

void
n3iwf_dp_punt_close(struct n3iwf_dp_punt *punt);

ssize_t
n3iwf_dp_punt_read(struct n3iwf_dp_punt *punt, void *frame, size_t capacity);

ssize_t
n3iwf_dp_punt_write(struct n3iwf_dp_punt *punt, const void *frame,
                    size_t length);

/* Return a punt kind, N3IWF_DP_PUNT_NONE, or a negative errno value. */
int
n3iwf_dp_punt_classify_to_cp(const uint8_t *frame, size_t length,
                             uint32_t local_ipv4_be,
                             bool allow_kernel_signalling_esp);

int
n3iwf_dp_punt_classify_from_cp(const uint8_t *frame, size_t length,
                               uint32_t local_ipv4_be,
                               bool allow_kernel_signalling_esp);

#endif
