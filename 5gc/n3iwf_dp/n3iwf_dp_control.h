/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef N3IWF_DP_CONTROL_H
#define N3IWF_DP_CONTROL_H

#include "n3iwf_dp_session.h"
#include "n3iwf_dp_wire.h"

#include <stddef.h>

#define N3IWF_DP_CONTROL_MAX_MESSAGE 2048U

struct n3iwf_dp_control {
    int listen_fd;
    int client_fd;
    char socket_path[108];
    struct n3iwf_dp_session_table *sessions;
    struct n3iwf_dp_stats_wire *stats;
};

int
n3iwf_dp_control_open(struct n3iwf_dp_control *control, const char *socket_path,
                      struct n3iwf_dp_session_table *sessions,
                      struct n3iwf_dp_stats_wire *stats);

/* Non-blocking; process at most one connection event and one message. */
int
n3iwf_dp_control_poll(struct n3iwf_dp_control *control);

void
n3iwf_dp_control_close(struct n3iwf_dp_control *control);

#endif
