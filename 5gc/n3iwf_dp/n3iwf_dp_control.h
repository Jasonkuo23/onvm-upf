/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef N3IWF_DP_CONTROL_H
#define N3IWF_DP_CONTROL_H

#include "n3iwf_dp_child_sa.h"
#include "n3iwf_dp_session.h"
#include "n3iwf_dp_wire.h"

#include <stddef.h>

#define N3IWF_DP_CONTROL_MAX_MESSAGE 2048U
#define N3IWF_DP_CONTROL_MAX_CLIENTS 8U

struct n3iwf_dp_control {
    int listen_fd;
    int client_fds[N3IWF_DP_CONTROL_MAX_CLIENTS];
    unsigned char client_roles[N3IWF_DP_CONTROL_MAX_CLIENTS];
    char socket_path[108];
    struct n3iwf_dp_session_table *sessions;
    struct n3iwf_dp_child_sa_table *child_sas;
    struct n3iwf_dp_stats_wire *stats;
};

int
n3iwf_dp_control_open(struct n3iwf_dp_control *control, const char *socket_path,
                      struct n3iwf_dp_session_table *sessions,
                      struct n3iwf_dp_child_sa_table *child_sas,
                      struct n3iwf_dp_stats_wire *stats);

/* Non-blocking; accept one connection and process one message per client. */
int
n3iwf_dp_control_poll(struct n3iwf_dp_control *control);

void
n3iwf_dp_control_close(struct n3iwf_dp_control *control);

#endif
