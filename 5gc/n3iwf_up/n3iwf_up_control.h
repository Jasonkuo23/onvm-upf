/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef N3IWF_UP_CONTROL_H
#define N3IWF_UP_CONTROL_H

#include "n3iwf_up_child_sa.h"
#include "n3iwf_up_session.h"
#include "n3iwf_up_wire.h"

#include <stddef.h>
#include "../../../n3iwf-up-client/transport.h"

#define N3IWF_UP_CONTROL_MAX_MESSAGE N3DP_MAX_MESSAGE
#define N3IWF_UP_CONTROL_MAX_CLIENTS N3DP_MAX_CLIENTS

struct n3iwf_up_control {
    struct n3dp_server transport;
    uint64_t client_owners[N3IWF_UP_CONTROL_MAX_CLIENTS];
    unsigned char client_roles[N3IWF_UP_CONTROL_MAX_CLIENTS];
    struct n3iwf_up_session_table *sessions;
    struct n3iwf_up_child_sa_table *child_sas;
    struct n3iwf_up_stats_wire *stats;
};

int
n3iwf_up_control_open(struct n3iwf_up_control *control, const char *control_name,
                      struct n3iwf_up_session_table *sessions,
                      struct n3iwf_up_child_sa_table *child_sas,
                      struct n3iwf_up_stats_wire *stats);

/* Nonblocking shared-memory polling; at most one command per client/burst. */
int
n3iwf_up_control_poll(struct n3iwf_up_control *control);

void
n3iwf_up_control_close(struct n3iwf_up_control *control);

#endif
