/* SPDX-License-Identifier: Apache-2.0 */
#ifndef N3IWF_DP_CHILD_SA_H
#define N3IWF_DP_CHILD_SA_H

#include "n3iwf_dp_wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define N3IWF_DP_MAX_CHILD_SAS 4096U

struct n3iwf_dp_child_sa {
    bool used;
    uint64_t generation;
    struct n3iwf_dp_child_sa_wire parameters; /* retained in network order */
};

struct n3iwf_dp_child_sa_table {
    struct n3iwf_dp_child_sa entries[N3IWF_DP_MAX_CHILD_SAS];
    size_t count;
};

void n3iwf_dp_child_sa_table_init(struct n3iwf_dp_child_sa_table *table);
void n3iwf_dp_child_sa_table_clear(struct n3iwf_dp_child_sa_table *table);

enum n3iwf_dp_status n3iwf_dp_child_sa_upsert_wire(
    struct n3iwf_dp_child_sa_table *table,
    const struct n3iwf_dp_child_sa_wire *wire, uint64_t generation);

enum n3iwf_dp_status n3iwf_dp_child_sa_delete(
    struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id, uint32_t inbound_spi, uint64_t generation);

const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_find_inbound(
    const struct n3iwf_dp_child_sa_table *table, uint32_t inbound_spi);

const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_find_session(
    const struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id);

#endif
