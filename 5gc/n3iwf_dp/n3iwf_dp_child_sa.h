/* SPDX-License-Identifier: Apache-2.0 */
#ifndef N3IWF_DP_CHILD_SA_H
#define N3IWF_DP_CHILD_SA_H

#include "n3iwf_dp_wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define N3IWF_DP_MAX_CHILD_SAS 4096U
#define N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE 8192U
#define N3IWF_DP_CHILD_SA_INDEX_TOMBSTONE UINT32_MAX

struct n3iwf_dp_session;
struct n3iwf_dp_session_table;

struct n3iwf_dp_child_sa {
    bool used;
    /* Generation which installed this particular key set. */
    uint64_t generation;
    /* Latest accepted Child-SA command for this UE/PDU session.  This is
     * advanced on both upsert and delete so a late rekey message cannot
     * resurrect or replace an SA during the overlap window. */
    uint64_t session_generation;
    /* Direct authenticated-uplink association.  The session slot generation
     * prevents a deleted/recycled session slot from receiving this SA's
     * traffic. */
    uint32_t session_index;
    uint64_t session_slot_generation;
    struct n3iwf_dp_child_sa_wire parameters; /* retained in network order */
};

struct n3iwf_dp_child_sa_table {
    struct n3iwf_dp_child_sa entries[N3IWF_DP_MAX_CHILD_SAS];
    /* Open-addressed inbound SPI -> stable entries[] slot index. */
    uint32_t inbound_spi_index[N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE];
    size_t count;
    uint64_t revision;
};

void n3iwf_dp_child_sa_table_init(struct n3iwf_dp_child_sa_table *table);
void n3iwf_dp_child_sa_table_clear(struct n3iwf_dp_child_sa_table *table);

enum n3iwf_dp_status n3iwf_dp_child_sa_upsert_wire(
    struct n3iwf_dp_child_sa_table *table,
    const struct n3iwf_dp_child_sa_wire *wire, uint64_t generation);

enum n3iwf_dp_status n3iwf_dp_child_sa_upsert_wire_at(
    struct n3iwf_dp_child_sa_table *table,
    const struct n3iwf_dp_child_sa_wire *wire, uint64_t generation,
    uint32_t *sa_index);

enum n3iwf_dp_status n3iwf_dp_child_sa_delete(
    struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id, uint32_t inbound_spi, uint64_t generation);

enum n3iwf_dp_status n3iwf_dp_child_sa_delete_at(
    struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id, uint32_t inbound_spi, uint64_t generation,
    uint32_t *sa_index);

const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_find_inbound(
    const struct n3iwf_dp_child_sa_table *table, uint32_t inbound_spi);

const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_find_inbound_at(
    const struct n3iwf_dp_child_sa_table *table, uint32_t inbound_spi,
    uint32_t *sa_index);

/* O(number-of-SAs) and restricted to control/update handling. */
const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_find_latest_for_control(
    const struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id, uint32_t *sa_index);

/* O(1) outbound selection used by the packet fast path. */
const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_get_active_outbound(
    const struct n3iwf_dp_child_sa_table *table,
    const struct n3iwf_dp_session *session, uint32_t *sa_index);

/* O(number-of-SAs + number-of-sessions), control path only. */
enum n3iwf_dp_status n3iwf_dp_child_sa_bind_session_for_control(
    struct n3iwf_dp_child_sa_table *table,
    const struct n3iwf_dp_session_table *sessions, uint64_t ue_id,
    uint32_t pdu_session_id);

/* O(1) authenticated secure-uplink selection used by the packet fast path. */
struct n3iwf_dp_session *n3iwf_dp_child_sa_get_bound_session(
    const struct n3iwf_dp_child_sa *sa,
    struct n3iwf_dp_session_table *sessions);

/* Algorithms implemented by the first DPDK software-IPsec backend. */
bool n3iwf_dp_child_sa_profile_supported(
    const struct n3iwf_dp_child_sa_wire *parameters);

#endif
