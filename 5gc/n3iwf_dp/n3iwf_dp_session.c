/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_session.h"

#include <arpa/inet.h>
#include <string.h>

static uint64_t
be64_to_host(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

static size_t
address_len(uint8_t address_family)
{
    return address_family == N3IWF_DP_AF_IPV4 ? 4U : 16U;
}

static uint32_t
hash_bytes(const uint8_t *data, size_t length)
{
    uint32_t hash = 2166136261U;
    size_t i;

    for (i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= 16777619U;
    }
    return hash;
}

static uint32_t
hash_teid(uint32_t teid)
{
    teid ^= teid >> 16;
    teid *= 0x7feb352dU;
    teid ^= teid >> 15;
    return teid;
}

static void
index_remove(uint32_t *index, uint32_t entry_index)
{
    size_t i;

    for (i = 0; i < N3IWF_DP_INDEX_SIZE; ++i) {
        if (index[i] == entry_index + 1U) {
            index[i] = N3IWF_DP_INDEX_TOMBSTONE;
            return;
        }
    }
}

static bool
index_insert(uint32_t *index, uint32_t hash, uint32_t entry_index)
{
    size_t probe;
    size_t first_tombstone = N3IWF_DP_INDEX_SIZE;

    for (probe = 0; probe < N3IWF_DP_INDEX_SIZE; ++probe) {
        size_t slot = (hash + probe) & (N3IWF_DP_INDEX_SIZE - 1U);

        if (index[slot] == N3IWF_DP_INDEX_TOMBSTONE &&
            first_tombstone == N3IWF_DP_INDEX_SIZE) {
            first_tombstone = slot;
        } else if (index[slot] == 0) {
            if (first_tombstone != N3IWF_DP_INDEX_SIZE) {
                slot = first_tombstone;
            }
            index[slot] = entry_index + 1U;
            return true;
        }
    }
    if (first_tombstone != N3IWF_DP_INDEX_SIZE) {
        index[first_tombstone] = entry_index + 1U;
        return true;
    }
    return false;
}

static int
find_identity(const struct n3iwf_dp_session_table *table, uint64_t ue_id,
              uint32_t pdu_session_id)
{
    size_t i;

    for (i = 0; i < N3IWF_DP_MAX_SESSIONS; ++i) {
        if (table->entries[i].used && table->entries[i].ue_id == ue_id &&
            table->entries[i].pdu_session_id == pdu_session_id) {
            return (int)i;
        }
    }
    return -1;
}

static bool
qfi_allowed(const struct n3iwf_dp_session *session, uint8_t qfi)
{
    return qfi > 0 && qfi <= N3IWF_DP_MAX_QFI &&
           (session->qfi_bitmap & (UINT64_C(1) << qfi)) != 0;
}

void
n3iwf_dp_session_table_init(struct n3iwf_dp_session_table *table)
{
    if (table != NULL) {
        memset(table, 0, sizeof(*table));
    }
}

enum n3iwf_dp_status
n3iwf_dp_session_upsert_wire(struct n3iwf_dp_session_table *table,
                             const struct n3iwf_dp_session_wire *wire,
                             uint64_t generation)
{
    struct n3iwf_dp_session candidate = {0};
    uint64_t ue_id;
    uint32_t pdu_session_id;
    int existing;
    int free_entry = -1;
    size_t i;

    /*
     * Wire v1 deliberately exposes only the dataplane slice that is complete:
     * IPv4 and one active QoS flow per PDU session.  The fixed-size wire
     * fields remain forward-compatible with IPv6/multi-QFI, but accepting
     * them before lookup and packet processing support is complete would turn
     * a control-plane ACK into a false promise.
     */
    if (table == NULL || wire == NULL || generation == 0 ||
        wire->address_family != N3IWF_DP_AF_IPV4 || wire->qfi_count != 1) {
        return N3IWF_DP_STATUS_BAD_MESSAGE;
    }

    ue_id = be64_to_host(wire->ue_id);
    pdu_session_id = ntohl(wire->pdu_session_id);
    candidate.used = true;
    candidate.generation = generation;
    candidate.ue_id = ue_id;
    candidate.pdu_session_id = pdu_session_id;
    candidate.uplink_teid = ntohl(wire->uplink_teid);
    candidate.downlink_teid = ntohl(wire->downlink_teid);
    candidate.address_family = wire->address_family;
    if (candidate.uplink_teid == 0 || candidate.downlink_teid == 0) {
        return N3IWF_DP_STATUS_BAD_MESSAGE;
    }

    memcpy(candidate.ue_pdu_address, wire->ue_pdu_address,
           sizeof(candidate.ue_pdu_address));
    memcpy(candidate.n3iwf_nwu_address, wire->n3iwf_nwu_address,
           sizeof(candidate.n3iwf_nwu_address));
    memcpy(candidate.ue_nwu_address, wire->ue_nwu_address,
           sizeof(candidate.ue_nwu_address));
    memcpy(candidate.n3iwf_n3_address, wire->n3iwf_n3_address,
           sizeof(candidate.n3iwf_n3_address));
    memcpy(candidate.upf_n3_address, wire->upf_n3_address,
           sizeof(candidate.upf_n3_address));

    for (i = 0; i < wire->qfi_count; ++i) {
        uint8_t qfi = wire->qfi[i];
        if (qfi == 0 || qfi > N3IWF_DP_MAX_QFI ||
            (candidate.qfi_bitmap & (UINT64_C(1) << qfi)) != 0) {
            return N3IWF_DP_STATUS_BAD_MESSAGE;
        }
        candidate.qfi_bitmap |= UINT64_C(1) << qfi;
    }

    existing = find_identity(table, ue_id, pdu_session_id);
    if (existing >= 0 && generation <= table->entries[existing].generation) {
        return N3IWF_DP_STATUS_STALE_GENERATION;
    }
    if (existing < 0) {
        for (i = 0; i < N3IWF_DP_MAX_SESSIONS; ++i) {
            if (!table->entries[i].used) {
                free_entry = (int)i;
                break;
            }
        }
        if (free_entry < 0) {
            return N3IWF_DP_STATUS_CAPACITY;
        }
        existing = free_entry;
    } else {
        index_remove(table->uplink_index, (uint32_t)existing);
        index_remove(table->downlink_index, (uint32_t)existing);
    }

    table->entries[existing] = candidate;
    if (!index_insert(table->uplink_index,
                      hash_bytes(candidate.ue_nwu_address,
                                 address_len(candidate.address_family)),
                      (uint32_t)existing) ||
        !index_insert(table->downlink_index, hash_teid(candidate.downlink_teid),
                      (uint32_t)existing)) {
        table->entries[existing].used = false;
        index_remove(table->uplink_index, (uint32_t)existing);
        index_remove(table->downlink_index, (uint32_t)existing);
        return N3IWF_DP_STATUS_CAPACITY;
    }
    if (free_entry >= 0) {
        ++table->count;
    }
    return N3IWF_DP_STATUS_OK;
}

enum n3iwf_dp_status
n3iwf_dp_session_delete(struct n3iwf_dp_session_table *table, uint64_t ue_id,
                        uint32_t pdu_session_id, uint64_t generation)
{
    int entry;

    if (table == NULL || generation == 0) {
        return N3IWF_DP_STATUS_BAD_MESSAGE;
    }
    entry = find_identity(table, ue_id, pdu_session_id);
    if (entry < 0) {
        return N3IWF_DP_STATUS_NOT_FOUND;
    }
    if (generation <= table->entries[entry].generation) {
        return N3IWF_DP_STATUS_STALE_GENERATION;
    }
    index_remove(table->uplink_index, (uint32_t)entry);
    index_remove(table->downlink_index, (uint32_t)entry);
    memset(&table->entries[entry], 0, sizeof(table->entries[entry]));
    --table->count;
    return N3IWF_DP_STATUS_OK;
}

const struct n3iwf_dp_session *
n3iwf_dp_session_find_uplink(const struct n3iwf_dp_session_table *table,
                             uint8_t family,
                             const uint8_t address[N3IWF_DP_ADDR_LEN],
                             uint8_t qfi)
{
    uint32_t hash;
    size_t probe;
    size_t length;

    if (table == NULL || address == NULL ||
        (family != N3IWF_DP_AF_IPV4 && family != N3IWF_DP_AF_IPV6)) {
        return NULL;
    }
    length = address_len(family);
    hash = hash_bytes(address, length);
    for (probe = 0; probe < N3IWF_DP_INDEX_SIZE; ++probe) {
        size_t slot = (hash + probe) & (N3IWF_DP_INDEX_SIZE - 1U);
        uint32_t value = table->uplink_index[slot];
        const struct n3iwf_dp_session *session;

        if (value == 0) {
            return NULL;
        }
        if (value == N3IWF_DP_INDEX_TOMBSTONE) {
            continue;
        }
        session = &table->entries[value - 1U];
        if (session->used && session->address_family == family &&
            memcmp(session->ue_nwu_address, address, length) == 0 &&
            qfi_allowed(session, qfi)) {
            return session;
        }
    }
    return NULL;
}

const struct n3iwf_dp_session *
n3iwf_dp_session_find_downlink(const struct n3iwf_dp_session_table *table,
                               uint32_t teid, uint8_t qfi)
{
    uint32_t hash;
    size_t probe;

    if (table == NULL || teid == 0) {
        return NULL;
    }
    hash = hash_teid(teid);
    for (probe = 0; probe < N3IWF_DP_INDEX_SIZE; ++probe) {
        size_t slot = (hash + probe) & (N3IWF_DP_INDEX_SIZE - 1U);
        uint32_t value = table->downlink_index[slot];
        const struct n3iwf_dp_session *session;

        if (value == 0) {
            return NULL;
        }
        if (value == N3IWF_DP_INDEX_TOMBSTONE) {
            continue;
        }
        session = &table->entries[value - 1U];
        if (session->used && session->downlink_teid == teid &&
            qfi_allowed(session, qfi)) {
            return session;
        }
    }
    return NULL;
}
