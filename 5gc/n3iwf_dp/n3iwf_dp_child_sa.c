/* SPDX-License-Identifier: Apache-2.0 */
#include "n3iwf_dp_child_sa.h"

#include "n3iwf_dp_session.h"

#include <arpa/inet.h>
#include <string.h>

static uint64_t be64_to_host(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

/* Prevent the compiler from optimizing secret erasure away. */
static void secure_zero(void *memory, size_t length)
{
    volatile uint8_t *byte = memory;
    while (length-- != 0) {
        *byte++ = 0;
    }
}

static bool valid_key_length(uint8_t length)
{
    return length > 0 && length <= N3IWF_DP_MAX_KEY_LEN;
}

static bool supported_aes_cbc_key_length(uint8_t length)
{
    return length == 16 || length == 32;
}

bool n3iwf_dp_child_sa_profile_supported(
    const struct n3iwf_dp_child_sa_wire *parameters)
{
    if (parameters == NULL) {
        return false;
    }
    /* IKEv2 transform 12 is AES-CBC and transform 2 is
     * AUTH_HMAC_SHA1_96. NAT-T, ESN and IPv6 transport are enabled only
     * after their packet paths and negative tests are implemented. */
    return parameters->address_family == N3IWF_DP_AF_IPV4 &&
           parameters->ip_protocol == 47 &&
           ntohs(parameters->encryption_id) == 12 &&
           ntohs(parameters->integrity_id) == 2 &&
           supported_aes_cbc_key_length(
               parameters->inbound_encryption_key_len) &&
           supported_aes_cbc_key_length(
               parameters->outbound_encryption_key_len) &&
           parameters->inbound_encryption_key_len ==
               parameters->outbound_encryption_key_len &&
           parameters->inbound_integrity_key_len == 20 &&
           parameters->outbound_integrity_key_len == 20 &&
           (ntohl(parameters->flags) &
            (N3IWF_DP_CHILD_SA_NAT_T | N3IWF_DP_CHILD_SA_ESN)) == 0;
}

static uint32_t hash_spi(uint32_t spi)
{
    spi ^= spi >> 16;
    spi *= 0x7feb352dU;
    spi ^= spi >> 15;
    return spi;
}

static int find_spi(const struct n3iwf_dp_child_sa_table *table,
                    uint32_t inbound_spi)
{
    uint32_t hash = hash_spi(inbound_spi);
    size_t probe;

    for (probe = 0; probe < N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE; ++probe) {
        size_t slot = (hash + probe) &
                      (N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE - 1U);
        uint32_t value = table->inbound_spi_index[slot];
        const struct n3iwf_dp_child_sa *sa;

        if (value == 0) {
            return -1;
        }
        if (value == N3IWF_DP_CHILD_SA_INDEX_TOMBSTONE) {
            continue;
        }
        sa = &table->entries[value - 1U];
        if (sa->used &&
            ntohl(sa->parameters.inbound_spi) == inbound_spi) {
            return (int)(value - 1U);
        }
    }
    return -1;
}

static bool spi_index_insert(struct n3iwf_dp_child_sa_table *table,
                             uint32_t inbound_spi, uint32_t entry_index)
{
    uint32_t hash = hash_spi(inbound_spi);
    size_t probe;
    size_t tombstone = N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE;

    for (probe = 0; probe < N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE; ++probe) {
        size_t slot = (hash + probe) &
                      (N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE - 1U);
        if (table->inbound_spi_index[slot] ==
                N3IWF_DP_CHILD_SA_INDEX_TOMBSTONE &&
            tombstone == N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE) {
            tombstone = slot;
        } else if (table->inbound_spi_index[slot] == 0) {
            if (tombstone != N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE) {
                slot = tombstone;
            }
            table->inbound_spi_index[slot] = entry_index + 1U;
            return true;
        }
    }
    if (tombstone != N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE) {
        table->inbound_spi_index[tombstone] = entry_index + 1U;
        return true;
    }
    return false;
}

static void spi_index_remove(struct n3iwf_dp_child_sa_table *table,
                             uint32_t inbound_spi, uint32_t entry_index)
{
    uint32_t hash = hash_spi(inbound_spi);
    size_t probe;

    for (probe = 0; probe < N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE; ++probe) {
        size_t slot = (hash + probe) &
                      (N3IWF_DP_CHILD_SA_SPI_INDEX_SIZE - 1U);
        uint32_t value = table->inbound_spi_index[slot];
        if (value == 0) {
            return;
        }
        if (value == entry_index + 1U) {
            table->inbound_spi_index[slot] =
                N3IWF_DP_CHILD_SA_INDEX_TOMBSTONE;
            return;
        }
    }
}

static bool same_session(const struct n3iwf_dp_child_sa *sa, uint64_t ue_id,
                         uint32_t pdu_session_id)
{
    return sa->used && be64_to_host(sa->parameters.ue_id) == ue_id &&
           ntohl(sa->parameters.pdu_session_id) == pdu_session_id;
}

static uint64_t session_generation(
    const struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id)
{
    uint64_t latest = 0;
    size_t i;

    for (i = 0; i < N3IWF_DP_MAX_CHILD_SAS; ++i) {
        if (same_session(&table->entries[i], ue_id, pdu_session_id) &&
            table->entries[i].session_generation > latest) {
            latest = table->entries[i].session_generation;
        }
    }
    return latest;
}

static void advance_session_generation(
    struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id, uint64_t generation)
{
    size_t i;

    for (i = 0; i < N3IWF_DP_MAX_CHILD_SAS; ++i) {
        if (same_session(&table->entries[i], ue_id, pdu_session_id)) {
            table->entries[i].session_generation = generation;
        }
    }
}

void n3iwf_dp_child_sa_table_init(struct n3iwf_dp_child_sa_table *table)
{
    if (table != NULL) {
        memset(table, 0, sizeof(*table));
    }
}

void n3iwf_dp_child_sa_table_clear(struct n3iwf_dp_child_sa_table *table)
{
    if (table != NULL) {
        secure_zero(table, sizeof(*table));
    }
}

enum n3iwf_dp_status n3iwf_dp_child_sa_upsert_wire(
    struct n3iwf_dp_child_sa_table *table,
    const struct n3iwf_dp_child_sa_wire *wire, uint64_t generation)
{
    return n3iwf_dp_child_sa_upsert_wire_at(table, wire, generation, NULL);
}

enum n3iwf_dp_status n3iwf_dp_child_sa_upsert_wire_at(
    struct n3iwf_dp_child_sa_table *table,
    const struct n3iwf_dp_child_sa_wire *wire, uint64_t generation,
    uint32_t *sa_index)
{
    int entry;
    size_t i;
    uint32_t inbound_spi;
    uint64_t ue_id;
    uint32_t pdu_session_id;
    bool new_entry = false;

    if (table == NULL || wire == NULL || generation == 0 ||
        (wire->address_family != N3IWF_DP_AF_IPV4 &&
         wire->address_family != N3IWF_DP_AF_IPV6) ||
        wire->ip_protocol == 0 || ntohs(wire->encryption_id) == 0 ||
        ntohl(wire->replay_window) == 0 ||
        !valid_key_length(wire->inbound_encryption_key_len) ||
        !valid_key_length(wire->outbound_encryption_key_len) ||
        wire->inbound_integrity_key_len > N3IWF_DP_MAX_KEY_LEN ||
        wire->outbound_integrity_key_len > N3IWF_DP_MAX_KEY_LEN ||
        (ntohs(wire->integrity_id) == 0 &&
         (wire->inbound_integrity_key_len != 0 ||
          wire->outbound_integrity_key_len != 0)) ||
        (ntohs(wire->integrity_id) != 0 &&
         (!valid_key_length(wire->inbound_integrity_key_len) ||
          !valid_key_length(wire->outbound_integrity_key_len)))) {
        return N3IWF_DP_STATUS_BAD_MESSAGE;
    }
    if (!n3iwf_dp_child_sa_profile_supported(wire)) {
        return N3IWF_DP_STATUS_UNSUPPORTED;
    }
    inbound_spi = ntohl(wire->inbound_spi);
    ue_id = be64_to_host(wire->ue_id);
    pdu_session_id = ntohl(wire->pdu_session_id);
    if (inbound_spi == 0 || ntohl(wire->outbound_spi) == 0 ||
        pdu_session_id == 0 ||
        (ntohl(wire->flags) & ~(N3IWF_DP_CHILD_SA_NAT_T |
                                N3IWF_DP_CHILD_SA_ESN)) != 0) {
        return N3IWF_DP_STATUS_BAD_MESSAGE;
    }

    entry = find_spi(table, inbound_spi);
    if (entry >= 0) {
        if (!same_session(&table->entries[entry], ue_id, pdu_session_id)) {
            /* An inbound SPI identifies one SA globally.  Never allow a
             * higher generation from another UE to take it over. */
            return N3IWF_DP_STATUS_BAD_MESSAGE;
        }
    }
    if (generation <= session_generation(table, ue_id, pdu_session_id)) {
        return N3IWF_DP_STATUS_STALE_GENERATION;
    }
    if (entry >= 0) {
        secure_zero(&table->entries[entry].parameters,
                    sizeof(table->entries[entry].parameters));
    } else {
        for (i = 0; i < N3IWF_DP_MAX_CHILD_SAS; ++i) {
            if (!table->entries[i].used) {
                entry = (int)i;
                break;
            }
        }
        if (entry < 0) {
            return N3IWF_DP_STATUS_CAPACITY;
        }
        ++table->count;
        new_entry = true;
    }
    table->entries[entry].used = true;
    table->entries[entry].generation = generation;
    table->entries[entry].session_generation = generation;
    table->entries[entry].session_index = N3IWF_DP_INVALID_SESSION_INDEX;
    memcpy(&table->entries[entry].parameters, wire, sizeof(*wire));
    if (find_spi(table, inbound_spi) < 0 &&
        !spi_index_insert(table, inbound_spi, (uint32_t)entry)) {
        secure_zero(&table->entries[entry], sizeof(table->entries[entry]));
        if (new_entry) {
            --table->count;
        }
        return N3IWF_DP_STATUS_CAPACITY;
    }
    advance_session_generation(table, ue_id, pdu_session_id, generation);
    ++table->revision;
    if (sa_index != NULL) {
        *sa_index = (uint32_t)entry;
    }
    return N3IWF_DP_STATUS_OK;
}

enum n3iwf_dp_status n3iwf_dp_child_sa_delete(
    struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id, uint32_t inbound_spi, uint64_t generation)
{
    return n3iwf_dp_child_sa_delete_at(table, ue_id, pdu_session_id,
                                       inbound_spi, generation, NULL);
}

enum n3iwf_dp_status n3iwf_dp_child_sa_delete_at(
    struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id, uint32_t inbound_spi, uint64_t generation,
    uint32_t *sa_index)
{
    int entry;
    struct n3iwf_dp_child_sa *sa;

    if (table == NULL || generation == 0 || inbound_spi == 0) {
        return N3IWF_DP_STATUS_BAD_MESSAGE;
    }
    entry = find_spi(table, inbound_spi);
    if (entry < 0) {
        return N3IWF_DP_STATUS_NOT_FOUND;
    }
    sa = &table->entries[entry];
    if (be64_to_host(sa->parameters.ue_id) != ue_id ||
        ntohl(sa->parameters.pdu_session_id) != pdu_session_id) {
        return N3IWF_DP_STATUS_NOT_FOUND;
    }
    if (generation <= session_generation(table, ue_id, pdu_session_id)) {
        return N3IWF_DP_STATUS_STALE_GENERATION;
    }
    spi_index_remove(table, inbound_spi, (uint32_t)entry);
    secure_zero(sa, sizeof(*sa));
    --table->count;
    /* Surviving overlap SAs retain their own installation generation for
     * runtime crypto-cache reconciliation, while sharing the newer command
     * watermark used for stale-update rejection. */
    advance_session_generation(table, ue_id, pdu_session_id, generation);
    ++table->revision;
    if (sa_index != NULL) {
        *sa_index = (uint32_t)entry;
    }
    return N3IWF_DP_STATUS_OK;
}

const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_find_inbound(
    const struct n3iwf_dp_child_sa_table *table, uint32_t inbound_spi)
{
    return n3iwf_dp_child_sa_find_inbound_at(table, inbound_spi, NULL);
}

const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_find_inbound_at(
    const struct n3iwf_dp_child_sa_table *table, uint32_t inbound_spi,
    uint32_t *sa_index)
{
    int entry;
    if (table == NULL || inbound_spi == 0) {
        return NULL;
    }
    entry = find_spi(table, inbound_spi);
    if (entry < 0) {
        return NULL;
    }
    if (sa_index != NULL) {
        *sa_index = (uint32_t)entry;
    }
    return &table->entries[entry];
}

const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_find_latest_for_control(
    const struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id, uint32_t *sa_index)
{
    size_t i;
    const struct n3iwf_dp_child_sa *latest = NULL;

    if (table == NULL || pdu_session_id == 0) {
        return NULL;
    }
    for (i = 0; i < N3IWF_DP_MAX_CHILD_SAS; ++i) {
        const struct n3iwf_dp_child_sa *sa = &table->entries[i];
        if (same_session(sa, ue_id, pdu_session_id) &&
            (latest == NULL || sa->generation > latest->generation)) {
            latest = sa;
            if (sa_index != NULL) {
                *sa_index = (uint32_t)i;
            }
        }
    }
    return latest;
}


const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_get_active_outbound(
    const struct n3iwf_dp_child_sa_table *table,
    const struct n3iwf_dp_session *session, uint32_t *sa_index)
{
    const struct n3iwf_dp_child_sa *sa;
    uint32_t index;

    if (table == NULL || session == NULL || !session->used) {
        return NULL;
    }
    index = session->active_outbound_sa_index;
    if (index >= N3IWF_DP_MAX_CHILD_SAS) {
        return NULL;
    }
    sa = &table->entries[index];
    if (!same_session(sa, session->ue_id, session->pdu_session_id) ||
        sa->generation != session->active_outbound_sa_generation) {
        return NULL;
    }
    if (sa_index != NULL) {
        *sa_index = index;
    }
    return sa;
}

enum n3iwf_dp_status
n3iwf_dp_child_sa_bind_session_for_control(
    struct n3iwf_dp_child_sa_table *table,
    const struct n3iwf_dp_session_table *sessions, uint64_t ue_id,
    uint32_t pdu_session_id)
{
    const struct n3iwf_dp_session *session;
    uint32_t session_index;
    size_t index;

    if (table == NULL || sessions == NULL || pdu_session_id == 0) {
        return N3IWF_DP_STATUS_BAD_MESSAGE;
    }
    session = n3iwf_dp_session_find_identity_for_control(
        sessions, ue_id, pdu_session_id, &session_index);
    if (session == NULL) {
        return N3IWF_DP_STATUS_NOT_FOUND;
    }
    for (index = 0; index < N3IWF_DP_MAX_CHILD_SAS; ++index) {
        struct n3iwf_dp_child_sa *sa = &table->entries[index];

        if (same_session(sa, ue_id, pdu_session_id)) {
            sa->session_index = session_index;
            sa->session_slot_generation = session->slot_generation;
        }
    }
    return N3IWF_DP_STATUS_OK;
}

struct n3iwf_dp_session *
n3iwf_dp_child_sa_get_bound_session(
    const struct n3iwf_dp_child_sa *sa,
    struct n3iwf_dp_session_table *sessions)
{
    struct n3iwf_dp_session *session;

    if (sa == NULL || !sa->used || sessions == NULL ||
        sa->session_index >= N3IWF_DP_MAX_SESSIONS ||
        sa->session_slot_generation == 0) {
        return NULL;
    }
    session = &sessions->entries[sa->session_index];
    if (!session->used ||
        session->slot_generation != sa->session_slot_generation ||
        session->ue_id != be64_to_host(sa->parameters.ue_id) ||
        session->pdu_session_id != ntohl(sa->parameters.pdu_session_id)) {
        return NULL;
    }
    return session;
}
