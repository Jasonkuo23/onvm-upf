/* SPDX-License-Identifier: Apache-2.0 */
#include "n3iwf_dp_child_sa.h"

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

static int find_spi(const struct n3iwf_dp_child_sa_table *table,
                    uint32_t inbound_spi)
{
    size_t i;
    for (i = 0; i < N3IWF_DP_MAX_CHILD_SAS; ++i) {
        if (table->entries[i].used &&
            ntohl(table->entries[i].parameters.inbound_spi) == inbound_spi) {
            return (int)i;
        }
    }
    return -1;
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
    int entry;
    size_t i;
    uint32_t inbound_spi;

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
    inbound_spi = ntohl(wire->inbound_spi);
    if (inbound_spi == 0 || ntohl(wire->outbound_spi) == 0 ||
        (ntohl(wire->flags) & ~(N3IWF_DP_CHILD_SA_NAT_T |
                                N3IWF_DP_CHILD_SA_ESN)) != 0) {
        return N3IWF_DP_STATUS_BAD_MESSAGE;
    }

    entry = find_spi(table, inbound_spi);
    if (entry >= 0) {
        if (generation <= table->entries[entry].generation) {
            return N3IWF_DP_STATUS_STALE_GENERATION;
        }
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
    }
    table->entries[entry].used = true;
    table->entries[entry].generation = generation;
    memcpy(&table->entries[entry].parameters, wire, sizeof(*wire));
    return N3IWF_DP_STATUS_OK;
}

enum n3iwf_dp_status n3iwf_dp_child_sa_delete(
    struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id, uint32_t inbound_spi, uint64_t generation)
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
    if (generation <= sa->generation) {
        return N3IWF_DP_STATUS_STALE_GENERATION;
    }
    secure_zero(sa, sizeof(*sa));
    --table->count;
    return N3IWF_DP_STATUS_OK;
}

const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_find_inbound(
    const struct n3iwf_dp_child_sa_table *table, uint32_t inbound_spi)
{
    int entry;
    if (table == NULL || inbound_spi == 0) {
        return NULL;
    }
    entry = find_spi(table, inbound_spi);
    return entry < 0 ? NULL : &table->entries[entry];
}

const struct n3iwf_dp_child_sa *n3iwf_dp_child_sa_find_session(
    const struct n3iwf_dp_child_sa_table *table, uint64_t ue_id,
    uint32_t pdu_session_id)
{
    size_t i;
    if (table == NULL || pdu_session_id == 0) {
        return NULL;
    }
    for (i = 0; i < N3IWF_DP_MAX_CHILD_SAS; ++i) {
        const struct n3iwf_dp_child_sa *sa = &table->entries[i];
        if (sa->used && be64_to_host(sa->parameters.ue_id) == ue_id &&
            ntohl(sa->parameters.pdu_session_id) == pdu_session_id) {
            return sa;
        }
    }
    return NULL;
}
