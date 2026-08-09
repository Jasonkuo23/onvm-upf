/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef N3IWF_DP_SESSION_H
#define N3IWF_DP_SESSION_H

#include "n3iwf_dp_wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define N3IWF_DP_MAX_SESSIONS 4096U
#define N3IWF_DP_INDEX_SIZE 8192U
#define N3IWF_DP_INDEX_TOMBSTONE UINT32_MAX
#define N3IWF_DP_ETHER_ADDR_LEN 6U

enum n3iwf_dp_mac_learn_result {
    N3IWF_DP_MAC_INVALID = -1,
    N3IWF_DP_MAC_UNCHANGED = 0,
    N3IWF_DP_MAC_LEARNED = 1,
    N3IWF_DP_MAC_CHANGED = 2,
};

struct n3iwf_dp_session {
    bool used;
    uint64_t generation;
    uint64_t ue_id;
    uint32_t pdu_session_id;
    uint32_t uplink_teid;
    uint32_t downlink_teid;
    uint8_t address_family;
    uint8_t ue_pdu_address[N3IWF_DP_ADDR_LEN];
    uint8_t n3iwf_nwu_address[N3IWF_DP_ADDR_LEN];
    uint8_t ue_nwu_address[N3IWF_DP_ADDR_LEN];
    uint8_t n3iwf_n3_address[N3IWF_DP_ADDR_LEN];
    uint8_t upf_n3_address[N3IWF_DP_ADDR_LEN];
    uint64_t qfi_bitmap;
    bool ue_access_mac_valid;
    uint8_t ue_access_mac[N3IWF_DP_ETHER_ADDR_LEN];
};

struct n3iwf_dp_session_table {
    struct n3iwf_dp_session entries[N3IWF_DP_MAX_SESSIONS];
    uint32_t uplink_index[N3IWF_DP_INDEX_SIZE];
    uint32_t downlink_index[N3IWF_DP_INDEX_SIZE];
    size_t count;
};

void
n3iwf_dp_session_table_init(struct n3iwf_dp_session_table *table);

enum n3iwf_dp_status
n3iwf_dp_session_upsert_wire(struct n3iwf_dp_session_table *table,
                             const struct n3iwf_dp_session_wire *wire,
                             uint64_t generation);

enum n3iwf_dp_status
n3iwf_dp_session_delete(struct n3iwf_dp_session_table *table, uint64_t ue_id,
                        uint32_t pdu_session_id, uint64_t generation);

const struct n3iwf_dp_session *
n3iwf_dp_session_find_uplink(const struct n3iwf_dp_session_table *table,
                             uint8_t address_family,
                             const uint8_t ue_nwu_address[N3IWF_DP_ADDR_LEN],
                             uint8_t qfi);

struct n3iwf_dp_session *
n3iwf_dp_session_find_uplink_mutable(
    struct n3iwf_dp_session_table *table, uint8_t address_family,
    const uint8_t ue_nwu_address[N3IWF_DP_ADDR_LEN], uint8_t qfi);

enum n3iwf_dp_mac_learn_result
n3iwf_dp_session_learn_access_mac(
    struct n3iwf_dp_session *session,
    const uint8_t mac[N3IWF_DP_ETHER_ADDR_LEN]);

const struct n3iwf_dp_session *
n3iwf_dp_session_find_downlink(const struct n3iwf_dp_session_table *table,
                               uint32_t teid, uint8_t qfi);

#endif
