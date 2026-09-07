/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "n3iwf_dp_session.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint64_t
to_be64(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

static struct n3iwf_dp_session_wire
make_session(uint64_t ue_id, uint32_t session_id, uint32_t ul_teid,
             uint32_t dl_teid)
{
    struct n3iwf_dp_session_wire wire = {0};

    wire.ue_id = to_be64(ue_id);
    wire.pdu_session_id = htonl(session_id);
    wire.uplink_teid = htonl(ul_teid);
    wire.downlink_teid = htonl(dl_teid);
    wire.address_family = N3IWF_DP_AF_IPV4;
    wire.qfi_count = 1;
    wire.ue_pdu_address[0] = 10;
    wire.ue_pdu_address[3] = (uint8_t)ue_id;
    wire.ue_nwu_address[0] = 192;
    wire.ue_nwu_address[1] = 168;
    wire.ue_nwu_address[2] = 127;
    wire.ue_nwu_address[3] = (uint8_t)(ue_id + 1U);
    wire.qfi[0] = 5;
    return wire;
}

int
main(void)
{
    struct n3iwf_dp_session_table table;
    struct n3iwf_dp_session_wire first = make_session(1, 10, 100, 200);
    const struct n3iwf_dp_session *found;
    struct n3iwf_dp_session *mutable;
    const uint8_t first_mac[N3IWF_DP_ETHER_ADDR_LEN] =
        {0x02, 0, 0, 0, 0, 1};
    const uint8_t changed_mac[N3IWF_DP_ETHER_ADDR_LEN] =
        {0x02, 0, 0, 0, 0, 2};
    const uint8_t multicast_mac[N3IWF_DP_ETHER_ADDR_LEN] =
        {0x01, 0, 0, 0, 0, 1};

    n3iwf_dp_session_table_init(&table);
    assert(n3iwf_dp_session_upsert_wire(&table, &first, 1) ==
           N3IWF_DP_STATUS_OK);
    assert(table.count == 1);
    assert(table.entries[0].active_outbound_sa_index ==
           N3IWF_DP_INVALID_SA_INDEX);
    assert(n3iwf_dp_session_activate_outbound_sa(&table, 1, 10, 7, 10) ==
           N3IWF_DP_STATUS_OK);
    assert(table.entries[0].active_outbound_sa_index == 7 &&
           table.entries[0].active_outbound_sa_generation == 10);
    assert(n3iwf_dp_session_activate_outbound_sa(&table, 1, 10, 8, 9) ==
           N3IWF_DP_STATUS_STALE_GENERATION);
    assert(table.entries[0].active_outbound_sa_index == 7);
    assert(n3iwf_dp_session_activate_outbound_sa(&table, 2, 10, 8, 11) ==
           N3IWF_DP_STATUS_NOT_FOUND);

    found = n3iwf_dp_session_find_uplink(&table, N3IWF_DP_AF_IPV4,
                                         first.ue_nwu_address, 5);
    assert(found != NULL && found->uplink_teid == 100);
    assert(n3iwf_dp_session_find_uplink(&table, N3IWF_DP_AF_IPV4,
                                        first.ue_nwu_address, 7) == NULL);
    found = n3iwf_dp_session_find_downlink(&table, 200, 5);
    assert(found != NULL && found->ue_id == 1);
    mutable = n3iwf_dp_session_find_uplink_mutable(
        &table, N3IWF_DP_AF_IPV4, first.ue_nwu_address, 5);
    assert(mutable != NULL);
    assert(n3iwf_dp_session_learn_access_mac(mutable, multicast_mac) ==
           N3IWF_DP_MAC_INVALID);
    assert(n3iwf_dp_session_learn_access_mac(mutable, first_mac) ==
           N3IWF_DP_MAC_LEARNED);
    assert(n3iwf_dp_session_learn_access_mac(mutable, first_mac) ==
           N3IWF_DP_MAC_UNCHANGED);
    assert(n3iwf_dp_session_learn_access_mac(mutable, changed_mac) ==
           N3IWF_DP_MAC_CHANGED);
    assert(memcmp(mutable->ue_access_mac, changed_mac,
                  N3IWF_DP_ETHER_ADDR_LEN) == 0);

    assert(n3iwf_dp_session_upsert_wire(&table, &first, 1) ==
           N3IWF_DP_STATUS_STALE_GENERATION);
    first.downlink_teid = htonl(201);
    assert(n3iwf_dp_session_upsert_wire(&table, &first, 2) ==
           N3IWF_DP_STATUS_OK);
    found = n3iwf_dp_session_find_downlink(&table, 201, 5);
    assert(found != NULL && found->ue_access_mac_valid);
    assert(memcmp(found->ue_access_mac, changed_mac,
                  N3IWF_DP_ETHER_ADDR_LEN) == 0);
    assert(found->active_outbound_sa_index == 7 &&
           found->active_outbound_sa_generation == 10);
    assert(n3iwf_dp_session_find_downlink(&table, 200, 5) == NULL);
    assert(n3iwf_dp_session_find_downlink(&table, 201, 5) != NULL);

    assert(n3iwf_dp_session_delete(&table, 1, 10, 2) ==
           N3IWF_DP_STATUS_STALE_GENERATION);
    assert(n3iwf_dp_session_delete(&table, 1, 10, 3) ==
           N3IWF_DP_STATUS_OK);
    assert(table.count == 0);
    assert(n3iwf_dp_session_find_downlink(&table, 201, 5) == NULL);

    first.qfi[0] = 64;
    assert(n3iwf_dp_session_upsert_wire(&table, &first, 4) ==
           N3IWF_DP_STATUS_BAD_MESSAGE);

    first.qfi[0] = 5;
    first.qfi_count = 2;
    first.qfi[1] = 9;
    assert(n3iwf_dp_session_upsert_wire(&table, &first, 4) ==
           N3IWF_DP_STATUS_OK);
    assert(n3iwf_dp_session_find_downlink(&table, 201, 9) != NULL);
    assert(n3iwf_dp_session_activate_outbound_sa(&table, 1, 10, 8, 11) ==
           N3IWF_DP_STATUS_OK);
    n3iwf_dp_session_clear_outbound_sa(&table, 1, 10, 7);
    found = n3iwf_dp_session_find_downlink(&table, 201, 9);
    assert(found != NULL && found->active_outbound_sa_index == 8);
    n3iwf_dp_session_clear_outbound_sa(&table, 1, 10, 8);
    assert(found->active_outbound_sa_index == N3IWF_DP_INVALID_SA_INDEX &&
           found->active_outbound_sa_generation == 0);

    first.qfi_count = 1;
    first.address_family = N3IWF_DP_AF_IPV6;
    assert(n3iwf_dp_session_upsert_wire(&table, &first, 4) ==
           N3IWF_DP_STATUS_BAD_MESSAGE);

    /* Distinct UEs/sessions can reuse a QFI, but a live downlink TEID cannot
     * be reassigned across identities. */
    {
        struct n3iwf_dp_session_wire second =
            make_session(2, 20, 101, 202);
        uint64_t first_slot_generation = table.entries[0].slot_generation;

        assert(n3iwf_dp_session_upsert_wire(&table, &second, 1) ==
               N3IWF_DP_STATUS_OK);
        second.downlink_teid = htonl(201);
        assert(n3iwf_dp_session_upsert_wire(&table, &second, 2) ==
               N3IWF_DP_STATUS_BAD_MESSAGE);
        assert(n3iwf_dp_session_find_downlink(&table, 202, 5) != NULL);
        assert(n3iwf_dp_session_delete(&table, 1, 10, 5) ==
               N3IWF_DP_STATUS_OK);
        second.downlink_teid = htonl(201);
        assert(n3iwf_dp_session_upsert_wire(&table, &second, 2) ==
               N3IWF_DP_STATUS_OK);
        first = make_session(3, 30, 103, 203);
        assert(n3iwf_dp_session_upsert_wire(&table, &first, 1) ==
               N3IWF_DP_STATUS_OK);
        assert(table.entries[0].slot_generation != first_slot_generation);
    }

    puts("n3iwf_dp_session_test: PASS");
    return 0;
}
