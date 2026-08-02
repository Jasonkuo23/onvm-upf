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

    n3iwf_dp_session_table_init(&table);
    assert(n3iwf_dp_session_upsert_wire(&table, &first, 1) ==
           N3IWF_DP_STATUS_OK);
    assert(table.count == 1);

    found = n3iwf_dp_session_find_uplink(&table, N3IWF_DP_AF_IPV4,
                                         first.ue_nwu_address, 5);
    assert(found != NULL && found->uplink_teid == 100);
    assert(n3iwf_dp_session_find_uplink(&table, N3IWF_DP_AF_IPV4,
                                        first.ue_nwu_address, 7) == NULL);
    found = n3iwf_dp_session_find_downlink(&table, 200, 5);
    assert(found != NULL && found->ue_id == 1);

    assert(n3iwf_dp_session_upsert_wire(&table, &first, 1) ==
           N3IWF_DP_STATUS_STALE_GENERATION);
    first.downlink_teid = htonl(201);
    assert(n3iwf_dp_session_upsert_wire(&table, &first, 2) ==
           N3IWF_DP_STATUS_OK);
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
    assert(n3iwf_dp_session_upsert_wire(&table, &first, 4) ==
           N3IWF_DP_STATUS_BAD_MESSAGE);

    first.qfi_count = 1;
    first.address_family = N3IWF_DP_AF_IPV6;
    assert(n3iwf_dp_session_upsert_wire(&table, &first, 4) ==
           N3IWF_DP_STATUS_BAD_MESSAGE);

    puts("n3iwf_dp_session_test: PASS");
    return 0;
}
