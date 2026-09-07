/* SPDX-License-Identifier: Apache-2.0 */
#include "n3iwf_dp_child_sa.h"
#include "n3iwf_dp_session.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint64_t to_be64(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

static struct n3iwf_dp_child_sa_wire make_sa(void)
{
    struct n3iwf_dp_child_sa_wire wire = {0};
    wire.ue_id = to_be64(0); /* First TS 38.413 RAN UE ID is valid. */
    wire.pdu_session_id = htonl(10);
    wire.inbound_spi = htonl(0x01020304);
    wire.outbound_spi = htonl(0x05060708);
    wire.encryption_id = htons(12); /* ENCR_AES_CBC */
    wire.integrity_id = htons(2);   /* AUTH_HMAC_SHA1_96 */
    wire.replay_window = htonl(64);
    wire.address_family = N3IWF_DP_AF_IPV4;
    wire.ip_protocol = 47; /* GRE */
    wire.inbound_encryption_key_len = 16;
    wire.outbound_encryption_key_len = 16;
    wire.inbound_integrity_key_len = 20;
    wire.outbound_integrity_key_len = 20;
    memset(wire.inbound_encryption_key, 0x11, 16);
    memset(wire.outbound_encryption_key, 0x22, 16);
    memset(wire.inbound_integrity_key, 0x33, 20);
    memset(wire.outbound_integrity_key, 0x44, 20);
    return wire;
}

static struct n3iwf_dp_session_wire
make_session(uint32_t pdu_session_id, uint32_t ul_teid, uint32_t dl_teid)
{
    struct n3iwf_dp_session_wire wire = {0};

    wire.ue_id = to_be64(0);
    wire.pdu_session_id = htonl(pdu_session_id);
    wire.uplink_teid = htonl(ul_teid);
    wire.downlink_teid = htonl(dl_teid);
    wire.address_family = N3IWF_DP_AF_IPV4;
    wire.qfi_count = 1;
    wire.ue_nwu_address[0] = 10;
    wire.ue_nwu_address[3] = 2;
    wire.qfi[0] = 9;
    return wire;
}

int main(void)
{
    struct n3iwf_dp_child_sa_table table;
    struct n3iwf_dp_session session = {
        .used = true,
        .ue_id = 0,
        .pdu_session_id = 10,
        .active_outbound_sa_index = N3IWF_DP_INVALID_SA_INDEX,
    };
    struct n3iwf_dp_child_sa_wire wire = make_sa();
    const struct n3iwf_dp_child_sa *found;
    uint32_t old_index;
    uint32_t new_index;

    n3iwf_dp_child_sa_table_init(&table);
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 1) ==
           N3IWF_DP_STATUS_OK);
    found = n3iwf_dp_child_sa_find_inbound(&table, 0x01020304);
    assert(found != NULL && found->generation == 1);
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 1) ==
           N3IWF_DP_STATUS_STALE_GENERATION);
    wire.outbound_encryption_key[0] = 0xaa;
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 2) ==
           N3IWF_DP_STATUS_OK);
    assert(n3iwf_dp_child_sa_delete(&table, 0, 10, 0x01020304, 2) ==
           N3IWF_DP_STATUS_STALE_GENERATION);
    assert(n3iwf_dp_child_sa_delete(&table, 1, 10, 0x01020304, 3) ==
           N3IWF_DP_STATUS_NOT_FOUND);
    assert(n3iwf_dp_child_sa_delete(&table, 0, 10, 0x01020304, 3) ==
           N3IWF_DP_STATUS_OK);
    assert(table.count == 0);

    /* Rekey overlap: retain the old inbound SPI for in-flight packets, but
     * switch downlink encryption to the newest installed SA immediately. */
    wire = make_sa();
    assert(n3iwf_dp_child_sa_upsert_wire_at(&table, &wire, 10, &old_index) ==
           N3IWF_DP_STATUS_OK);
    session.active_outbound_sa_index = old_index;
    session.active_outbound_sa_generation = 10;
    found = n3iwf_dp_child_sa_get_active_outbound(&table, &session, NULL);
    assert(found != NULL && found->generation == 10);
    wire.inbound_spi = htonl(0x11121314);
    wire.outbound_spi = htonl(0x15161718);
    memset(wire.inbound_encryption_key, 0x55, 16);
    memset(wire.outbound_encryption_key, 0x66, 16);
    assert(n3iwf_dp_child_sa_upsert_wire_at(&table, &wire, 11, &new_index) ==
           N3IWF_DP_STATUS_OK);
    assert(table.count == 2);
    assert(n3iwf_dp_child_sa_find_inbound(&table, 0x01020304) != NULL);
    assert(n3iwf_dp_child_sa_find_inbound(&table, 0x11121314) != NULL);
    found = n3iwf_dp_child_sa_find_latest_for_control(&table, 0, 10, NULL);
    assert(found != NULL && found->generation == 11 &&
           ntohl(found->parameters.inbound_spi) == 0x11121314);
    session.active_outbound_sa_index = new_index;
    session.active_outbound_sa_generation = 11;
    found = n3iwf_dp_child_sa_get_active_outbound(&table, &session, NULL);
    assert(found != NULL && found->generation == 11);

    /* A delayed upsert for either SPI is stale at the session level. */
    wire = make_sa();
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 9) ==
           N3IWF_DP_STATUS_STALE_GENERATION);
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 11) ==
           N3IWF_DP_STATUS_STALE_GENERATION);
    assert(n3iwf_dp_child_sa_delete(&table, 0, 10, 0x01020304, 11) ==
           N3IWF_DP_STATUS_STALE_GENERATION);

    /* Explicit retirement removes only the old SA.  The PDU session's new
     * SA remains selected and its keys/configuration generation is intact. */
    assert(n3iwf_dp_child_sa_delete(&table, 0, 10, 0x01020304, 12) ==
           N3IWF_DP_STATUS_OK);
    assert(table.count == 1);
    assert(n3iwf_dp_child_sa_find_inbound(&table, 0x01020304) == NULL);
    found = n3iwf_dp_child_sa_find_latest_for_control(&table, 0, 10, NULL);
    assert(found != NULL && found->generation == 11 &&
           found->session_generation == 12);
    found = n3iwf_dp_child_sa_get_active_outbound(&table, &session, NULL);
    assert(found != NULL && found->generation == 11);
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 12) ==
           N3IWF_DP_STATUS_STALE_GENERATION);
    assert(n3iwf_dp_child_sa_delete(&table, 0, 10, 0x11121314, 13) ==
           N3IWF_DP_STATUS_OK);
    assert(table.count == 0);
    assert(n3iwf_dp_child_sa_get_active_outbound(&table, &session, NULL) ==
           NULL);

    wire = make_sa();
    wire.inbound_encryption_key_len = 32;
    wire.outbound_encryption_key_len = 32;
    memset(wire.inbound_encryption_key, 0x55, 32);
    memset(wire.outbound_encryption_key, 0x66, 32);
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 4) ==
           N3IWF_DP_STATUS_OK);
    assert(n3iwf_dp_child_sa_delete(&table, 0, 10, 0x01020304, 5) ==
           N3IWF_DP_STATUS_OK);

    wire = make_sa();
    wire.inbound_encryption_key_len = 0;
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 6) ==
           N3IWF_DP_STATUS_BAD_MESSAGE);
    wire = make_sa();
    wire.inbound_encryption_key_len = 24; /* AES-192 is not in this profile. */
    wire.outbound_encryption_key_len = 24;
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 7) ==
           N3IWF_DP_STATUS_UNSUPPORTED);
    wire = make_sa();
    wire.inbound_encryption_key_len = 16;
    wire.outbound_encryption_key_len = 32; /* Directions must use one suite. */
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 8) ==
           N3IWF_DP_STATUS_UNSUPPORTED);
    wire = make_sa();
    wire.encryption_id = htons(13); /* ENCR_AES_CTR: not implemented yet. */
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 9) ==
           N3IWF_DP_STATUS_UNSUPPORTED);
    wire = make_sa();
    wire.flags = htonl(N3IWF_DP_CHILD_SA_NAT_T);
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 10) ==
           N3IWF_DP_STATUS_UNSUPPORTED);

    /* Session isolation: each session's stable slot resolves only to an SA
     * with the same UE/PDU identity. */
    wire = make_sa();
    assert(n3iwf_dp_child_sa_upsert_wire_at(&table, &wire, 20, &old_index) ==
           N3IWF_DP_STATUS_OK);
    wire.ue_id = to_be64(1);
    wire.pdu_session_id = htonl(20);
    wire.inbound_spi = htonl(0x21222324);
    wire.outbound_spi = htonl(0x25262728);
    assert(n3iwf_dp_child_sa_upsert_wire_at(&table, &wire, 1, &new_index) ==
           N3IWF_DP_STATUS_OK);
    session.active_outbound_sa_index = old_index;
    session.active_outbound_sa_generation = 20;
    {
        struct n3iwf_dp_session session_b = {
            .used = true,
            .ue_id = 1,
            .pdu_session_id = 20,
            .active_outbound_sa_index = new_index,
            .active_outbound_sa_generation = 1,
        };
        assert(n3iwf_dp_child_sa_get_active_outbound(
                   &table, &session, NULL) == &table.entries[old_index]);
        assert(n3iwf_dp_child_sa_get_active_outbound(
                   &table, &session_b, NULL) == &table.entries[new_index]);
        session_b.active_outbound_sa_index = old_index;
        assert(n3iwf_dp_child_sa_get_active_outbound(
                   &table, &session_b, NULL) == NULL);
    }
    n3iwf_dp_child_sa_table_clear(&table);

    /* One UE may reuse a QFI and NWu address across PDU sessions.  Inbound
     * SPI selects a Child SA whose stable session slot disambiguates them in
     * O(1).  A recycled session slot must not satisfy the old binding. */
    {
        struct n3iwf_dp_session_table sessions;
        struct n3iwf_dp_session_wire session_a =
            make_session(10, 100, 200);
        struct n3iwf_dp_session_wire session_b =
            make_session(20, 101, 201);
        const struct n3iwf_dp_child_sa *sa_a;
        const struct n3iwf_dp_child_sa *sa_b;
        const struct n3iwf_dp_session *bound;

        n3iwf_dp_session_table_init(&sessions);
        n3iwf_dp_child_sa_table_init(&table);
        assert(n3iwf_dp_session_upsert_wire(&sessions, &session_a, 1) ==
               N3IWF_DP_STATUS_OK);
        assert(n3iwf_dp_session_upsert_wire(&sessions, &session_b, 1) ==
               N3IWF_DP_STATUS_OK);
        wire = make_sa();
        assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 1) ==
               N3IWF_DP_STATUS_OK);
        wire.pdu_session_id = htonl(20);
        wire.inbound_spi = htonl(0x11121314);
        wire.outbound_spi = htonl(0x15161718);
        assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 1) ==
               N3IWF_DP_STATUS_OK);
        assert(n3iwf_dp_child_sa_bind_session_for_control(
                   &table, &sessions, 0, 10) == N3IWF_DP_STATUS_OK);
        assert(n3iwf_dp_child_sa_bind_session_for_control(
                   &table, &sessions, 0, 20) == N3IWF_DP_STATUS_OK);
        sa_a = n3iwf_dp_child_sa_find_inbound(&table, 0x01020304);
        sa_b = n3iwf_dp_child_sa_find_inbound(&table, 0x11121314);
        bound = n3iwf_dp_child_sa_get_bound_session(sa_a, &sessions);
        assert(bound != NULL && bound->pdu_session_id == 10 &&
               bound->uplink_teid == 100);
        bound = n3iwf_dp_child_sa_get_bound_session(sa_b, &sessions);
        assert(bound != NULL && bound->pdu_session_id == 20 &&
               bound->uplink_teid == 101);
        assert(n3iwf_dp_session_delete(&sessions, 0, 10, 2) ==
               N3IWF_DP_STATUS_OK);
        assert(n3iwf_dp_child_sa_get_bound_session(sa_a, &sessions) == NULL);
        session_a = make_session(30, 102, 202);
        assert(n3iwf_dp_session_upsert_wire(&sessions, &session_a, 1) ==
               N3IWF_DP_STATUS_OK);
        assert(n3iwf_dp_child_sa_get_bound_session(sa_a, &sessions) == NULL);
        bound = n3iwf_dp_child_sa_get_bound_session(sa_b, &sessions);
        assert(bound != NULL && bound->pdu_session_id == 20);
    }
    n3iwf_dp_child_sa_table_clear(&table);
    puts("n3iwf_dp_child_sa_test: PASS");
    return 0;
}
