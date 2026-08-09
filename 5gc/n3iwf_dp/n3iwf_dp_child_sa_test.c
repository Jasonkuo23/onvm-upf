/* SPDX-License-Identifier: Apache-2.0 */
#include "n3iwf_dp_child_sa.h"

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

int main(void)
{
    struct n3iwf_dp_child_sa_table table;
    struct n3iwf_dp_child_sa_wire wire = make_sa();
    const struct n3iwf_dp_child_sa *found;

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

    wire = make_sa();
    wire.inbound_encryption_key_len = 0;
    assert(n3iwf_dp_child_sa_upsert_wire(&table, &wire, 4) ==
           N3IWF_DP_STATUS_BAD_MESSAGE);
    n3iwf_dp_child_sa_table_clear(&table);
    puts("n3iwf_dp_child_sa_test: PASS");
    return 0;
}
