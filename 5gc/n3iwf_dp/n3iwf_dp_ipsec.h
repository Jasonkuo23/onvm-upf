/* SPDX-License-Identifier: Apache-2.0 */
#ifndef N3IWF_DP_IPSEC_H
#define N3IWF_DP_IPSEC_H

#include "n3iwf_dp_child_sa.h"
#include "n3iwf_dp_session.h"
#include "n3iwf_dp_wire.h"

#include <stdbool.h>
#include <stdint.h>

#include <rte_cryptodev.h>
#include <rte_ipsec.h>
#include <rte_mbuf.h>

#include "onvm_common.h"

#define N3IWF_DP_ENCR_AES_CBC 12U
#define N3IWF_DP_AUTH_HMAC_SHA1_96 2U
#define N3IWF_DP_AES_CBC_IV_LEN 16U
#define N3IWF_DP_AES_CBC_128_KEY_LEN 16U
#define N3IWF_DP_AES_CBC_256_KEY_LEN 32U
#define N3IWF_DP_SHA1_KEY_LEN 20U
#define N3IWF_DP_SHA1_96_LEN 12U

struct n3iwf_dp_ipsec_sa {
    bool used;
    uint32_t inbound_spi;
    uint64_t generation;
    struct rte_crypto_sym_xform inbound_auth;
    struct rte_crypto_sym_xform inbound_cipher;
    struct rte_crypto_sym_xform outbound_cipher;
    struct rte_crypto_sym_xform outbound_auth;
    struct rte_cryptodev_sym_session *inbound_crypto;
    struct rte_cryptodev_sym_session *outbound_crypto;
    struct rte_ipsec_session inbound;
    struct rte_ipsec_session outbound;
    struct rte_ipsec_sa *inbound_sa;
    struct rte_ipsec_sa *outbound_sa;
};

struct n3iwf_dp_ipsec {
    bool ready;
    bool device_started;
    uint8_t device_id;
    struct rte_mempool *session_pool;
    uint64_t reconciled_child_sa_revision;
    struct n3iwf_dp_ipsec_sa sas[N3IWF_DP_MAX_CHILD_SAS];
};

int n3iwf_dp_ipsec_init(struct n3iwf_dp_ipsec *ipsec);
void n3iwf_dp_ipsec_close(struct n3iwf_dp_ipsec *ipsec);
void n3iwf_dp_ipsec_reconcile(
    struct n3iwf_dp_ipsec *ipsec,
    const struct n3iwf_dp_child_sa_table *child_sas);

int n3iwf_dp_handle_ipsec_packet(
    struct rte_mbuf *packet, struct onvm_pkt_meta *meta,
    struct n3iwf_dp_session_table *sessions,
    struct n3iwf_dp_child_sa_table *child_sas,
    struct n3iwf_dp_ipsec *ipsec, struct n3iwf_dp_stats_wire *stats,
    uint16_t upf_service_id, uint16_t access_port,
    const uint8_t access_mac[N3IWF_DP_ETHER_ADDR_LEN]);

#endif
