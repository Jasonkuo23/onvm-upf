/* SPDX-License-Identifier: Apache-2.0 */
#include "n3iwf_dp_ipsec.h"

#include "n3iwf_dp_clear.h"
#include "n3iwf_dp_downlink.h"
#include "n3iwf_dp_mtu.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <rte_byteorder.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_ether.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_ipsec.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_security.h>

#define IPSEC_SESSION_POOL_SIZE (2U * N3IWF_DP_MAX_CHILD_SAS)
#define IPSEC_SESSION_CACHE_SIZE 64U
#define IPSEC_QUEUE_DESCRIPTORS 1024U
#define ESP_HEADER_LEN 8U
#define IPSEC_IV_OFFSET \
    (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op) + \
     2U * sizeof(struct rte_crypto_sym_xform))

_Static_assert(ESP_HEADER_LEN == N3IWF_DP_ESP_HEADER_LEN,
               "MTU profile ESP header length must match IPsec");
_Static_assert(N3IWF_DP_AES_CBC_IV_LEN ==
                   N3IWF_DP_AES_CBC_IV_LEN_BYTES,
               "MTU profile IV length must match IPsec");
_Static_assert(N3IWF_DP_SHA1_96_LEN == N3IWF_DP_SHA1_96_ICV_LEN,
               "MTU profile ICV length must match IPsec");

static uint64_t be64_to_host(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

static bool
device_supports_profile(uint8_t device_id)
{
    struct rte_cryptodev_info info;
    struct rte_cryptodev_sym_capability_idx cipher_index = {
        .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
        .algo.cipher = RTE_CRYPTO_CIPHER_AES_CBC,
    };
    struct rte_cryptodev_sym_capability_idx auth_index = {
        .type = RTE_CRYPTO_SYM_XFORM_AUTH,
        .algo.auth = RTE_CRYPTO_AUTH_SHA1_HMAC,
    };
    const struct rte_cryptodev_symmetric_capability *cipher;
    const struct rte_cryptodev_symmetric_capability *auth;

    rte_cryptodev_info_get(device_id, &info);
    if ((info.feature_flags & RTE_CRYPTODEV_FF_SYM_CPU_CRYPTO) == 0) {
        return false;
    }
    cipher = rte_cryptodev_sym_capability_get(device_id, &cipher_index);
    auth = rte_cryptodev_sym_capability_get(device_id, &auth_index);
    return cipher != NULL && auth != NULL &&
           rte_cryptodev_sym_capability_check_cipher(
               cipher, N3IWF_DP_AES_CBC_128_KEY_LEN,
               N3IWF_DP_AES_CBC_IV_LEN) == 0 &&
           rte_cryptodev_sym_capability_check_cipher(
               cipher, N3IWF_DP_AES_CBC_256_KEY_LEN,
               N3IWF_DP_AES_CBC_IV_LEN) == 0 &&
           rte_cryptodev_sym_capability_check_auth(
               auth, N3IWF_DP_SHA1_KEY_LEN, N3IWF_DP_SHA1_96_LEN, 0) == 0;
}

int
n3iwf_dp_ipsec_init(struct n3iwf_dp_ipsec *ipsec)
{
    struct rte_cryptodev_config config = {0};
    struct rte_cryptodev_qp_conf queue_config = {0};
    uint8_t count;
    uint8_t device_id;
    uint32_t private_size;
    char pool_name[RTE_MEMPOOL_NAMESIZE];

    if (ipsec == NULL) {
        return -EINVAL;
    }
    memset(ipsec, 0, sizeof(*ipsec));
    count = rte_cryptodev_count();
    for (device_id = 0; device_id < count; ++device_id) {
        if (rte_cryptodev_is_valid_dev(device_id) &&
            device_supports_profile(device_id)) {
            break;
        }
    }
    if (device_id == count) {
        return -ENODEV;
    }
    private_size = rte_cryptodev_sym_get_private_session_size(device_id);
    snprintf(pool_name, sizeof(pool_name), "n3iwf_ipsec_sess_%u",
             (unsigned int)getpid());
    ipsec->session_pool = rte_cryptodev_sym_session_pool_create(
        pool_name, IPSEC_SESSION_POOL_SIZE, private_size,
        IPSEC_SESSION_CACHE_SIZE, 0, rte_socket_id());
    if (ipsec->session_pool == NULL) {
        return -ENOMEM;
    }
    ipsec->device_id = device_id;
    config.socket_id = rte_socket_id();
    config.nb_queue_pairs = 1;
    if (rte_cryptodev_configure(device_id, &config) != 0) {
        rte_mempool_free(ipsec->session_pool);
        ipsec->session_pool = NULL;
        return -ENODEV;
    }
    queue_config.nb_descriptors = IPSEC_QUEUE_DESCRIPTORS;
    queue_config.mp_session = ipsec->session_pool;
    if (rte_cryptodev_queue_pair_setup(
            device_id, 0, &queue_config, rte_socket_id()) != 0) {
        rte_mempool_free(ipsec->session_pool);
        ipsec->session_pool = NULL;
        return -ENODEV;
    }
    /* IPSec-MB creates a missing queue pair in the primary via IPC on the
     * first secondary-process call.  A second call binds the secondary's
     * process-local IMB function pointers to that shared queue pair. */
    if (rte_cryptodev_queue_pair_setup(
            device_id, 0, &queue_config, rte_socket_id()) != 0) {
        rte_mempool_free(ipsec->session_pool);
        ipsec->session_pool = NULL;
        return -ENODEV;
    }
    if (rte_cryptodev_start(device_id) != 0) {
        rte_mempool_free(ipsec->session_pool);
        ipsec->session_pool = NULL;
        return -ENODEV;
    }
    ipsec->device_started = true;
    ipsec->ready = true;
    return 0;
}

static void
release_runtime_sa(struct n3iwf_dp_ipsec *ipsec,
                   struct n3iwf_dp_ipsec_sa *runtime)
{
    if (runtime->inbound_crypto != NULL) {
        (void)rte_cryptodev_sym_session_free(ipsec->device_id,
                                             runtime->inbound_crypto);
    }
    if (runtime->outbound_crypto != NULL) {
        (void)rte_cryptodev_sym_session_free(ipsec->device_id,
                                             runtime->outbound_crypto);
    }
    if (runtime->inbound_sa != NULL) {
        rte_ipsec_sa_fini(runtime->inbound_sa);
        rte_free(runtime->inbound_sa);
    }
    if (runtime->outbound_sa != NULL) {
        rte_ipsec_sa_fini(runtime->outbound_sa);
        rte_free(runtime->outbound_sa);
    }
    memset(runtime, 0, sizeof(*runtime));
}

void
n3iwf_dp_ipsec_close(struct n3iwf_dp_ipsec *ipsec)
{
    size_t index;

    if (ipsec == NULL) {
        return;
    }
    for (index = 0; index < N3IWF_DP_MAX_CHILD_SAS; ++index) {
        if (ipsec->sas[index].used) {
            release_runtime_sa(ipsec, &ipsec->sas[index]);
        }
    }
    if (ipsec->device_started) {
        rte_cryptodev_stop(ipsec->device_id);
    }
    if (ipsec->session_pool != NULL) {
        rte_mempool_free(ipsec->session_pool);
    }
    memset(ipsec, 0, sizeof(*ipsec));
}

void
n3iwf_dp_ipsec_reconcile(
    struct n3iwf_dp_ipsec *ipsec,
    const struct n3iwf_dp_child_sa_table *child_sas)
{
    size_t index;

    if (ipsec == NULL || child_sas == NULL) {
        return;
    }
    if (ipsec->reconciled_child_sa_revision == child_sas->revision) {
        return;
    }
    for (index = 0; index < N3IWF_DP_MAX_CHILD_SAS; ++index) {
        struct n3iwf_dp_ipsec_sa *runtime = &ipsec->sas[index];
        const struct n3iwf_dp_child_sa *contract =
            &child_sas->entries[index];

        if (!runtime->used) {
            continue;
        }
        if (!contract->used ||
            ntohl(contract->parameters.inbound_spi) != runtime->inbound_spi ||
            contract->generation != runtime->generation) {
            release_runtime_sa(ipsec, runtime);
        }
    }
    ipsec->reconciled_child_sa_revision = child_sas->revision;
}

static void
fill_xforms(struct n3iwf_dp_ipsec_sa *runtime,
            const struct n3iwf_dp_child_sa_wire *wire)
{
    runtime->inbound_auth.type = RTE_CRYPTO_SYM_XFORM_AUTH;
    runtime->inbound_auth.auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
    runtime->inbound_auth.auth.algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
    runtime->inbound_auth.auth.key.data =
        (uint8_t *)wire->inbound_integrity_key;
    runtime->inbound_auth.auth.key.length = wire->inbound_integrity_key_len;
    runtime->inbound_auth.auth.digest_length = N3IWF_DP_SHA1_96_LEN;
    runtime->inbound_auth.next = &runtime->inbound_cipher;

    runtime->inbound_cipher.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
    runtime->inbound_cipher.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
    runtime->inbound_cipher.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
    runtime->inbound_cipher.cipher.key.data =
        (uint8_t *)wire->inbound_encryption_key;
    runtime->inbound_cipher.cipher.key.length =
        wire->inbound_encryption_key_len;
    runtime->inbound_cipher.cipher.iv.offset = IPSEC_IV_OFFSET;
    runtime->inbound_cipher.cipher.iv.length = N3IWF_DP_AES_CBC_IV_LEN;

    runtime->outbound_cipher.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
    runtime->outbound_cipher.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
    runtime->outbound_cipher.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
    runtime->outbound_cipher.cipher.key.data =
        (uint8_t *)wire->outbound_encryption_key;
    runtime->outbound_cipher.cipher.key.length =
        wire->outbound_encryption_key_len;
    runtime->outbound_cipher.cipher.iv.offset = IPSEC_IV_OFFSET;
    runtime->outbound_cipher.cipher.iv.length = N3IWF_DP_AES_CBC_IV_LEN;
    runtime->outbound_cipher.next = &runtime->outbound_auth;

    runtime->outbound_auth.type = RTE_CRYPTO_SYM_XFORM_AUTH;
    runtime->outbound_auth.auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
    runtime->outbound_auth.auth.algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
    runtime->outbound_auth.auth.key.data =
        (uint8_t *)wire->outbound_integrity_key;
    runtime->outbound_auth.auth.key.length = wire->outbound_integrity_key_len;
    runtime->outbound_auth.auth.digest_length = N3IWF_DP_SHA1_96_LEN;
}

static int
init_direction(struct n3iwf_dp_ipsec *ipsec,
               struct n3iwf_dp_ipsec_sa *runtime,
               const struct n3iwf_dp_child_sa *child, bool inbound)
{
    const struct n3iwf_dp_child_sa_wire *wire = &child->parameters;
    struct rte_crypto_sym_xform *xform = inbound ? &runtime->inbound_auth :
                                                  &runtime->outbound_cipher;
    struct rte_cryptodev_sym_session **crypto = inbound ?
        &runtime->inbound_crypto : &runtime->outbound_crypto;
    struct rte_ipsec_session *session = inbound ? &runtime->inbound :
                                                 &runtime->outbound;
    struct rte_ipsec_sa **sa = inbound ? &runtime->inbound_sa :
                                        &runtime->outbound_sa;
    struct rte_ipsec_sa_prm parameters;
    struct rte_ipv4_hdr tunnel;
    int size;
    int result;

    rte_errno = 0;
    *crypto = rte_cryptodev_sym_session_create(
        ipsec->device_id, xform, ipsec->session_pool);
    if (*crypto == NULL) {
        return rte_errno == 0 ? -ENOMEM : -rte_errno;
    }
    memset(&parameters, 0, sizeof(parameters));
    memset(&tunnel, 0, sizeof(tunnel));
    tunnel.version_ihl = 0x45;
    tunnel.time_to_live = 64;
    tunnel.next_proto_id = IPPROTO_ESP;
    if (inbound) {
        memcpy(&tunnel.src_addr, wire->peer_address, 4);
        memcpy(&tunnel.dst_addr, wire->local_address, 4);
    } else {
        memcpy(&tunnel.src_addr, wire->local_address, 4);
        memcpy(&tunnel.dst_addr, wire->peer_address, 4);
    }
    parameters.flags = RTE_IPSEC_SAFLAG_SQN_ATOM;
    parameters.ipsec_xform.spi = ntohl(inbound ? wire->inbound_spi :
                                                 wire->outbound_spi);
    parameters.ipsec_xform.direction = inbound ?
        RTE_SECURITY_IPSEC_SA_DIR_INGRESS : RTE_SECURITY_IPSEC_SA_DIR_EGRESS;
    parameters.ipsec_xform.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP;
    parameters.ipsec_xform.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL;
    parameters.ipsec_xform.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
    parameters.ipsec_xform.replay_win_sz = ntohl(wire->replay_window);
    parameters.ipsec_xform.esn.value = inbound ? 0 :
        be64_to_host(wire->outbound_sequence);
    parameters.crypto_xform = xform;
    parameters.tun.hdr_len = sizeof(tunnel);
    parameters.tun.next_proto = IPPROTO_IPIP;
    parameters.tun.hdr = &tunnel;

    size = rte_ipsec_sa_size(&parameters);
    if (size <= 0) {
        return -EINVAL;
    }
    *sa = rte_zmalloc("n3iwf_ipsec_sa", (size_t)size, RTE_CACHE_LINE_SIZE);
    if (*sa == NULL) {
        return -ENOMEM;
    }
    result = rte_ipsec_sa_init(*sa, &parameters, (uint32_t)size);
    if (result <= 0 || result > size) {
        return -EINVAL;
    }
    memset(session, 0, sizeof(*session));
    session->sa = *sa;
    session->type = RTE_SECURITY_ACTION_TYPE_CPU_CRYPTO;
    session->crypto.ses = *crypto;
    session->crypto.dev_id = ipsec->device_id;
    return rte_ipsec_session_prepare(session);
}

static struct n3iwf_dp_ipsec_sa *
runtime_sa(struct n3iwf_dp_ipsec *ipsec,
           const struct n3iwf_dp_child_sa *child, uint32_t child_index)
{
    struct n3iwf_dp_ipsec_sa *runtime;
    uint32_t spi = ntohl(child->parameters.inbound_spi);
    static uint32_t reported_failures;
    int result;

    if (child_index >= N3IWF_DP_MAX_CHILD_SAS) {
        return NULL;
    }
    runtime = &ipsec->sas[child_index];
    if (runtime->used && runtime->inbound_spi == spi &&
        runtime->generation == child->generation) {
        return runtime;
    }
    if (runtime->used) {
        release_runtime_sa(ipsec, runtime);
    }
    if (!n3iwf_dp_child_sa_profile_supported(&child->parameters)) {
        return NULL;
    }
    fill_xforms(runtime, &child->parameters);
    result = init_direction(ipsec, runtime, child, true);
    if (result != 0) {
        if (reported_failures++ < 8U) {
            fprintf(stderr,
                    "N3IWF-DP IPsec runtime SA creation failed: "
                    "direction=inbound SPI=0x%08x error=%d (%s)\n",
                    spi, result, rte_strerror(-result));
        }
        release_runtime_sa(ipsec, runtime);
        return NULL;
    }
    result = init_direction(ipsec, runtime, child, false);
    if (result != 0) {
        if (reported_failures++ < 8U) {
            fprintf(stderr,
                    "N3IWF-DP IPsec runtime SA creation failed: "
                    "direction=outbound SPI=0x%08x error=%d (%s)\n",
                    ntohl(child->parameters.outbound_spi), result,
                    rte_strerror(-result));
        }
        release_runtime_sa(ipsec, runtime);
        return NULL;
    }
    runtime->used = true;
    runtime->inbound_spi = spi;
    runtime->generation = child->generation;
    return runtime;
}

static int
ipv4_esp_spi(const struct rte_mbuf *packet, uint32_t *spi)
{
    const uint8_t *data;
    size_t length;
    const struct rte_ether_hdr *ether;
    const struct rte_ipv4_hdr *ipv4;
    size_t header_length;

    data = rte_pktmbuf_mtod(packet, const uint8_t *);
    length = rte_pktmbuf_pkt_len(packet);
    if (length < sizeof(*ether) + sizeof(*ipv4) + ESP_HEADER_LEN) {
        return -EMSGSIZE;
    }
    ether = (const struct rte_ether_hdr *)data;
    if (rte_be_to_cpu_16(ether->ether_type) != RTE_ETHER_TYPE_IPV4) {
        return -EPROTONOSUPPORT;
    }
    ipv4 = (const struct rte_ipv4_hdr *)(data + sizeof(*ether));
    header_length = (size_t)(ipv4->version_ihl & 0x0fU) * 4U;
    if ((ipv4->version_ihl >> 4) != 4 || header_length < sizeof(*ipv4) ||
        ipv4->next_proto_id != IPPROTO_ESP ||
        length < sizeof(*ether) + header_length + ESP_HEADER_LEN) {
        return -EPROTO;
    }
    if ((rte_be_to_cpu_16(ipv4->fragment_offset) &
         (RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_OFFSET_MASK)) != 0) {
        return -EINPROGRESS;
    }
    memcpy(spi, data + sizeof(*ether) + header_length, sizeof(*spi));
    *spi = ntohl(*spi);
    return 0;
}

static int
cpu_crypto(struct rte_ipsec_session *session, struct rte_mbuf *packet,
           uint32_t spi, const char *direction)
{
    struct rte_mbuf *packets[1] = {packet};
    const uint8_t *data = rte_pktmbuf_mtod(packet, const uint8_t *);
    const struct rte_ipv4_hdr *ipv4;
    struct rte_ether_hdr ethernet;
    void *restored;
    uint16_t prepared;
    uint16_t processed;
    int prepare_error;
    static uint32_t reported_failures;

    if (rte_pktmbuf_pkt_len(packet) < sizeof(struct rte_ether_hdr) +
                                      sizeof(*ipv4)) {
        return -EMSGSIZE;
    }
    memcpy(&ethernet, data, sizeof(ethernet));
    ipv4 = (const struct rte_ipv4_hdr *)(data + sizeof(struct rte_ether_hdr));
    packet->l2_len = sizeof(struct rte_ether_hdr);
    packet->l3_len = (uint16_t)((ipv4->version_ihl & 0x0fU) * 4U);

    rte_errno = 0;
    prepared = rte_ipsec_pkt_cpu_prepare(session, packets, 1);
    if (prepared != 1) {
        prepare_error = rte_errno == 0 ? EPROTO : rte_errno;
        if (reported_failures++ < 8U) {
            fprintf(stderr,
                    "N3IWF-DP IPsec %s prepare failed: SPI=0x%08x "
                    "errno=%d (%s) packet_len=%u l2=%u l3=%u\n",
                    direction, spi, rte_errno, rte_strerror(rte_errno),
                    rte_pktmbuf_pkt_len(packet), packet->l2_len,
                    packet->l3_len);
        }
        return -prepare_error;
    }
    processed = rte_ipsec_pkt_process(session, packets, 1);
    if (processed != 1) {
        if (reported_failures++ < 8U) {
            fprintf(stderr,
                    "N3IWF-DP IPsec %s authentication/post-process failed: "
                    "SPI=0x%08x errno=%d (%s) ol_flags=0x%016" PRIx64
                    " packet_len=%u\n",
                    direction, spi, rte_errno, rte_strerror(rte_errno),
                    packet->ol_flags, rte_pktmbuf_pkt_len(packet));
        }
        return -EBADMSG;
    }
    /* DPDK tunnel-mode IPsec exposes an L3 packet after inbound decapsulation
     * and consumes the clear-path L2 header while building an outbound ESP
     * tunnel.  ONVM and the shared clear/GTP path exchange Ethernet frames,
     * so preserve the access header across both transformations.  Inbound
     * restoration also retains the authenticated packet's UE source MAC for
     * session MAC learning; outbound restoration retains the already selected
     * UE destination MAC. */
    restored = rte_pktmbuf_prepend(packet, sizeof(ethernet));
    if (restored == NULL) {
        return -ENOSPC;
    }
    memcpy(restored, &ethernet, sizeof(ethernet));
    if (rte_pktmbuf_pkt_len(packet) < sizeof(ethernet) + sizeof(*ipv4)) {
        return -EMSGSIZE;
    }
    ipv4 = (const struct rte_ipv4_hdr *)((const uint8_t *)restored +
                                         sizeof(ethernet));
    if ((ipv4->version_ihl >> 4) != 4 ||
        (ipv4->version_ihl & 0x0fU) < 5U) {
        return -EPROTO;
    }
    /* rte_ipsec updates tunnel length/ID but does not calculate the IPv4
     * header checksum for CPU-crypto output.  ONVM does not request a NIC
     * checksum offload for this packet, so finish it in software.  Recomputing
     * the authenticated inner IPv4 checksum on inbound is harmless and also
     * covers any ECN/TOS adjustment made by rte_ipsec. */
    ((struct rte_ipv4_hdr *)ipv4)->hdr_checksum = 0;
    ((struct rte_ipv4_hdr *)ipv4)->hdr_checksum =
        rte_ipv4_cksum((const struct rte_ipv4_hdr *)ipv4);
    packet->l2_len = sizeof(ethernet);
    packet->l3_len = (uint16_t)((ipv4->version_ihl & 0x0fU) * 4U);
    return 0;
}

int
n3iwf_dp_handle_ipsec_packet(
    struct rte_mbuf *packet, struct onvm_pkt_meta *meta,
    struct n3iwf_dp_session_table *sessions,
    struct n3iwf_dp_child_sa_table *child_sas,
    struct n3iwf_dp_ipsec *ipsec, struct n3iwf_dp_stats_wire *stats,
    uint16_t upf_service_id, uint16_t access_port,
    const uint8_t access_mac[N3IWF_DP_ETHER_ADDR_LEN])
{
    if (packet == NULL || meta == NULL || sessions == NULL ||
        child_sas == NULL || ipsec == NULL || !ipsec->ready || stats == NULL) {
        return -EINVAL;
    }
    meta->action = ONVM_NF_ACTION_DROP;
    /* ONVM sets meta->src to zero for packets received from a physical NIC
     * and to the sending NF instance for NF-to-NF traffic.  rte_mbuf.port is
     * an ingress-port annotation, not an ownership/direction contract, and
     * can be stale after ring handoffs.  The manager's physical service map
     * sends only the NWu port to this NF, so meta->src is the authoritative
     * distinction between physical ESP and logical N3 downlink traffic. */
    if (meta->src == 0) {
        uint32_t spi;
        uint32_t child_index;
        const struct n3iwf_dp_child_sa *child;
        struct n3iwf_dp_session *bound_session;
        struct n3iwf_dp_ipsec_sa *runtime;
        int parse_result;
        static uint32_t reported_classification_failures;

        parse_result = ipv4_esp_spi(packet, &spi);
        if (parse_result == -EINPROGRESS) {
            ++stats->fragment_drops;
            return parse_result;
        }
        if (parse_result != 0) {
            if (reported_classification_failures++ < 8U) {
                const uint8_t *frame = rte_pktmbuf_mtod(
                    packet, const uint8_t *);
                uint16_t ether_type = 0;
                uint8_t next_header = 0;

                if (rte_pktmbuf_pkt_len(packet) >=
                    sizeof(struct rte_ether_hdr)) {
                    const struct rte_ether_hdr *ether =
                        (const struct rte_ether_hdr *)frame;
                    ether_type = rte_be_to_cpu_16(ether->ether_type);
                    if (ether_type == RTE_ETHER_TYPE_IPV4 &&
                        rte_pktmbuf_pkt_len(packet) >=
                            sizeof(*ether) + sizeof(struct rte_ipv4_hdr)) {
                        const struct rte_ipv4_hdr *outer =
                            (const struct rte_ipv4_hdr *)(frame +
                                                        sizeof(*ether));
                        next_header = outer->next_proto_id;
                    }
                }
                fprintf(stderr,
                        "N3IWF-DP physical ingress is not IPv4 ESP: "
                        "mbuf_port=%u configured_access_port=%u "
                        "ether_type=0x%04x next_header=%u error=%d (%s)\n",
                        packet->port, access_port, ether_type, next_header,
                        parse_result, rte_strerror(-parse_result));
            }
            return -EPROTONOSUPPORT;
        }
        child = n3iwf_dp_child_sa_find_inbound_at(child_sas, spi,
                                                  &child_index);
        if (child == NULL || ntohl(child->parameters.pdu_session_id) == 0) {
            return -ENOENT;
        }
        bound_session = n3iwf_dp_child_sa_get_bound_session(child, sessions);
        if (bound_session == NULL) {
            return -ENOENT;
        }
        runtime = runtime_sa(ipsec, child, child_index);
        if (runtime == NULL) {
            ++stats->crypto_failures;
            return -EBADMSG;
        }
        parse_result = cpu_crypto(&runtime->inbound, packet, spi, "inbound");
        if (parse_result != 0) {
            if (parse_result == -EINVAL) {
                ++stats->replay_drops;
            } else {
                ++stats->crypto_failures;
            }
            return parse_result;
        }
        return n3iwf_dp_handle_authenticated_uplink(
            packet, meta, bound_session, stats, upf_service_id, access_mac);
    }
    {
        const struct n3iwf_dp_session *session = NULL;

        if (n3iwf_dp_handle_clear_downlink_selected(
                packet, meta, sessions, stats, access_port, access_mac,
                &session) == 0 &&
            meta->action == ONVM_NF_ACTION_OUT) {
            const struct n3iwf_dp_child_sa *child;
            struct n3iwf_dp_ipsec_sa *runtime;
            uint32_t child_index;

            if (session == NULL) {
                ++stats->crypto_failures;
                meta->action = ONVM_NF_ACTION_DROP;
                return -ENOENT;
            }
            child = n3iwf_dp_child_sa_get_active_outbound(
                child_sas, session, &child_index);
            runtime = child == NULL ? NULL :
                runtime_sa(ipsec, child, child_index);
            if (runtime == NULL ||
                cpu_crypto(&runtime->outbound, packet,
                           ntohl(child->parameters.outbound_spi),
                           "outbound") != 0) {
                ++stats->crypto_failures;
                if (stats->downlink_packets != 0) {
                    --stats->downlink_packets;
                }
                meta->action = ONVM_NF_ACTION_DROP;
                return -EBADMSG;
            }
            meta->action = ONVM_NF_ACTION_OUT;
            meta->destination = access_port;
            return 0;
        }
    }
    return -EPROTO;
}
