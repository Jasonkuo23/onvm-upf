/*
 * Versioned control-plane/data-plane contract for L25GC+ N3IWF.
 *
 * All multi-octet integer fields are network byte order. Socket transport is
 * AF_UNIX/SOCK_SEQPACKET so one datagram contains exactly one message.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef N3IWF_DP_WIRE_H
#define N3IWF_DP_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define N3IWF_DP_WIRE_MAGIC 0x4e334450U /* "N3DP" */
#define N3IWF_DP_WIRE_VERSION 1U
#define N3IWF_DP_MAX_QFI 63U
#define N3IWF_DP_ADDR_LEN 16U
#define N3IWF_DP_MAX_KEY_LEN 64U

enum n3iwf_dp_message_type {
    N3IWF_DP_MSG_HELLO = 1,
    N3IWF_DP_MSG_SESSION_UPSERT = 2,
    N3IWF_DP_MSG_SESSION_DELETE = 3,
    N3IWF_DP_MSG_CHILD_SA_UPSERT = 4,
    N3IWF_DP_MSG_CHILD_SA_DELETE = 5,
    N3IWF_DP_MSG_STATS_GET = 6,
    N3IWF_DP_MSG_ACK = 0x8000,
    N3IWF_DP_MSG_STATS = 0x8001,
};

enum n3iwf_dp_status {
    N3IWF_DP_STATUS_OK = 0,
    N3IWF_DP_STATUS_BAD_MESSAGE = 1,
    N3IWF_DP_STATUS_UNSUPPORTED_VERSION = 2,
    N3IWF_DP_STATUS_STALE_GENERATION = 3,
    N3IWF_DP_STATUS_NOT_FOUND = 4,
    N3IWF_DP_STATUS_CAPACITY = 5,
    N3IWF_DP_STATUS_UNSUPPORTED = 6,
};

enum n3iwf_dp_address_family {
    N3IWF_DP_AF_IPV4 = 4,
    N3IWF_DP_AF_IPV6 = 6,
};

enum n3iwf_dp_client_role {
    N3IWF_DP_ROLE_WRITER = 1,
    N3IWF_DP_ROLE_OBSERVER = 2,
};

enum n3iwf_dp_child_sa_flags {
    N3IWF_DP_CHILD_SA_NAT_T = 1U << 0,
    N3IWF_DP_CHILD_SA_ESN = 1U << 1,
};

struct n3iwf_dp_wire_header {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t length;
    uint32_t transaction_id;
    uint64_t generation;
} __attribute__((packed));

struct n3iwf_dp_session_wire {
    uint64_t ue_id;
    uint32_t pdu_session_id;
    uint32_t uplink_teid;
    uint32_t downlink_teid;
    uint8_t address_family;
    uint8_t qfi_count;
    uint8_t reserved[2];
    uint8_t ue_pdu_address[N3IWF_DP_ADDR_LEN];
    uint8_t n3iwf_nwu_address[N3IWF_DP_ADDR_LEN];
    uint8_t ue_nwu_address[N3IWF_DP_ADDR_LEN];
    uint8_t n3iwf_n3_address[N3IWF_DP_ADDR_LEN];
    uint8_t upf_n3_address[N3IWF_DP_ADDR_LEN];
    uint8_t qfi[N3IWF_DP_MAX_QFI];
} __attribute__((packed));

struct n3iwf_dp_session_delete_wire {
    uint64_t ue_id;
    uint32_t pdu_session_id;
} __attribute__((packed));

struct n3iwf_dp_hello_wire {
    uint8_t role;
    uint8_t reserved[3];
} __attribute__((packed));

/*
 * One bidirectional ESP Child-SA pair. Algorithm values are the IKEv2
 * Transform IDs from RFC 7296/IANA, not implementation-specific enums.
 * Keys are directionally explicit from the N3IWF point of view.
 */
struct n3iwf_dp_child_sa_wire {
    uint64_t ue_id;
    uint32_t pdu_session_id; /* zero for the signalling Child SA */
    uint32_t inbound_spi;    /* UE -> N3IWF */
    uint32_t outbound_spi;   /* N3IWF -> UE */
    uint16_t encryption_id;
    uint16_t integrity_id;
    uint16_t local_port;
    uint16_t peer_port;
    uint32_t replay_window;
    uint32_t flags;
    uint64_t outbound_sequence;
    uint64_t soft_lifetime_seconds;
    uint64_t hard_lifetime_seconds;
    uint8_t address_family;
    uint8_t ip_protocol;
    uint8_t inbound_encryption_key_len;
    uint8_t inbound_integrity_key_len;
    uint8_t outbound_encryption_key_len;
    uint8_t outbound_integrity_key_len;
    uint8_t reserved[2];
    uint8_t local_address[N3IWF_DP_ADDR_LEN];
    uint8_t peer_address[N3IWF_DP_ADDR_LEN];
    uint8_t local_selector[N3IWF_DP_ADDR_LEN];
    uint8_t peer_selector[N3IWF_DP_ADDR_LEN];
    uint8_t inbound_encryption_key[N3IWF_DP_MAX_KEY_LEN];
    uint8_t inbound_integrity_key[N3IWF_DP_MAX_KEY_LEN];
    uint8_t outbound_encryption_key[N3IWF_DP_MAX_KEY_LEN];
    uint8_t outbound_integrity_key[N3IWF_DP_MAX_KEY_LEN];
} __attribute__((packed));

struct n3iwf_dp_child_sa_delete_wire {
    uint64_t ue_id;
    uint32_t pdu_session_id;
    uint32_t inbound_spi;
} __attribute__((packed));

struct n3iwf_dp_ack_wire {
    uint32_t status;
    uint32_t detail;
    uint64_t applied_generation;
} __attribute__((packed));

struct n3iwf_dp_stats_wire {
    uint64_t uplink_packets;
    uint64_t downlink_packets;
    uint64_t unknown_teid;
    uint64_t unknown_qfi;
    uint64_t malformed_packets;
    uint64_t replay_drops;
    uint64_t crypto_failures;
    uint64_t fragment_drops;
    uint64_t stale_updates;
    uint64_t control_to_cp;
    uint64_t control_from_cp;
    uint64_t control_punt_drops;
    uint64_t access_mac_learns;
    uint64_t access_mac_changes;
    uint64_t access_neighbor_drops;
} __attribute__((packed));

int
n3iwf_dp_wire_validate(const uint8_t *message, size_t message_len,
                       uint16_t *type, uint64_t *generation,
                       const uint8_t **payload, size_t *payload_len);

size_t
n3iwf_dp_wire_encode_ack(uint8_t *out, size_t capacity, uint32_t transaction_id,
                         uint64_t generation, enum n3iwf_dp_status status,
                         uint32_t detail);

#endif
