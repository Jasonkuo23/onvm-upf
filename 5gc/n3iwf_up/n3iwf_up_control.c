/*
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include "n3iwf_up_control.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

struct response_buffer {
    uint8_t data[N3DP_MAX_MESSAGE];
    size_t length;
};

static uint64_t
host_to_be64(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

static uint64_t
be64_to_host(uint64_t value)
{
    return host_to_be64(value);
}

static void
send_ack(struct response_buffer *response, uint32_t transaction_id,
         uint64_t generation, enum n3iwf_up_status status, uint32_t detail)
{
    uint8_t encoded[sizeof(struct n3iwf_up_wire_header) +
                     sizeof(struct n3iwf_up_ack_wire)];
    size_t response_len;

    response_len = n3iwf_up_wire_encode_ack(encoded, sizeof(encoded),
                                             transaction_id, generation,
                                             status, detail);
    if (response_len != 0) {
        memcpy(response->data, encoded, response_len);
        response->length = response_len;
    }
}

static void
send_stats(struct n3iwf_up_control *control, struct response_buffer *response,
           uint32_t transaction_id,
           uint64_t generation)
{
    uint8_t encoded[sizeof(struct n3iwf_up_wire_header) +
                     sizeof(struct n3iwf_up_stats_wire)] = {0};
    struct n3iwf_up_wire_header header = {0};
    struct n3iwf_up_stats_wire stats = {0};

    header.magic = htonl(N3IWF_UP_WIRE_MAGIC);
    header.version = htons(N3IWF_UP_WIRE_VERSION);
    header.type = htons(N3IWF_UP_MSG_STATS);
    header.length = htonl((uint32_t)sizeof(encoded));
    header.transaction_id = htonl(transaction_id);
    header.generation = host_to_be64(generation);
    stats.uplink_packets = host_to_be64(control->stats->uplink_packets);
    stats.downlink_packets = host_to_be64(control->stats->downlink_packets);
    stats.unknown_teid = host_to_be64(control->stats->unknown_teid);
    stats.unknown_qfi = host_to_be64(control->stats->unknown_qfi);
    stats.malformed_packets = host_to_be64(control->stats->malformed_packets);
    stats.replay_drops = host_to_be64(control->stats->replay_drops);
    stats.crypto_failures = host_to_be64(control->stats->crypto_failures);
    stats.fragment_drops = host_to_be64(control->stats->fragment_drops);
    stats.stale_updates = host_to_be64(control->stats->stale_updates);
    stats.control_to_cp = host_to_be64(control->stats->control_to_cp);
    stats.control_from_cp = host_to_be64(control->stats->control_from_cp);
    stats.control_punt_drops =
        host_to_be64(control->stats->control_punt_drops);
    stats.access_mac_learns =
        host_to_be64(control->stats->access_mac_learns);
    stats.access_mac_changes =
        host_to_be64(control->stats->access_mac_changes);
    stats.access_neighbor_drops =
        host_to_be64(control->stats->access_neighbor_drops);
    stats.active_sessions = host_to_be64(control->sessions->count);
    stats.active_child_sas = host_to_be64(control->child_sas->count);
    stats.unknown_spi = host_to_be64(control->stats->unknown_spi);
    stats.oversize_drops = host_to_be64(control->stats->oversize_drops);
    stats.buffer_drops = host_to_be64(control->stats->buffer_drops);
    memcpy(encoded, &header, sizeof(header));
    memcpy(encoded + sizeof(header), &stats, sizeof(stats));
    memcpy(response->data, encoded, sizeof(encoded));
    response->length = sizeof(encoded);
}

static void
handle_message(struct n3iwf_up_control *control, const uint8_t *message,
               size_t message_len, struct response_buffer *response, unsigned char *client_role)
{
    struct n3iwf_up_wire_header header;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    uint16_t type = 0;
    uint64_t generation = 0;
    uint32_t transaction_id = 0;
    enum n3iwf_up_status status = N3IWF_UP_STATUS_BAD_MESSAGE;
    int validation;

    if (message_len >= sizeof(header)) {
        memcpy(&header, message, sizeof(header));
        transaction_id = ntohl(header.transaction_id);
    }
    validation = n3iwf_up_wire_validate(message, message_len, &type,
                                         &generation, &payload, &payload_len);
    if (validation == -EPROTONOSUPPORT) {
        send_ack(response, transaction_id, generation,
                 N3IWF_UP_STATUS_UNSUPPORTED_VERSION, 0);
        return;
    }
    if (validation != 0) {
        send_ack(response, transaction_id, generation,
                 N3IWF_UP_STATUS_BAD_MESSAGE, (uint32_t)-validation);
        return;
    }

    switch (type) {
    case N3IWF_UP_MSG_HELLO:
        if (payload_len == sizeof(struct n3iwf_up_hello_wire)) {
            const struct n3iwf_up_hello_wire *hello =
                (const struct n3iwf_up_hello_wire *)payload;
            if (hello->role == N3IWF_UP_ROLE_WRITER ||
                hello->role == N3IWF_UP_ROLE_OBSERVER) {
                bool writer_exists = false;
                size_t role_index;
                for (role_index = 0;
                     role_index < N3IWF_UP_CONTROL_MAX_CLIENTS;
                     ++role_index) {
                    if (&control->client_roles[role_index] != client_role &&
                        control->client_roles[role_index] ==
                            N3IWF_UP_ROLE_WRITER &&
                        control->client_owners[role_index] != 0 &&
                        n3dp_server_client_owner(&control->transport, role_index) ==
                            control->client_owners[role_index]) {
                        writer_exists = true;
                    }
                }
                if (hello->role != N3IWF_UP_ROLE_WRITER || !writer_exists) {
                    *client_role = hello->role;
                    status = N3IWF_UP_STATUS_OK;
                } else {
                    status = N3IWF_UP_STATUS_CAPACITY;
                }
            }
        }
        break;
    case N3IWF_UP_MSG_SESSION_UPSERT:
        if (*client_role != N3IWF_UP_ROLE_WRITER) {
            status = N3IWF_UP_STATUS_UNSUPPORTED;
        } else if (payload_len == sizeof(struct n3iwf_up_session_wire)) {
            struct n3iwf_up_session_wire wire;
            const struct n3iwf_up_child_sa *child;
            uint32_t sa_index = N3IWF_UP_INVALID_SA_INDEX;

            memcpy(&wire, payload, sizeof(wire));
            child = n3iwf_up_child_sa_find_latest_for_control(
                control->child_sas, be64_to_host(wire.ue_id),
                ntohl(wire.pdu_session_id), &sa_index);
            if (child == NULL) {
                status = N3IWF_UP_STATUS_NOT_FOUND;
            } else {
                status = n3iwf_up_session_upsert_wire(control->sessions,
                                                       &wire, generation);
                if (status == N3IWF_UP_STATUS_OK) {
                    status = n3iwf_up_session_activate_outbound_sa(
                        control->sessions, be64_to_host(wire.ue_id),
                        ntohl(wire.pdu_session_id), sa_index,
                        child->generation);
                    if (status == N3IWF_UP_STATUS_OK) {
                        status = n3iwf_up_child_sa_bind_session_for_control(
                            control->child_sas, control->sessions,
                            be64_to_host(wire.ue_id),
                            ntohl(wire.pdu_session_id));
                    }
                }
            }
        }
        break;
    case N3IWF_UP_MSG_SESSION_DELETE:
        if (*client_role != N3IWF_UP_ROLE_WRITER) {
            status = N3IWF_UP_STATUS_UNSUPPORTED;
        } else if (payload_len == sizeof(struct n3iwf_up_session_delete_wire)) {
            struct n3iwf_up_session_delete_wire wire;

            memcpy(&wire, payload, sizeof(wire));
            status = n3iwf_up_session_delete(control->sessions,
                                              be64_to_host(wire.ue_id),
                                              ntohl(wire.pdu_session_id),
                                              generation);
        }
        break;
    case N3IWF_UP_MSG_STATS_GET:
        if (payload_len == 0) {
            send_stats(control, response, transaction_id, generation);
            return;
        }
        break;
    case N3IWF_UP_MSG_CHILD_SA_UPSERT:
        if (*client_role != N3IWF_UP_ROLE_WRITER) {
            status = N3IWF_UP_STATUS_UNSUPPORTED;
        } else if (payload_len == sizeof(struct n3iwf_up_child_sa_wire)) {
            struct n3iwf_up_child_sa_wire wire;
            uint32_t sa_index = N3IWF_UP_INVALID_SA_INDEX;
            memcpy(&wire, payload, sizeof(wire));
            status = n3iwf_up_child_sa_upsert_wire_at(
                control->child_sas, &wire, generation, &sa_index);
            if (status == N3IWF_UP_STATUS_OK) {
                enum n3iwf_up_status activation =
                    n3iwf_up_session_activate_outbound_sa(
                        control->sessions, be64_to_host(wire.ue_id),
                        ntohl(wire.pdu_session_id), sa_index, generation);
                /* Child-SA programming precedes the initial PDU-session
                 * command.  A missing session is therefore expected; the
                 * later session upsert binds the newest installed SA. */
                if (activation != N3IWF_UP_STATUS_OK &&
                    activation != N3IWF_UP_STATUS_NOT_FOUND) {
                    status = activation;
                } else if (activation == N3IWF_UP_STATUS_OK) {
                    status = n3iwf_up_child_sa_bind_session_for_control(
                        control->child_sas, control->sessions,
                        be64_to_host(wire.ue_id),
                        ntohl(wire.pdu_session_id));
                }
            }
            /* Erase the stack copy containing traffic keys immediately. */
            memset(&wire, 0, sizeof(wire));
        }
        break;
    case N3IWF_UP_MSG_CHILD_SA_DELETE:
        if (*client_role != N3IWF_UP_ROLE_WRITER) {
            status = N3IWF_UP_STATUS_UNSUPPORTED;
        } else if (payload_len == sizeof(struct n3iwf_up_child_sa_delete_wire)) {
            struct n3iwf_up_child_sa_delete_wire wire;
            uint32_t sa_index = N3IWF_UP_INVALID_SA_INDEX;
            memcpy(&wire, payload, sizeof(wire));
            status = n3iwf_up_child_sa_delete_at(
                control->child_sas, be64_to_host(wire.ue_id),
                ntohl(wire.pdu_session_id), ntohl(wire.inbound_spi), generation,
                &sa_index);
            if (status == N3IWF_UP_STATUS_OK) {
                /* Normally overlap retirement deletes the inactive old SA.
                 * If control deletes the selected SA, fail closed rather
                 * than silently falling back to an older generation. */
                n3iwf_up_session_clear_outbound_sa(
                    control->sessions, be64_to_host(wire.ue_id),
                    ntohl(wire.pdu_session_id), sa_index);
            }
        }
        break;
    default:
        status = N3IWF_UP_STATUS_UNSUPPORTED;
        break;
    }

    if (status == N3IWF_UP_STATUS_STALE_GENERATION) {
        ++control->stats->stale_updates;
    }
    send_ack(response, transaction_id, generation, status, 0);
}

int
n3iwf_up_control_open(struct n3iwf_up_control *control, const char *control_name,
                      struct n3iwf_up_session_table *sessions,
                      struct n3iwf_up_child_sa_table *child_sas,
                      struct n3iwf_up_stats_wire *stats)
{
    if (control == NULL || sessions == NULL || child_sas == NULL || stats == NULL)
        return -EINVAL;
    memset(control, 0, sizeof(*control));
    control->sessions = sessions;
    control->child_sas = child_sas;
    control->stats = stats;
    return n3dp_server_open(&control->transport, control_name);
}

int
n3iwf_up_control_poll(struct n3iwf_up_control *control)
{
    if (control == NULL || control->transport.shared == NULL) return -EINVAL;
    (void)n3dp_server_maintain(&control->transport);
    /* Refresh every role before checking writer exclusivity, including leases
     * closed/recycled at an index after the requesting client. */
    for (unsigned i = 0; i < N3DP_MAX_CLIENTS; ++i) {
        uint64_t owner = n3dp_server_client_owner(&control->transport, i);
        if (owner != control->client_owners[i]) {
            control->client_owners[i] = owner;
            control->client_roles[i] = 0;
        }
    }
    for (unsigned i = 0; i < N3DP_MAX_CLIENTS; ++i) {
        struct n3dp_message *message = NULL;
        struct response_buffer response;
        if (n3dp_server_receive(&control->transport, i, &message) != 0) continue;
        response.length = 0;
        uint64_t owner = message->owner;
        handle_message(control, message->data, message->length, &response,
                       &control->client_roles[i]);
        /* Erase keys before publishing ACK, even if the response ring is full. */
        n3dp_server_release(&control->transport, message);
        (void)n3dp_server_reply(&control->transport, i, owner,
                               response.data, response.length);
    }
    return 0;
}

void
n3iwf_up_control_close(struct n3iwf_up_control *control)
{
    if (control != NULL) n3dp_server_close(&control->transport);
}
