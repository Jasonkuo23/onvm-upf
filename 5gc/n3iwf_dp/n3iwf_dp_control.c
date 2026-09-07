/*
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include "n3iwf_dp_control.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

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

static int
set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    return 0;
}

static void
send_ack(int client_fd, uint32_t transaction_id,
         uint64_t generation, enum n3iwf_dp_status status, uint32_t detail)
{
    uint8_t response[sizeof(struct n3iwf_dp_wire_header) +
                     sizeof(struct n3iwf_dp_ack_wire)];
    size_t response_len;

    response_len = n3iwf_dp_wire_encode_ack(response, sizeof(response),
                                             transaction_id, generation,
                                             status, detail);
    if (response_len != 0) {
        (void)send(client_fd, response, response_len, MSG_DONTWAIT);
    }
}

static void
send_stats(struct n3iwf_dp_control *control, int client_fd,
           uint32_t transaction_id,
           uint64_t generation)
{
    uint8_t response[sizeof(struct n3iwf_dp_wire_header) +
                     sizeof(struct n3iwf_dp_stats_wire)] = {0};
    struct n3iwf_dp_wire_header header = {0};
    struct n3iwf_dp_stats_wire stats = {0};

    header.magic = htonl(N3IWF_DP_WIRE_MAGIC);
    header.version = htons(N3IWF_DP_WIRE_VERSION);
    header.type = htons(N3IWF_DP_MSG_STATS);
    header.length = htonl((uint32_t)sizeof(response));
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
    memcpy(response, &header, sizeof(header));
    memcpy(response + sizeof(header), &stats, sizeof(stats));
    (void)send(client_fd, response, sizeof(response), MSG_DONTWAIT);
}

static void
handle_message(struct n3iwf_dp_control *control, const uint8_t *message,
               size_t message_len, int client_fd, unsigned char *client_role)
{
    struct n3iwf_dp_wire_header header;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    uint16_t type = 0;
    uint64_t generation = 0;
    uint32_t transaction_id = 0;
    enum n3iwf_dp_status status = N3IWF_DP_STATUS_BAD_MESSAGE;
    int validation;

    if (message_len >= sizeof(header)) {
        memcpy(&header, message, sizeof(header));
        transaction_id = ntohl(header.transaction_id);
    }
    validation = n3iwf_dp_wire_validate(message, message_len, &type,
                                         &generation, &payload, &payload_len);
    if (validation == -EPROTONOSUPPORT) {
        send_ack(client_fd, transaction_id, generation,
                 N3IWF_DP_STATUS_UNSUPPORTED_VERSION, 0);
        return;
    }
    if (validation != 0) {
        send_ack(client_fd, transaction_id, generation,
                 N3IWF_DP_STATUS_BAD_MESSAGE, (uint32_t)-validation);
        return;
    }

    switch (type) {
    case N3IWF_DP_MSG_HELLO:
        if (payload_len == sizeof(struct n3iwf_dp_hello_wire)) {
            const struct n3iwf_dp_hello_wire *hello =
                (const struct n3iwf_dp_hello_wire *)payload;
            if (hello->role == N3IWF_DP_ROLE_WRITER ||
                hello->role == N3IWF_DP_ROLE_OBSERVER) {
                bool writer_exists = false;
                size_t role_index;
                for (role_index = 0;
                     role_index < N3IWF_DP_CONTROL_MAX_CLIENTS;
                     ++role_index) {
                    if (&control->client_roles[role_index] != client_role &&
                        control->client_roles[role_index] ==
                            N3IWF_DP_ROLE_WRITER) {
                        writer_exists = true;
                    }
                }
                if (hello->role != N3IWF_DP_ROLE_WRITER || !writer_exists) {
                    *client_role = hello->role;
                    status = N3IWF_DP_STATUS_OK;
                } else {
                    status = N3IWF_DP_STATUS_CAPACITY;
                }
            }
        }
        break;
    case N3IWF_DP_MSG_SESSION_UPSERT:
        if (*client_role != N3IWF_DP_ROLE_WRITER) {
            status = N3IWF_DP_STATUS_UNSUPPORTED;
        } else if (payload_len == sizeof(struct n3iwf_dp_session_wire)) {
            struct n3iwf_dp_session_wire wire;
            const struct n3iwf_dp_child_sa *child;
            uint32_t sa_index = N3IWF_DP_INVALID_SA_INDEX;

            memcpy(&wire, payload, sizeof(wire));
            child = n3iwf_dp_child_sa_find_latest_for_control(
                control->child_sas, be64_to_host(wire.ue_id),
                ntohl(wire.pdu_session_id), &sa_index);
            if (child == NULL) {
                status = N3IWF_DP_STATUS_NOT_FOUND;
            } else {
                status = n3iwf_dp_session_upsert_wire(control->sessions,
                                                       &wire, generation);
                if (status == N3IWF_DP_STATUS_OK) {
                    status = n3iwf_dp_session_activate_outbound_sa(
                        control->sessions, be64_to_host(wire.ue_id),
                        ntohl(wire.pdu_session_id), sa_index,
                        child->generation);
                    if (status == N3IWF_DP_STATUS_OK) {
                        status = n3iwf_dp_child_sa_bind_session_for_control(
                            control->child_sas, control->sessions,
                            be64_to_host(wire.ue_id),
                            ntohl(wire.pdu_session_id));
                    }
                }
            }
        }
        break;
    case N3IWF_DP_MSG_SESSION_DELETE:
        if (*client_role != N3IWF_DP_ROLE_WRITER) {
            status = N3IWF_DP_STATUS_UNSUPPORTED;
        } else if (payload_len == sizeof(struct n3iwf_dp_session_delete_wire)) {
            struct n3iwf_dp_session_delete_wire wire;

            memcpy(&wire, payload, sizeof(wire));
            status = n3iwf_dp_session_delete(control->sessions,
                                              be64_to_host(wire.ue_id),
                                              ntohl(wire.pdu_session_id),
                                              generation);
        }
        break;
    case N3IWF_DP_MSG_STATS_GET:
        if (payload_len == 0) {
            send_stats(control, client_fd, transaction_id, generation);
            return;
        }
        break;
    case N3IWF_DP_MSG_CHILD_SA_UPSERT:
        if (*client_role != N3IWF_DP_ROLE_WRITER) {
            status = N3IWF_DP_STATUS_UNSUPPORTED;
        } else if (payload_len == sizeof(struct n3iwf_dp_child_sa_wire)) {
            struct n3iwf_dp_child_sa_wire wire;
            uint32_t sa_index = N3IWF_DP_INVALID_SA_INDEX;
            memcpy(&wire, payload, sizeof(wire));
            status = n3iwf_dp_child_sa_upsert_wire_at(
                control->child_sas, &wire, generation, &sa_index);
            if (status == N3IWF_DP_STATUS_OK) {
                enum n3iwf_dp_status activation =
                    n3iwf_dp_session_activate_outbound_sa(
                        control->sessions, be64_to_host(wire.ue_id),
                        ntohl(wire.pdu_session_id), sa_index, generation);
                /* Child-SA programming precedes the initial PDU-session
                 * command.  A missing session is therefore expected; the
                 * later session upsert binds the newest installed SA. */
                if (activation != N3IWF_DP_STATUS_OK &&
                    activation != N3IWF_DP_STATUS_NOT_FOUND) {
                    status = activation;
                } else if (activation == N3IWF_DP_STATUS_OK) {
                    status = n3iwf_dp_child_sa_bind_session_for_control(
                        control->child_sas, control->sessions,
                        be64_to_host(wire.ue_id),
                        ntohl(wire.pdu_session_id));
                }
            }
            /* Erase the stack copy containing traffic keys immediately. */
            memset(&wire, 0, sizeof(wire));
        }
        break;
    case N3IWF_DP_MSG_CHILD_SA_DELETE:
        if (*client_role != N3IWF_DP_ROLE_WRITER) {
            status = N3IWF_DP_STATUS_UNSUPPORTED;
        } else if (payload_len == sizeof(struct n3iwf_dp_child_sa_delete_wire)) {
            struct n3iwf_dp_child_sa_delete_wire wire;
            uint32_t sa_index = N3IWF_DP_INVALID_SA_INDEX;
            memcpy(&wire, payload, sizeof(wire));
            status = n3iwf_dp_child_sa_delete_at(
                control->child_sas, be64_to_host(wire.ue_id),
                ntohl(wire.pdu_session_id), ntohl(wire.inbound_spi), generation,
                &sa_index);
            if (status == N3IWF_DP_STATUS_OK) {
                /* Normally overlap retirement deletes the inactive old SA.
                 * If control deletes the selected SA, fail closed rather
                 * than silently falling back to an older generation. */
                n3iwf_dp_session_clear_outbound_sa(
                    control->sessions, be64_to_host(wire.ue_id),
                    ntohl(wire.pdu_session_id), sa_index);
            }
        }
        break;
    default:
        status = N3IWF_DP_STATUS_UNSUPPORTED;
        break;
    }

    if (status == N3IWF_DP_STATUS_STALE_GENERATION) {
        ++control->stats->stale_updates;
    }
    send_ack(client_fd, transaction_id, generation, status, 0);
}

int
n3iwf_dp_control_open(struct n3iwf_dp_control *control, const char *socket_path,
                      struct n3iwf_dp_session_table *sessions,
                      struct n3iwf_dp_child_sa_table *child_sas,
                      struct n3iwf_dp_stats_wire *stats)
{
    struct sockaddr_un address = {0};
    struct stat existing;
    size_t path_len;
    size_t index;

    if (control == NULL || socket_path == NULL || sessions == NULL ||
        child_sas == NULL || stats == NULL) {
        return -EINVAL;
    }
    path_len = strlen(socket_path);
    if (path_len == 0 || path_len >= sizeof(address.sun_path)) {
        return -ENAMETOOLONG;
    }
    memset(control, 0, sizeof(*control));
    control->listen_fd = -1;
    for (index = 0; index < N3IWF_DP_CONTROL_MAX_CLIENTS; ++index) {
        control->client_fds[index] = -1;
    }
    control->sessions = sessions;
    control->child_sas = child_sas;
    control->stats = stats;
    memcpy(control->socket_path, socket_path, path_len + 1);

    if (lstat(socket_path, &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode)) {
            return -EEXIST;
        }
        if (unlink(socket_path) < 0) {
            return -errno;
        }
    } else if (errno != ENOENT) {
        return -errno;
    }

    control->listen_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (control->listen_fd < 0 || set_nonblocking(control->listen_fd) < 0) {
        n3iwf_dp_control_close(control);
        return -errno;
    }

    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, path_len + 1);
    if (bind(control->listen_fd, (const struct sockaddr *)&address,
             sizeof(address)) < 0 ||
        listen(control->listen_fd, (int)N3IWF_DP_CONTROL_MAX_CLIENTS) < 0) {
        int saved_errno = errno;
        n3iwf_dp_control_close(control);
        return -saved_errno;
    }
    if (chmod(socket_path, S_IRUSR | S_IWUSR) < 0) {
        int saved_errno = errno;
        n3iwf_dp_control_close(control);
        return -saved_errno;
    }
    return 0;
}

int
n3iwf_dp_control_poll(struct n3iwf_dp_control *control)
{
    uint8_t message[N3IWF_DP_CONTROL_MAX_MESSAGE];
    size_t index;
    int free_slot = -1;

    if (control == NULL || control->listen_fd < 0) {
        return -EINVAL;
    }
    for (index = 0; index < N3IWF_DP_CONTROL_MAX_CLIENTS; ++index) {
        if (control->client_fds[index] < 0) {
            free_slot = (int)index;
            break;
        }
    }
    if (free_slot >= 0) {
        int client_fd = accept(control->listen_fd, NULL, NULL);

        if (client_fd >= 0) {
            struct ucred credential = {0};
            socklen_t credential_len = sizeof(credential);
            bool trusted = getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED,
                                      &credential, &credential_len) == 0 &&
                           credential_len == sizeof(credential) &&
                           (credential.uid == 0 || credential.uid == geteuid());
            if (trusted && set_nonblocking(client_fd) == 0) {
                control->client_fds[free_slot] = client_fd;
            } else {
                close(client_fd);
            }
        } else if (errno != EAGAIN && errno != EWOULDBLOCK &&
                   errno != ENOTSOCK && errno != EINVAL) {
            return -errno;
        }
    }

    for (index = 0; index < N3IWF_DP_CONTROL_MAX_CLIENTS; ++index) {
        ssize_t received;
        int client_fd = control->client_fds[index];

        if (client_fd < 0) {
            continue;
        }
        received = recv(client_fd, message, sizeof(message), MSG_DONTWAIT);
        if (received > 0) {
            handle_message(control, message, (size_t)received, client_fd,
                           &control->client_roles[index]);
        } else if (received == 0 ||
                   (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            close(client_fd);
            control->client_fds[index] = -1;
            control->client_roles[index] = 0;
        }
    }
    return 0;
}

void
n3iwf_dp_control_close(struct n3iwf_dp_control *control)
{
    struct stat existing;
    size_t index;

    if (control == NULL) {
        return;
    }
    for (index = 0; index < N3IWF_DP_CONTROL_MAX_CLIENTS; ++index) {
        if (control->client_fds[index] >= 0) {
            close(control->client_fds[index]);
            control->client_fds[index] = -1;
        }
    }
    if (control->listen_fd >= 0) {
        close(control->listen_fd);
    }
    if (control->socket_path[0] != '\0' &&
        lstat(control->socket_path, &existing) == 0 &&
        S_ISSOCK(existing.st_mode)) {
        (void)unlink(control->socket_path);
    }
    control->listen_fd = -1;
}
