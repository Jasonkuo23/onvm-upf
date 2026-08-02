/*
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

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
send_ack(struct n3iwf_dp_control *control, uint32_t transaction_id,
         uint64_t generation, enum n3iwf_dp_status status, uint32_t detail)
{
    uint8_t response[sizeof(struct n3iwf_dp_wire_header) +
                     sizeof(struct n3iwf_dp_ack_wire)];
    size_t response_len;

    response_len = n3iwf_dp_wire_encode_ack(response, sizeof(response),
                                             transaction_id, generation,
                                             status, detail);
    if (response_len != 0) {
        (void)send(control->client_fd, response, response_len, MSG_DONTWAIT);
    }
}

static void
send_stats(struct n3iwf_dp_control *control, uint32_t transaction_id,
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
    memcpy(response, &header, sizeof(header));
    memcpy(response + sizeof(header), &stats, sizeof(stats));
    (void)send(control->client_fd, response, sizeof(response), MSG_DONTWAIT);
}

static void
handle_message(struct n3iwf_dp_control *control, const uint8_t *message,
               size_t message_len)
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
        send_ack(control, transaction_id, generation,
                 N3IWF_DP_STATUS_UNSUPPORTED_VERSION, 0);
        return;
    }
    if (validation != 0) {
        send_ack(control, transaction_id, generation,
                 N3IWF_DP_STATUS_BAD_MESSAGE, (uint32_t)-validation);
        return;
    }

    switch (type) {
    case N3IWF_DP_MSG_HELLO:
        status = payload_len == 0 ? N3IWF_DP_STATUS_OK :
                 N3IWF_DP_STATUS_BAD_MESSAGE;
        break;
    case N3IWF_DP_MSG_SESSION_UPSERT:
        if (payload_len == sizeof(struct n3iwf_dp_session_wire)) {
            struct n3iwf_dp_session_wire wire;

            memcpy(&wire, payload, sizeof(wire));
            status = n3iwf_dp_session_upsert_wire(control->sessions, &wire,
                                                   generation);
        }
        break;
    case N3IWF_DP_MSG_SESSION_DELETE:
        if (payload_len == sizeof(struct n3iwf_dp_session_delete_wire)) {
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
            send_stats(control, transaction_id, generation);
            return;
        }
        break;
    case N3IWF_DP_MSG_CHILD_SA_UPSERT:
    case N3IWF_DP_MSG_CHILD_SA_DELETE:
        /* Crypto is fail-closed until a cryptodev backend is selected. */
        status = N3IWF_DP_STATUS_UNSUPPORTED;
        break;
    default:
        status = N3IWF_DP_STATUS_UNSUPPORTED;
        break;
    }

    if (status == N3IWF_DP_STATUS_STALE_GENERATION) {
        ++control->stats->stale_updates;
    }
    send_ack(control, transaction_id, generation, status, 0);
}

int
n3iwf_dp_control_open(struct n3iwf_dp_control *control, const char *socket_path,
                      struct n3iwf_dp_session_table *sessions,
                      struct n3iwf_dp_stats_wire *stats)
{
    struct sockaddr_un address = {0};
    struct stat existing;
    size_t path_len;

    if (control == NULL || socket_path == NULL || sessions == NULL ||
        stats == NULL) {
        return -EINVAL;
    }
    path_len = strlen(socket_path);
    if (path_len == 0 || path_len >= sizeof(address.sun_path)) {
        return -ENAMETOOLONG;
    }
    memset(control, 0, sizeof(*control));
    control->listen_fd = -1;
    control->client_fd = -1;
    control->sessions = sessions;
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
        listen(control->listen_fd, 4) < 0) {
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
    ssize_t received;

    if (control == NULL || control->listen_fd < 0) {
        return -EINVAL;
    }
    if (control->client_fd < 0) {
        control->client_fd = accept(control->listen_fd, NULL, NULL);
        if (control->client_fd >= 0) {
            (void)set_nonblocking(control->client_fd);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return -errno;
        }
    }
    if (control->client_fd < 0) {
        return 0;
    }

    received = recv(control->client_fd, message, sizeof(message), MSG_DONTWAIT);
    if (received > 0) {
        handle_message(control, message, (size_t)received);
    } else if (received == 0) {
        close(control->client_fd);
        control->client_fd = -1;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        int saved_errno = errno;
        close(control->client_fd);
        control->client_fd = -1;
        return -saved_errno;
    }
    return 0;
}

void
n3iwf_dp_control_close(struct n3iwf_dp_control *control)
{
    struct stat existing;

    if (control == NULL) {
        return;
    }
    if (control->client_fd >= 0) {
        close(control->client_fd);
    }
    if (control->listen_fd >= 0) {
        close(control->listen_fd);
    }
    if (control->socket_path[0] != '\0' &&
        lstat(control->socket_path, &existing) == 0 &&
        S_ISSOCK(existing.st_mode)) {
        (void)unlink(control->socket_path);
    }
    control->client_fd = -1;
    control->listen_fd = -1;
}
