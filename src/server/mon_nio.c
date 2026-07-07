#include "mon_nio.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "access_log.h"
#include "buffer.h"
#include "metrics.h"
#include "mon_parser.h"
#include "mon_protocol.h"
#include "selector.h"
#include "user_table.h"

#define MON_BUF_SIZE 4096

struct mon_conn {
  buffer read_buffer;
  buffer write_buffer;
  uint8_t raw_read[MON_BUF_SIZE];
  uint8_t raw_write[MON_BUF_SIZE];
  struct mon_parser parser;
  bool authenticated;
};

static void mon_read(struct selector_key *key);
static void mon_write(struct selector_key *key);
static void mon_close(struct selector_key *key);
static void mon_process_request(struct mon_conn *conn);

static const struct fd_handler mon_handler = {
  .handle_read = mon_read,
  .handle_write = mon_write,
  .handle_close = mon_close,
};

void mon_passive_accept(struct selector_key *key) {
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);

  const int client = accept(key->fd, (struct sockaddr *) &addr, &addr_len);
  if (client == -1) return;

  if (selector_fd_set_nio(client) == -1) {
    close(client);
    return;
  }

  struct mon_conn *conn = calloc(1, sizeof(*conn));
  if (conn == NULL) {
    close(client);
    return;
  }

  buffer_init(&conn->read_buffer, MON_BUF_SIZE, conn->raw_read);
  buffer_init(&conn->write_buffer, MON_BUF_SIZE, conn->raw_write);
  mon_parser_init(&conn->parser);

  if (
    selector_register(key->s, client, &mon_handler, OP_READ, conn) !=
    SELECTOR_SUCCESS
  ) {
    free(conn);
    close(client);
  }
}

static void mon_read(struct selector_key *key) {
  struct mon_conn *conn = key->data;
  size_t count;
  uint8_t *ptr = buffer_write_ptr(&conn->read_buffer, &count);
  const ssize_t n = recv(key->fd, ptr, count, 0);

  if (n <= 0) {
    selector_unregister_fd(key->s, key->fd);
    close(key->fd);
    return;
  }

  buffer_write_adv(&conn->read_buffer, n);

  bool error = false;
  enum mon_parser_state st =
    mon_parser_consume(&conn->read_buffer, &conn->parser, &error);

  if (error) {
    selector_unregister_fd(key->s, key->fd);
    close(key->fd);
    return;
  }

  if (mon_parser_is_done(st, NULL)) {
    mon_process_request(conn);
    selector_set_interest_key(key, OP_WRITE);
  }
}

static void mon_write(struct selector_key *key) {
  struct mon_conn *conn = key->data;
  size_t count;
  uint8_t *ptr = buffer_read_ptr(&conn->write_buffer, &count);
  const ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);

  if (n <= 0) {
    selector_unregister_fd(key->s, key->fd);
    close(key->fd);
    return;
  }

  buffer_read_adv(&conn->write_buffer, n);

  if (!buffer_can_read(&conn->write_buffer)) {
    buffer_reset(&conn->read_buffer);
    buffer_reset(&conn->write_buffer);
    mon_parser_init(&conn->parser);
    selector_set_interest_key(key, OP_READ);
  }
}

static void mon_close(struct selector_key *key) { free(key->data); }

/* helper: encode a response into the write buffer */
static void send_response(
  struct mon_conn *conn, uint8_t status, const uint8_t *payload,
  uint16_t payload_len
) {
  struct mon_response resp = {
    .version = MON_VERSION,
    .status = status,
    .payload_len = payload_len,
    .payload = payload,
  };
  size_t count;
  uint8_t *ptr = buffer_write_ptr(&conn->write_buffer, &count);
  int written = mon_response_encode(&resp, ptr, count);
  if (written > 0) buffer_write_adv(&conn->write_buffer, written);
}

struct list_ctx {
  uint8_t *buf;
  size_t offset;
  size_t cap;
  uint8_t count;
};

static void list_user_cb(const char *name, void *ctx) {
  struct list_ctx *lc = ctx;
  size_t len = strlen(name);
  if (len > UINT8_MAX) len = UINT8_MAX;
  if (lc->offset + len + 1 <= lc->cap) {
    lc->buf[lc->offset++] = (uint8_t) len;
    memcpy(lc->buf + lc->offset, name, len);
    lc->offset += len;
    if (lc->count < UINT8_MAX) lc->count++;
  }
}

static void mon_process_request(struct mon_conn *conn) {
  struct mon_request *req = &conn->parser.request;

  if (!conn->authenticated && req->cmd != MON_CMD_AUTH) {
    send_response(conn, MON_STATUS_AUTH_FAIL, NULL, 0);
    return;
  }

  switch (req->cmd) {
    case MON_CMD_AUTH:
      if (req->nargs < 2 || !user_table_lookup(req->args[0], req->args[1])) {
        send_response(conn, MON_STATUS_AUTH_FAIL, NULL, 0);
      } else {
        conn->authenticated = true;
        fprintf(
          stderr, " [ You're being monitored by %s ... ]\n", req->args[0]
        );
        send_response(conn, MON_STATUS_OK, NULL, 0);
      }
      break;

    case MON_CMD_ADD_USER:
      if (req->nargs < 2) {
        send_response(conn, MON_STATUS_INTERNAL_ERROR, NULL, 0);
      } else if (user_table_add(req->args[0], req->args[1])) {
        send_response(conn, MON_STATUS_OK, NULL, 0);
      } else {
        send_response(conn, MON_STATUS_USER_EXISTS, NULL, 0);
      }
      break;

    case MON_CMD_DEL_USER:
      if (req->nargs < 1) {
        send_response(conn, MON_STATUS_INTERNAL_ERROR, NULL, 0);
      } else if (user_table_remove(req->args[0])) {
        send_response(conn, MON_STATUS_OK, NULL, 0);
      } else {
        send_response(conn, MON_STATUS_USER_NOT_FOUND, NULL, 0);
      }
      break;

    case MON_CMD_LIST_USERS: {
      uint8_t payload[MON_BUF_SIZE];
      struct list_ctx lc =
        {.buf = payload, .offset = 1, .cap = sizeof(payload), .count = 0};
      user_table_list(list_user_cb, &lc);
      payload[0] = lc.count;
      send_response(conn, MON_STATUS_OK, payload, (uint16_t) lc.offset);
      break;
    }

    case MON_CMD_GET_METRICS: {
      const struct metrics *m = metrics_get();
      uint8_t payload[MON_METRICS_PAYLOAD_LEN];
      for (int i = 0; i < 8; i++)
        payload[i] = (m->historic_connections >> (8 * (7 - i))) & 0xFF;
      for (int i = 0; i < 8; i++)
        payload[8 + i] = (m->current_connections >> (8 * (7 - i))) & 0xFF;
      for (int i = 0; i < 8; i++)
        payload[16 + i] = (m->bytes_transferred >> (8 * (7 - i))) & 0xFF;
      send_response(conn, MON_STATUS_OK, payload, MON_METRICS_PAYLOAD_LEN);
      break;
    }

    case MON_CMD_GET_ACCESS_LOG: {
      unsigned count;
      const struct access_entry *entries = access_log_get(&count);
      unsigned oldest = access_log_oldest_index();

      uint8_t payload[4096];
      size_t off = 2;
      uint16_t encoded = 0;
      for (unsigned i = 0; i < count; i++) {
        unsigned idx = (oldest + i) % MAX_LOG_ENTRIES;
        const struct access_entry *e = &entries[idx];
        uint8_t ulen = (uint8_t) strlen(e->username);
        uint8_t dlen = (uint8_t) strlen(e->dest_addr);

        if (off + 8 + 2 + 1 + ulen + 1 + dlen > sizeof(payload)) break;

        uint64_t ts = (uint64_t) e->timestamp;
        for (int j = 0; j < 8; j++)
          payload[off++] = (ts >> (8 * (7 - j))) & 0xFF;
        payload[off++] = (e->dest_port >> 8) & 0xFF;
        payload[off++] = e->dest_port & 0xFF;
        payload[off++] = ulen;
        memcpy(payload + off, e->username, ulen);
        off += ulen;
        payload[off++] = dlen;
        memcpy(payload + off, e->dest_addr, dlen);
        off += dlen;
        encoded++;
      }
      payload[0] = (encoded >> 8) & 0xFF;
      payload[1] = encoded & 0xFF;
      send_response(conn, MON_STATUS_OK, payload, (uint16_t) off);
      break;
    }

    default:
      send_response(conn, MON_STATUS_UNKNOWN_CMD, NULL, 0);
      break;
  }
}
