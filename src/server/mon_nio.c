#include "mon_nio.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "buffer.h"
#include "mon_parser.h"
#include "mon_protocol.h"
#include "selector.h"

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

static void mon_process_request(struct mon_conn *conn) {
  /* TODO: dispatch commands */
  send_response(conn, MON_STATUS_UNKNOWN_CMD, NULL, 0);
}
