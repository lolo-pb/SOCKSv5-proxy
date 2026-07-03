#include "socks5.h"
#include "access_log.h"
#include "connect.h"
#include "dns_resolver.h"
#include "metrics.h"
#include "user_table.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

static struct socks5args *socks5_args;

static void hello_read_init(const unsigned state, struct selector_key *key);
static unsigned hello_read(struct selector_key *key);
static unsigned hello_write(struct selector_key *key);
static void auth_read_init(const unsigned state, struct selector_key *key);
static unsigned auth_read(struct selector_key *key);
static unsigned auth_write(struct selector_key *key);
static void request_read_init(const unsigned state, struct selector_key *key);
static unsigned request_read(struct selector_key *key);
static unsigned request_write(struct selector_key *key);
static void client_unregister(struct socks5 *socks, fd_selector selector);
static void client_close(struct socks5 *socks, fd_selector selector);
static void socks5_free(struct socks5 *socks);

static const struct state_definition socks5_states[] = {
  {
    .state = SOCKS5_STATE_HELLO_READ,
    .on_arrival = hello_read_init,
    .on_read_ready = hello_read,
  },
  {
    .state = SOCKS5_STATE_HELLO_WRITE,
    .on_write_ready = hello_write,
  },
  {
    .state = SOCKS5_STATE_AUTH_READ,
    .on_arrival = auth_read_init,
    .on_read_ready = auth_read,
  },
  {
    .state = SOCKS5_STATE_AUTH_WRITE,
    .on_write_ready = auth_write,
  },
  {
    .state = SOCKS5_STATE_REQUEST_READ,
    .on_arrival = request_read_init,
    .on_read_ready = request_read,
  },
  {
    // Waiting for the upstream/origin nonblocking connect() to finish.
    .state = SOCKS5_STATE_CONNECTING,
  },
  {
    .state = SOCKS5_STATE_REQUEST_WRITE,
    .on_write_ready = request_write,
  },
  {
    .state = SOCKS5_STATE_RELAY,
  },
  {
    .state = SOCKS5_STATE_DONE,
  },
  {
    .state = SOCKS5_STATE_ERROR,
  },
};

void socks5_set_args(struct socks5args *args) { socks5_args = args; }

void socks5_init(struct socks5 *socks) {
  memset(socks, 0, sizeof(*socks));
  atomic_init(&socks->references, 1);
  socks->client_fd = -1;
  socks->origin_fd = -1;
  pthread_mutex_init(&socks->dns_mutex, NULL);
  socks->stm.initial = SOCKS5_STATE_HELLO_READ;
  socks->stm.states = socks5_states;
  socks->stm.max_state = SOCKS5_STATE_ERROR;
  stm_init(&socks->stm);
  buffer_init(
    &socks->read_buffer, sizeof(socks->raw_read_buffer), socks->raw_read_buffer
  );
  buffer_init(
    &socks->write_buffer, sizeof(socks->raw_write_buffer),
    socks->raw_write_buffer
  );
}

void socks5_ref(struct socks5 *socks) {
  if (socks == NULL) { return; }
  atomic_fetch_add_explicit(&socks->references, 1, memory_order_relaxed);
}

// Releases one owner reference; the last release frees the SOCKS state.
void socks5_release(struct socks5 *socks) {
  if (socks == NULL) { return; }

  const unsigned refs =
    atomic_fetch_sub_explicit(&socks->references, 1, memory_order_acq_rel);
  if (refs == 1) {
    socks5_free(socks);
  } else if (refs == 0) {
    abort();
  }
}


// Stores the accepted client fd so origin callbacks can resume client writes.
void socks5_set_client_fd(struct socks5 *socks, const int client_fd) {
  socks->client_fd = client_fd;
}

void socks5_cancel(struct socks5 *socks) {
  if (socks == NULL) { return; }

  pthread_mutex_lock(&socks->dns_mutex);
  socks->cancelled = true;
  pthread_mutex_unlock(&socks->dns_mutex);
}

bool socks5_is_relaying(struct socks5 *socks) { return socks->relay_started; }

static void relay_shutdown_write_side(int fd, bool *shutdown_done) {
  if (*shutdown_done || fd < 0) { return; }

  shutdown(fd, SHUT_WR);
  *shutdown_done = true;
}

// Propagates EOF in one direction without closing the whole tunnel.
static bool relay_should_close(struct socks5 *socks) {
  const bool client_to_origin_drained = !buffer_can_read(&socks->read_buffer);
  const bool origin_to_client_drained = !buffer_can_read(&socks->write_buffer);

  if (socks->client_eof && client_to_origin_drained) {
    relay_shutdown_write_side(socks->origin_fd, &socks->origin_write_shutdown);
  }
  if (socks->origin_eof && origin_to_client_drained) {
    relay_shutdown_write_side(socks->client_fd, &socks->client_write_shutdown);
  }

  return socks->client_eof && socks->origin_eof && client_to_origin_drained &&
         origin_to_client_drained;
}

// Recomputes read/write interests from relay buffer state.
static void relay_update_interests(struct socks5 *socks, fd_selector selector) {
  fd_interest client_interest = OP_NOOP;
  fd_interest origin_interest = OP_NOOP;

  if (!socks->client_eof && buffer_can_write(&socks->read_buffer)) {
    client_interest |= OP_READ;
  }
  if (buffer_can_read(&socks->write_buffer)) { client_interest |= OP_WRITE; }

  if (!socks->origin_eof && buffer_can_write(&socks->write_buffer)) {
    origin_interest |= OP_READ;
  }
  if (buffer_can_read(&socks->read_buffer)) { origin_interest |= OP_WRITE; }

  selector_set_interest(selector, socks->client_fd, client_interest);
  selector_set_interest(selector, socks->origin_fd, origin_interest);
}

// Switches from SOCKS negotiation to raw bidirectional relay.
static unsigned start_relay(struct socks5 *socks, fd_selector selector) {
  socks->relay_started = true;
  socks->client_eof = false;
  socks->origin_eof = false;
  socks->client_write_shutdown = false;
  socks->origin_write_shutdown = false;
  buffer_reset(&socks->read_buffer);
  buffer_reset(&socks->write_buffer);
  relay_update_interests(socks, selector);
  return SOCKS5_STATE_RELAY;
}

// Treats nonblocking would-block errors as normal selector flow.
static bool is_retryable_io_error(void) {
  return errno == EAGAIN || errno == EWOULDBLOCK;
}

// Reads client bytes into the client-to-origin relay buffer.
socks5_action
socks5_relay_client_read(struct socks5 *socks, struct selector_key *key) {
  size_t count;
  uint8_t *ptr = buffer_write_ptr(&socks->read_buffer, &count);
  const ssize_t bytes = read(key->fd, ptr, count);

  if (bytes > 0) {
    buffer_write_adv(&socks->read_buffer, bytes);
  } else if (bytes == 0) {
    socks->client_eof = true;
  } else if (!is_retryable_io_error()) {
    return SOCKS5_ACTION_CLOSE;
  }

  if (relay_should_close(socks)) { return SOCKS5_ACTION_CLOSE; }
  relay_update_interests(socks, key->s);
  return SOCKS5_ACTION_NONE;
}

// Writes origin bytes from the origin-to-client relay buffer.
socks5_action
socks5_relay_client_write(struct socks5 *socks, struct selector_key *key) {
  size_t count;
  uint8_t *ptr = buffer_read_ptr(&socks->write_buffer, &count);
  const ssize_t bytes = write(key->fd, ptr, count);

  if (bytes > 0) {
    buffer_read_adv(&socks->write_buffer, bytes);
    metrics_add_bytes(bytes);
  } else if (bytes < 0 && !is_retryable_io_error()) {
    return SOCKS5_ACTION_CLOSE;
  }

  if (relay_should_close(socks)) { return SOCKS5_ACTION_CLOSE; }
  relay_update_interests(socks, key->s);
  return SOCKS5_ACTION_NONE;
}

socks5_action
socks5_handle_read(struct socks5 *socks, struct selector_key *key) {

  const unsigned state = stm_handler_read(&socks->stm, key);

  if (state == SOCKS5_STATE_ERROR || state == SOCKS5_STATE_DONE) {
    return SOCKS5_ACTION_CLOSE;
  }
  // Pause the client fd while the origin fd completes connect().
  if (state == SOCKS5_STATE_CONNECTING) { return SOCKS5_ACTION_NOOP; }
  if (state == SOCKS5_STATE_RELAY) { return SOCKS5_ACTION_NONE; }
  return buffer_can_read(&socks->write_buffer) ? SOCKS5_ACTION_WRITE
                                               : SOCKS5_ACTION_READ;
}

socks5_action
socks5_handle_write(struct socks5 *socks, struct selector_key *key) {
  const unsigned state = stm_handler_write(&socks->stm, key);

  if (state == SOCKS5_STATE_ERROR || state == SOCKS5_STATE_DONE) {
    return SOCKS5_ACTION_CLOSE;
  }
  // Pause the client fd while the origin fd completes connect().
  if (state == SOCKS5_STATE_CONNECTING) { return SOCKS5_ACTION_NOOP; }
  if (state == SOCKS5_STATE_RELAY) { return SOCKS5_ACTION_NONE; }
  return buffer_can_read(&socks->write_buffer) ? SOCKS5_ACTION_WRITE
                                               : SOCKS5_ACTION_READ;
}

socks5_action
socks5_handle_block_done(struct socks5 *socks, struct selector_key *key) {
  pthread_mutex_lock(&socks->dns_mutex);
  socks->dns_pending = false;
  pthread_mutex_unlock(&socks->dns_mutex);

  const int connect_status = connect_to_origin(socks, key);
  if (connect_status == EINPROGRESS) {
    socks->stm.current = socks->stm.states + SOCKS5_STATE_CONNECTING;
    return SOCKS5_ACTION_NOOP;
  }

  socks->request_reply = connect_reply_from_errno(connect_status);
  if (connect_marshall_reply(socks) == SOCKS5_STATE_ERROR) {
    socks->stm.current = socks->stm.states + SOCKS5_STATE_ERROR;
    return SOCKS5_ACTION_CLOSE;
  }
  socks->stm.current = socks->stm.states + SOCKS5_STATE_REQUEST_WRITE;
  return SOCKS5_ACTION_WRITE;
}

static void on_hello_method(struct hello_parser *p, const uint8_t method) {
  uint8_t *selected = p->data;
  if (SOCKS_HELLO_USERNAME_PASSWORD == method) { *selected = method; }
}

static void hello_read_init(const unsigned state, struct selector_key *key) {
  struct socks5 *socks = key->data;

  socks->selected_method = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;
  socks->hello.data = &socks->selected_method;
  socks->hello.on_authentication_method = on_hello_method;
  hello_parser_init(&socks->hello);
}

static unsigned hello_read(struct selector_key *key) {
  struct socks5 *socks = key->data;
  bool error = false;
  const enum hello_state state =
    hello_consume(&socks->read_buffer, &socks->hello, &error);

  if (error) { return SOCKS5_STATE_ERROR; }
  if (!hello_is_done(state, NULL)) { return SOCKS5_STATE_HELLO_READ; }
  if (-1 == hello_marshall(&socks->write_buffer, socks->selected_method)) {
    return SOCKS5_STATE_ERROR;
  }
  return SOCKS5_STATE_HELLO_WRITE;
}

static unsigned hello_write(struct selector_key *key) {
  struct socks5 *socks = key->data;

  if (buffer_can_read(&socks->write_buffer)) {
    return SOCKS5_STATE_HELLO_WRITE;
  }
  if (socks->selected_method == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) {
    return SOCKS5_STATE_ERROR;
  }
  return SOCKS5_STATE_AUTH_READ;
}

static void auth_read_init(const unsigned state, struct selector_key *key) {
  struct socks5 *socks = key->data;

  socks->auth_status = AUTH_STATUS_FAILURE;
  auth_parser_init(&socks->auth);
}

static bool credentials_match(const char *user, const char *pass) {
  return user_table_lookup(user, pass);
}

static unsigned auth_read(struct selector_key *key) {
  struct socks5 *socks = key->data;
  bool error = false;
  const enum auth_state state =
    auth_consume(&socks->read_buffer, &socks->auth, &error);

  if (error) { return SOCKS5_STATE_ERROR; }
  if (!auth_is_done(state, NULL)) { return SOCKS5_STATE_AUTH_READ; }

  socks->auth_status = credentials_match(socks->auth.uname, socks->auth.passwd)
                         ? AUTH_STATUS_SUCCESS
                         : AUTH_STATUS_FAILURE;
  if (-1 == auth_marshall(&socks->write_buffer, socks->auth_status)) {
    return SOCKS5_STATE_ERROR;
  }
  return SOCKS5_STATE_AUTH_WRITE;
}

static unsigned auth_write(struct selector_key *key) {
  struct socks5 *socks = key->data;

  if (buffer_can_read(&socks->write_buffer)) { return SOCKS5_STATE_AUTH_WRITE; }
  return socks->auth_status == AUTH_STATUS_SUCCESS ? SOCKS5_STATE_REQUEST_READ
                                                   : SOCKS5_STATE_ERROR;
}

static void request_read_init(const unsigned state, struct selector_key *key) {
  struct socks5 *socks = key->data;

  socks->request_reply = SOCKS5_REPLY_GENERAL_FAILURE;
  request_parser_init(&socks->request);
}

// Parses CONNECT and starts the origin connection instead of failing directly.
static unsigned request_read(struct selector_key *key) {
  struct socks5 *socks = key->data;
  bool error = false;
  const enum request_state state =
    request_consume(&socks->read_buffer, &socks->request, &error);

  if (error) {
    socks->request_reply = state == request_error_unsupported_atyp
                             ? SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED
                             : SOCKS5_REPLY_GENERAL_FAILURE;
  } else if (!request_is_done(state, NULL)) {
    return SOCKS5_STATE_REQUEST_READ;
  } else if (socks->request.command != SOCKS5_CMD_CONNECT) {
    socks->request_reply = SOCKS5_REPLY_COMMAND_NOT_SUPPORTED;
  } else {
    const int connect_status = connect_to_origin(socks, key);
    if (connect_status == EINPROGRESS) { return SOCKS5_STATE_CONNECTING; }
    socks->request_reply = connect_reply_from_errno(connect_status);
  }

  return connect_marshall_reply(socks);
}

// Sends the SOCKS reply, then starts relay only on success.
static unsigned request_write(struct selector_key *key) {
  struct socks5 *socks = key->data;

  if (buffer_can_read(&socks->write_buffer)) {
    return SOCKS5_STATE_REQUEST_WRITE;
  }
  if (socks->request_reply != SOCKS5_REPLY_SUCCEEDED) {
    return SOCKS5_STATE_DONE;
  }

  // log successful connection
  char dest_str[256];
  const char *dest_ptr = NULL;
  uint16_t dest_port =
    ((uint16_t) socks->request.port[0] << 8) | socks->request.port[1];
  if (socks->request.atyp == SOCKS5_ATYP_DOMAINNAME) {
    memcpy(dest_str, socks->request.address, socks->request.address_len);
    dest_str[socks->request.address_len] = '\0';
    dest_ptr = dest_str;
  } else if (socks->request.atyp == SOCKS5_ATYP_IPV4) {
    dest_ptr =
      inet_ntop(AF_INET, socks->request.address, dest_str, sizeof(dest_str));
  } else if (socks->request.atyp == SOCKS5_ATYP_IPV6) {
    dest_ptr =
      inet_ntop(AF_INET6, socks->request.address, dest_str, sizeof(dest_str));
  }
  access_log_add(socks->auth.uname, dest_ptr, dest_port);

  return start_relay(socks, key->s);
}

// Frees the SOCKS state once every owner has released its reference.
static void socks5_free(struct socks5 *socks) {
  if (socks->dns_result != NULL) {
    freeaddrinfo(socks->dns_result);
    socks->dns_result = NULL;
  }
  pthread_mutex_destroy(&socks->dns_mutex);
  free(socks);
}

static void client_unregister(struct socks5 *socks, fd_selector selector) {
  if (socks->client_registered && socks->client_fd >= 0) {
    const int fd = socks->client_fd;
    socks->client_registered = false;
    selector_unregister_fd(selector, fd);
  }
}

static void client_close(struct socks5 *socks, fd_selector selector) {
  const int fd = socks->client_fd;
  client_unregister(socks, selector);
  if (fd >= 0) {
    close(fd);
    if (socks->client_fd == fd) { socks->client_fd = -1; }
  }
}

static void origin_close(struct socks5 *socks, fd_selector selector) {
  if (socks->origin_registered && socks->origin_fd >= 0) {
    const int fd = socks->origin_fd;
    socks->origin_registered = false;
    selector_unregister_fd(selector, fd);
  }
  const int fd = socks->origin_fd;
  if (fd >= 0) {
    close(fd);
    if (socks->origin_fd == fd) { socks->origin_fd = -1; }
  }
}

void socks5_connection_close(struct socks5 *socks, fd_selector selector) {
  if (socks == NULL || socks->closing) { return; }

  socks->closing = true;
  socks5_cancel(socks);
  client_close(socks, selector);
  origin_close(socks, selector);
  socks5_release(socks);
}
