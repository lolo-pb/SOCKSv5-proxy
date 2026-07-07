#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "buffer.h"
#include "metrics.h"
#include "selector.h"
#include "socks5.h"
#include "socks5nio.h"

static void socksv5_read(struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_block_done(struct selector_key *key);
static void socksv5_close(struct selector_key *key);
static void
socksv5_apply_action(struct selector_key *key, socks5_action action);
static void socksv5_pool_add(struct socks5 *state);
static void socksv5_pool_remove(struct socks5 *state);
static bool socksv5_retryable_io_error(void);

static struct socks5 *socksv5_pool = NULL;
static size_t socksv5_pool_size = 0;

static const struct fd_handler socksv5_handler = {
  .handle_read = socksv5_read,
  .handle_write = socksv5_write,
  .handle_block_done = socksv5_block_done,
  .handle_close = socksv5_close,
};


void socksv5_passive_accept(struct selector_key *key) {
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  const int client =
    accept(key->fd, (struct sockaddr *) &client_addr, &client_addr_len);
  if (client == -1) return;

  if (selector_fd_set_nio(client) == -1) {
    close(client);
    return;
  }

  struct socks5 *state = calloc(1, sizeof(*state));
  if (state == NULL) {
    close(client);
    return;
  }
  socks5_init(state);
  socks5_set_client_fd(state, client);

  selector_status ss =
    selector_register(key->s, client, &socksv5_handler, OP_READ, state);
  if (ss != SELECTOR_SUCCESS) {
    fprintf(
      stderr, "unable to register client fd=%d: %s\n", client,
      selector_error(ss)
    );
    socks5_release(state);
    close(client);
    return;
  }
  state->client_registered = true;
  socksv5_pool_add(state);

  // fprintf(stderr, "new connection fd=%d\n", client);
}

static void socksv5_read(struct selector_key *key) {
  struct socks5 *state = key->data;
  if (socks5_is_relaying(state)) {
    socksv5_apply_action(key, socks5_relay_client_read(state, key));
    return;
  }

  size_t count;
  uint8_t *ptr = buffer_write_ptr(&state->read_buffer, &count);
  const ssize_t bytes = read(key->fd, ptr, count);

  if (bytes == 0) {// EOF
    socks5_connection_close(state, key->s);
    return;
  } else if (bytes < 0) {
    if (socksv5_retryable_io_error()) {
      selector_set_interest_key(key, OP_READ);
      return;
    }
    socks5_connection_close(state, key->s);
    return;
  }

  buffer_write_adv(&state->read_buffer, bytes);
  const socks5_action action = socks5_handle_read(state, key);

  socksv5_apply_action(key, action);
}

static void socksv5_close(struct selector_key *key) {
  struct socks5 *state = key->data;
  if (state->client_fd == key->fd) { state->client_registered = false; }
  socksv5_pool_remove(state);
  socks5_connection_close(state, key->s);
}

static void socksv5_block_done(struct selector_key *key) {
  struct socks5 *state = key->data;
  const socks5_action action = socks5_handle_block_done(state, key);

  socksv5_apply_action(key, action);
}

static void socksv5_write(struct selector_key *key) {
  struct socks5 *state = key->data;
  if (socks5_is_relaying(state)) {
    socksv5_apply_action(key, socks5_relay_client_write(state, key));
    return;
  }

  size_t count;
  uint8_t *ptr = buffer_read_ptr(&state->write_buffer, &count);
  const ssize_t bytes = write(key->fd, ptr, count);

  if (bytes == 0) {
    socks5_connection_close(state, key->s);
    return;
  } else if (bytes < 0) {
    if (socksv5_retryable_io_error()) {
      selector_set_interest_key(key, OP_WRITE);
      return;
    }
    socks5_connection_close(state, key->s);
    return;
  }

  buffer_read_adv(&state->write_buffer, bytes);
  if (buffer_can_read(&state->write_buffer)) {
    selector_set_interest_key(key, OP_WRITE);
    return;
  }

  const socks5_action action = socks5_handle_write(state, key);

  socksv5_apply_action(key, action);
}

/**
 * Sets the next action to wait for in the select
 */
static void
socksv5_apply_action(struct selector_key *key, const socks5_action action) {
  switch (action) {
    case SOCKS5_ACTION_NONE:
      break;
    case SOCKS5_ACTION_NOOP:
      selector_set_interest_key(key, OP_NOOP);
      break;
    case SOCKS5_ACTION_READ:
      selector_set_interest_key(key, OP_READ);
      break;
    case SOCKS5_ACTION_WRITE:
      selector_set_interest_key(key, OP_WRITE);
      break;
    case SOCKS5_ACTION_CLOSE:
      socks5_connection_close(key->data, key->s);
      break;
  }
}

// methods to add a socks thing to the list
static void socksv5_pool_add(struct socks5 *state) {
  state->pool_next = socksv5_pool;
  socksv5_pool = state;
  socksv5_pool_size++;
  metrics_connection_opened();
}

// methods to remove a socks thing to the list
static void socksv5_pool_remove(struct socks5 *state) {
  struct socks5 **current = &socksv5_pool;

  while (*current != NULL) {
    if (*current == state) {
      *current = state->pool_next;
      state->pool_next = NULL;
      socksv5_pool_size--;
      metrics_connection_closed();
      return;
    }
    current = &(*current)->pool_next;
  }
}

size_t socksv5_active_connections(void) { return socksv5_pool_size; }

void socksv5_pool_force_shutdown(fd_selector selector) {
  while (socksv5_pool != NULL) {
    struct socks5 *state = socksv5_pool;
    socks5_cancel(state);
    socks5_connection_close(state, selector);
    if (socksv5_pool == state) { socksv5_pool_remove(state); }
  }
}

void socksv5_pool_destroy(void) {
  if (socksv5_pool_size != 0) {
    fprintf(
      stderr, "warning: %zu SOCKS connections still tracked\n",
      socksv5_pool_size
    );
  }
}

static bool socksv5_retryable_io_error(void) {
  return errno == EAGAIN || errno == EWOULDBLOCK;
}
