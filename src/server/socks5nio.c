#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "buffer.h"
#include "selector.h"
#include "socks5.h"
#include "socks5nio.h"

static void socksv5_read(struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_close(struct selector_key *key);
static void
socksv5_apply_action(struct selector_key *key, socks5_action action);

static const struct fd_handler socksv5_handler = {
  .handle_read = socksv5_read,
  .handle_write = socksv5_write,
  .handle_block = NULL,
  .handle_close = socksv5_close,
};

void socksv5_init(struct socks5args *args) { socks5_set_args(args); }

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

  struct socks5 *state = malloc(sizeof(*state));
  if (state == NULL) {
    close(client);
    return;
  }
  socks5_init(state);

  selector_status ss =
    selector_register(key->s, client, &socksv5_handler, OP_READ, state);
  if (ss != SELECTOR_SUCCESS) {
    fprintf(
      stderr, "unable to register client fd=%d: %s\n", client,
      selector_error(ss)
    );
    free(state);
    close(client);
    return;
  }

  fprintf(stderr, "new connection fd=%d\n", client);
}

static void socksv5_read(struct selector_key *key) {
  struct socks5 *state = key->data;
  size_t count;
  uint8_t *ptr = buffer_write_ptr(&state->read_buffer, &count);
  const ssize_t bytes = read(key->fd, ptr, count);

  if (bytes <= 0) {// error or EOF
    selector_unregister_fd(key->s, key->fd);
    fprintf(stderr, "closing fd=%d ...\n", key->fd);
    close(key->fd);
    return;
  }

  buffer_write_adv(&state->read_buffer, bytes);
  const socks5_action action = socks5_handle_read(state, key);

  socksv5_apply_action(key, action);
}

static void socksv5_close(struct selector_key *key) { free(key->data); }

static void socksv5_write(struct selector_key *key) {
  struct socks5 *state = key->data;
  size_t count;
  uint8_t *ptr = buffer_read_ptr(&state->write_buffer, &count);
  const ssize_t bytes = write(key->fd, ptr, count);

  if (bytes <= 0) {
    selector_unregister_fd(key->s, key->fd);
    fprintf(stderr, "closing fd=%d ...\n", key->fd);
    close(key->fd);
    return;
  }

  buffer_read_adv(&state->write_buffer, bytes);
  const socks5_action action = socks5_handle_write(state, key);

  socksv5_apply_action(key, action);
}

/**
 * Sets the next action to wait for in the select
 */
static void
socksv5_apply_action(struct selector_key *key, const socks5_action action) {
  switch (action) {
    case SOCKS5_ACTION_READ:
      selector_set_interest_key(key, OP_READ);
      break;
    case SOCKS5_ACTION_WRITE:
      selector_set_interest_key(key, OP_WRITE);
      break;
    case SOCKS5_ACTION_CLOSE:
      selector_unregister_fd(key->s, key->fd);
      fprintf(stderr, "closing fd=%d ...\n", key->fd);
      close(key->fd);
      break;
  }
}

void socksv5_pool_destroy(void) {
  // TODO: liberar pool de conexiones
}
