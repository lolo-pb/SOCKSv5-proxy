#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "selector.h"
#include "socks5.h"
#include "socks5nio.h"

struct socksv5 {
  int client_fd;
};

static void socksv5_read(struct selector_key *key);
static void socksv5_close(struct selector_key *key);

static const struct fd_handler socksv5_handler = {
  .handle_read = socksv5_read,
  .handle_write = NULL,
  .handle_block = NULL,
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

  struct socksv5 *state = malloc(sizeof(*state));
  if (state == NULL) {
    close(client);
    return;
  }
  memset(state, 0, sizeof(*state));
  state->client_fd = client;

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
  uint8_t buffer[1024];// TODO : check size curr 1024 bytes
  const ssize_t bytes = read(key->fd, buffer, sizeof(buffer));

  if (bytes <= 0) {// error or EOF
    selector_unregister_fd(key->s, key->fd);
    fprintf(stderr, "closing ...\n");
    close(key->fd);
    return;
  }

  const socks5_action action = socks5_handle_read(key, buffer, bytes);

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

static void socksv5_close(struct selector_key *key) { free(key->data); }

void socksv5_pool_destroy(void) {
  // TODO: liberar pool de conexiones
}
