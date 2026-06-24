#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "selector.h"
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
  // TODO: drive the SOCKS5 state machine.
  selector_unregister_fd(key->s, key->fd);

  fprintf(stderr, "Read smth from fd=%d\n", key->fd);
  fprintf(stderr, "closing ...");
  close(key->fd);
}

static void socksv5_close(struct selector_key *key) { free(key->data); }

void socksv5_pool_destroy(void) {
  // TODO: liberar pool de conexiones
}
