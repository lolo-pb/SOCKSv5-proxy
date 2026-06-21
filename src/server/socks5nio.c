#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "selector.h"
#include "socks5nio.h"

void socksv5_passive_accept(struct selector_key *key) {
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  const int client =
    accept(key->fd, (struct sockaddr *) &client_addr, &client_addr_len);
  if (client == -1) return;

  // acepta y cierra inmediatamente
  // TODO: inicializar STM y registrar en selector
  fprintf(stderr, "new connection fd=%d\n", client);
  close(client);
}

void socksv5_pool_destroy(void) {
  // TODO: liberar pool de conexiones
}
