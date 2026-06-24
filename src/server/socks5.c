#include "socks5.h"

#include <stdio.h>

socks5_action socks5_handle_read(
  struct selector_key *key, const uint8_t *data, ssize_t bytes
) {
  fprintf(stderr, "Read %zd bytes from fd=%d: \n", bytes, key->fd);
  fwrite(data, 1, bytes, stderr);
  fprintf(stderr, "\n");
  return SOCKS5_ACTION_WRITE;
}

socks5_action
socks5_handle_write(struct selector_key *key, const uint8_t **data, size_t *bytes) {
  static const uint8_t response[] = "received\n";
  (void) key;

  *data = response;
  *bytes = sizeof(response) - 1;
  return SOCKS5_ACTION_READ;
}
