#include "socks5.h"

#include <stdio.h>

socks5_action socks5_handle_read(struct selector_key *key) {
  fprintf(stderr, "Read smth from fd=%d\n", key->fd);
  return SOCKS5_ACTION_CLOSE;
}
