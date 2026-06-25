#include <assert.h>
#include <stdio.h>

#include "metrics.c"

int main(void) {
  metrics_init();
  const struct metrics *m = metrics_get();
  assert(m->historic_connections == 0);
  assert(m->current_connections == 0);
  assert(m->bytes_transferred == 0);

  metrics_connection_opened();
  metrics_connection_opened();
  assert(m->historic_connections == 2);
  assert(m->current_connections == 2);

  metrics_connection_closed();
  assert(m->current_connections == 1);
  assert(m->historic_connections == 2);

  metrics_add_bytes(100);
  metrics_add_bytes(50);
  assert(m->bytes_transferred == 150);

  printf("metrics: all tests passed\n");
  return 0;
}
