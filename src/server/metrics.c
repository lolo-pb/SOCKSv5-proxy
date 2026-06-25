#include "metrics.h"

#include <string.h>

static struct metrics m;

void metrics_init(void) { memset(&m, 0, sizeof(m)); }

void metrics_connection_opened(void) {
  m.historic_connections++;
  m.current_connections++;
}

void metrics_connection_closed(void) { m.current_connections--; }

void metrics_add_bytes(uint64_t n) { m.bytes_transferred += n; }

const struct metrics *metrics_get(void) { return &m; }
