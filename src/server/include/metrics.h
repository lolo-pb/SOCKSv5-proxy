#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

struct metrics {
  uint64_t historic_connections;
  uint64_t current_connections;
  uint64_t bytes_transferred;
};

void metrics_init(void);
void metrics_connection_opened(void);
void metrics_connection_closed(void);
void metrics_add_bytes(uint64_t n);
const struct metrics *metrics_get(void);

#endif
