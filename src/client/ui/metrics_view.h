#ifndef METRICS_VIEW_H
#define METRICS_VIEW_H

#include <stdint.h>

struct metrics_view_data {
  uint64_t historic_connections;
  uint64_t current_connections;
  uint64_t bytes_transferred;
};

void draw_metrics_view(
  const struct metrics_view_data *metrics, const char *access_log,
  int access_log_offset
);

#endif
