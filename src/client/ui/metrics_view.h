#ifndef METRICS_VIEW_H
#define METRICS_VIEW_H

#include <stdint.h>

struct metrics_view_data {
  uint64_t historic_connections;
  uint64_t current_connections;
  uint64_t bytes_transferred;
};

#define METRICS_GRAPH_MAX_POINTS 256

struct metrics_graph {
  uint64_t values[METRICS_GRAPH_MAX_POINTS];
  unsigned count;
  unsigned next_time_sec;
};

void metrics_view_init_colors(void);
void metrics_graph_init(struct metrics_graph *graph);
void metrics_graph_record(struct metrics_graph *graph, uint64_t current_connections);
void draw_metrics_view(
  const struct metrics_view_data *metrics, const char *access_log,
  int access_log_offset, const struct metrics_graph *graph
);

#endif
