#include "metrics_view.h"

#include <inttypes.h>
#include <ncurses.h>
#include <stdio.h>
#include <string.h>

#define METRICS_COLOR_BAR_GREEN 1
#define METRICS_COLOR_BAR_YELLOW 2
#define METRICS_COLOR_BAR_RED 3
#define METRICS_COLOR_LOG_NAME 4
#define METRICS_COLOR_GRAPH_POINT 5

void metrics_view_init_colors(void) {
  if (!has_colors()) return;

  start_color();
  use_default_colors();
  init_pair(METRICS_COLOR_BAR_GREEN, COLOR_GREEN, -1);
  init_pair(METRICS_COLOR_BAR_YELLOW, COLOR_YELLOW, -1);
  init_pair(METRICS_COLOR_BAR_RED, COLOR_RED, -1);
  init_pair(METRICS_COLOR_LOG_NAME, COLOR_CYAN, -1);
  init_pair(METRICS_COLOR_GRAPH_POINT, COLOR_MAGENTA, -1);
}

void metrics_graph_init(struct metrics_graph *graph) {
  memset(graph, 0, sizeof(*graph));
}

void metrics_graph_record(struct metrics_graph *graph, uint64_t current_connections) {
  if (graph->count < METRICS_GRAPH_MAX_POINTS) {
    graph->values[graph->count++] = current_connections;
  } else {
    memmove(
      graph->values, graph->values + 1,
      sizeof(graph->values[0]) * (METRICS_GRAPH_MAX_POINTS - 1)
    );
    graph->values[METRICS_GRAPH_MAX_POINTS - 1] = current_connections;
  }
  graph->next_time_sec += 1;
}

static void graph_y_bounds(
  const struct metrics_graph *graph, unsigned first, unsigned visible,
  int plot_height, uint64_t *y_min, uint64_t *y_max
) {
  uint64_t min = graph->values[first];
  uint64_t max = min;
  for (unsigned i = 1; i < visible; i++) {
    const uint64_t value = graph->values[first + i];
    if (value < min) min = value;
    if (value > max) max = value;
  }

  const uint64_t span = (uint64_t) plot_height;
  if (min == max) {
    *y_min = min >= span / 2 ? min - span / 2 : 0;
    *y_max = *y_min + span - 1;
    return;
  }

  const uint64_t padding = (max - min) / 10 + 1;
  *y_min = min > padding ? min - padding : 0;
  *y_max = max + padding;
  if (*y_max <= *y_min) *y_max = *y_min + 1;
}

static int graph_y_for_value(
  uint64_t value, uint64_t y_min, uint64_t y_max, int plot_top, int plot_height
) {
  const uint64_t range = y_max - y_min;
  const uint64_t offset = y_max - value;
  return plot_top +
         (int) ((offset * (uint64_t) (plot_height - 1) + range / 2) / range);
}

static int line_count(const char *text) {
  int count = 1;
  for (const char *p = text; p != NULL && *p != '\0'; p++) {
    if (*p == '\n') count++;
  }
  return count;
}

static const char *line_at(const char *text, int idx, int *len) {
  const char *line = text;
  for (int i = 0; i < idx && line != NULL && *line != '\0'; i++) {
    line = strchr(line, '\n');
    if (line != NULL) line++;
  }

  if (line == NULL || *line == '\0') {
    *len = 0;
    return "";
  }

  const char *end = strchr(line, '\n');
  *len = end == NULL ? (int) strlen(line) : (int) (end - line);
  return line;
}

static void draw_access_log_line(int y, int x, int width, const char *line, int len) {
  char buf[256];
  const int copy_len = len < (int) sizeof(buf) - 1 ? len : (int) sizeof(buf) - 1;
  memcpy(buf, line, (size_t) copy_len);
  buf[copy_len] = '\0';

  char timestamp[32];
  char user[64];
  if (sscanf(buf, "%31s %63s", timestamp, user) == 2) {
    if (strlen(timestamp) > 10 && timestamp[10] == 'T') timestamp[10] = ' ';
    mvprintw(y, x, "%.*s  ", 19, timestamp);
    attron(COLOR_PAIR(METRICS_COLOR_LOG_NAME));
    addnstr(user, width > 21 ? width - 21 : 0);
    attroff(COLOR_PAIR(METRICS_COLOR_LOG_NAME));
  } else {
    mvaddnstr(y, x, line, len < width ? len : width);
  }
}

static void draw_box(int top, int left, int height, int width, const char *title) {
  mvaddch(top, left, '+');
  mvhline(top, left + 1, '-', width - 2);
  mvaddch(top, left + width - 1, '+');
  mvvline(top + 1, left, '|', height - 2);
  mvvline(top + 1, left + width - 1, '|', height - 2);
  mvaddch(top + height - 1, left, '+');
  mvhline(top + height - 1, left + 1, '-', width - 2);
  mvaddch(top + height - 1, left + width - 1, '+');

  if (title != NULL) mvaddnstr(top, left + 2, title, width - 4);
}

static void draw_access_log(
  int top, int left, int height, int width, const char *text, int offset
) {
  draw_box(top, left, height, width, "Access Log");

  const int body_rows = height - 2;
  const int body_width = width - 2;
  const int lines = line_count(text);
  const int max_start = lines > body_rows ? lines - body_rows : 0;
  const int start = offset < max_start ? offset : max_start;

  for (int i = 0; i < body_rows; i++) {
    int len;
    const char *line = line_at(text, start + i, &len);
    draw_access_log_line(top + 1 + i, left + 1, body_width, line, len);
  }
}

static void draw_graph_space(
  int top, int left, int height, int width, const struct metrics_graph *graph,
  uint64_t current_connections
) {
  draw_box(top, left, height, width, "Current Connections");

  int rows, cols;
  getmaxyx(stdscr, rows, cols);
  (void) cols;

  const int plot_top = top + 2;
  const int axis_col = left + 5;
  const int plot_left = axis_col + 1;
  const int plot_height = height - 5;
  const int plot_width = width - 8;
  const int axis_y = plot_top + plot_height;
  if (plot_height < 2 || plot_width < 4) {
    mvprintw(top + 1, left + 2, "current: %" PRIu64, current_connections);
    return;
  }

  const unsigned visible =
    graph != NULL && graph->count < (unsigned) plot_width
      ? graph->count
      : (unsigned) plot_width;
  const unsigned first = graph != NULL ? graph->count - visible : 0;

  uint64_t y_min;
  uint64_t y_max;
  if (graph != NULL && visible > 0) {
    graph_y_bounds(graph, first, visible, plot_height, &y_min, &y_max);
  } else {
    const uint64_t y_span = (uint64_t) plot_height;
    y_min = current_connections >= y_span ? current_connections - y_span + 1 : 0;
    y_max = y_min + y_span - 1;
  }
  const uint64_t y_range = y_max - y_min;

  for (int row = 0; row < plot_height; row++) {
    const uint64_t y_value =
      y_max - ((uint64_t) row * y_range) / (uint64_t) (plot_height - 1);
    mvprintw(plot_top + row, left + 1, "%4" PRIu64 "|", y_value);
  }

  mvaddch(axis_y, axis_col, '+');
  mvhline(axis_y, plot_left, '-', plot_width);

  if (axis_y + 1 < rows - 1) mvaddstr(axis_y + 1, left + 1, "time");

  if (graph == NULL || graph->count == 0) return;
  const unsigned first_time = graph->next_time_sec - graph->count;

  for (unsigned i = 0; i < visible; i++) {
    const uint64_t value = graph->values[first + i];
    if (value < y_min || value > y_max) continue;

    const int x = plot_left + plot_width - (int) visible + (int) i;
    const int y = graph_y_for_value(value, y_min, y_max, plot_top, plot_height);
    attron(COLOR_PAIR(METRICS_COLOR_GRAPH_POINT));
    mvaddch(y, x, '*');
    attroff(COLOR_PAIR(METRICS_COLOR_GRAPH_POINT));
  }

  if (axis_y + 1 >= rows - 1) return;

  for (unsigned i = 0; i < visible; i++) {
    const unsigned sample_time = first_time + first + i;
    if (sample_time % 10 != 0) continue;

    const int x = plot_left + plot_width - (int) visible + (int) i;
    if (x + 1 >= left + width - 1) continue;
    mvprintw(axis_y + 1, x, "%02u", sample_time % 100);
  }
}

static void draw_bar_row(
  int y, int x, int width, const char *label, uint64_t value
) {
  const int label_width = 10;
  const int prefix_width = label_width + 3;
  const int bar_width = width - prefix_width;
  int filled = bar_width > 0 ? (int) ((value % 1000) * bar_width / 1000) : 0;
  if (value > 0 && filled == 0 && bar_width > 0) filled = 1;

  mvprintw(y, x, "%-*s : ", label_width, label);
  for (int i = 0; i < bar_width; i++) {
    if (i >= filled) {
      addch(' ');
      continue;
    }

    const int color = i < bar_width / 3
                        ? METRICS_COLOR_BAR_GREEN
                        : (i < (bar_width * 2) / 3 ? METRICS_COLOR_BAR_YELLOW
                                                   : METRICS_COLOR_BAR_RED);
    attron(COLOR_PAIR(color));
    addch('#');
    attroff(COLOR_PAIR(color));
  }
}

static void draw_counters(
  int top, int left, int height, int width, const struct metrics_view_data *metrics
) {
  draw_box(top, left, height, width, "Totals");

  const int x = left + 2;
  const int row_width = width - 4;
  const int last_content_row = top + height - 2;
  const uint64_t bytes = metrics->bytes_transferred;
  const uint64_t kilobytes = bytes / 1000;
  const uint64_t megabytes = kilobytes / 1000;
  const uint64_t gigabytes = megabytes / 1000;

  if (top + 1 <= last_content_row)
    mvprintw(
      top + 1, x, "Historic connections: %" PRIu64,
      metrics->historic_connections
    );
  if (top + 2 <= last_content_row)
    mvprintw(top + 2, x, "Total bytes sent:    %" PRIu64, bytes);
  if (top + 4 <= last_content_row) draw_bar_row(top + 4, x, row_width, "Bytes", bytes);
  if (top + 5 <= last_content_row)
    draw_bar_row(top + 5, x, row_width, "KiloBytes", kilobytes);
  if (top + 6 <= last_content_row)
    draw_bar_row(top + 6, x, row_width, "MegaBytes", megabytes);
  if (top + 7 <= last_content_row)
    draw_bar_row(top + 7, x, row_width, "GigaBytes", gigabytes);
}

void draw_metrics_view(
  const struct metrics_view_data *metrics, const char *access_log,
  int access_log_offset, const struct metrics_graph *graph
) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  erase();
  if (rows < 12 || cols < 60) {
    mvaddstr(0, 0, "terminal too small");
    refresh();
    return;
  }

  const int footer_row = rows - 1;
  const int content_height = rows - 1;
  const int left_width = cols / 3;
  const int right_width = cols - left_width;
  const int graph_height = content_height * 2 / 3;
  const int totals_height = content_height - graph_height;

  draw_access_log(0, 0, content_height, left_width, access_log, access_log_offset);
  draw_graph_space(
    0, left_width, graph_height, right_width, graph,
    metrics->current_connections
  );
  draw_counters(graph_height, left_width, totals_height, right_width, metrics);

  mvaddnstr(
    footer_row, 0, "Auto-refresh: 1s    r: refresh now    b/Esc: back",
    cols - 1
  );
  refresh();
}
