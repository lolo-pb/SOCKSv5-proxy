#include "access_log_view.h"

#include <ncurses.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define ACCESS_LOG_REAPER_PATH "src/client/ui/reaper.txt"
#define ACCESS_LOG_FRAME_DELAY_MS 350
#define ACCESS_LOG_REAPER_MAX_SIZE 4096

struct ascii_art {
  char text[ACCESS_LOG_REAPER_MAX_SIZE];
  int rows;
  int cols;
};

static bool is_back_key(int ch) {
  return ch == 27 || ch == 'b' || ch == 'B' || ch == 'q' || ch == 'Q';
}

static bool is_up_key(int ch) { return ch == KEY_UP || ch == 'k' || ch == 'K'; }

static bool is_down_key(int ch) {
  return ch == KEY_DOWN || ch == 'j' || ch == 'J';
}

static int text_line_count(const char *text) {
  if (text[0] == '\0') return 0;

  int lines = 1;
  for (const char *p = text; *p != '\0'; p++) {
    if (*p == '\n' && *(p + 1) != '\0') lines++;
  }
  return lines;
}

static int log_entry_count(const char *text) {
  if (strcmp(text, "(empty log)\n") == 0 || strcmp(text, "(empty log)") == 0)
    return 0;
  return text_line_count(text);
}

static size_t utf8_columns(const char *s, size_t len) {
  size_t cols = 0;
  for (size_t i = 0; i < len; i++) {
    if (((unsigned char) s[i] & 0xC0) != 0x80) cols++;
  }
  return cols;
}

static void measure_art(struct ascii_art *art) {
  art->rows = 0;
  art->cols = 0;
  const char *line = art->text;
  while (*line != '\0') {
    const char *end = strchr(line, '\n');
    const size_t len = end == NULL ? strlen(line) : (size_t) (end - line);
    const int cols = (int) utf8_columns(line, len);
    if (cols > art->cols) art->cols = cols;
    art->rows++;
    if (end == NULL) break;
    line = end + 1;
  }
}

static bool load_ascii_art(struct ascii_art *art, const char *path) {
  FILE *f = fopen(path, "r");
  if (f == NULL) return false;

  size_t used = fread(art->text, 1, sizeof(art->text) - 1, f);
  art->text[used] = '\0';
  fclose(f);
  measure_art(art);
  return art->text[0] != '\0';
}

static void draw_scroll_box(int top, int left, int height, int width) {
  const int right = left + width;
  const int bottom = top + height - 1;
  const int body_left = left + 4;

  mvhline(top, left + 2, '_', width - 3);

  mvaddch(top + 1, left + 1, '/');
  mvaddch(top + 1, left + 3, '\\');
  mvhline(top + 1, left + 4, ' ', width - 6);
  mvaddch(top + 1, right - 1, '\\');

  mvaddch(top + 2, left, '|');
  mvaddch(top + 2, left + 4, '|');
  mvaddch(top + 2, right, '|');

  mvaddch(top + 3, left + 1, '\\');
  mvaddch(top + 3, left + 2, '_');
  mvaddch(top + 3, left + 3, '_');
  mvaddch(top + 3, body_left, '|');
  mvaddch(top + 3, right, '|');

  for (int y = top + 4; y < bottom - 2; y++) {
    mvaddch(y, body_left, '|');
    mvaddch(y, right, '|');
  }

  mvaddch(bottom - 2, body_left, '|');
  mvhline(bottom - 2, body_left + 3, '_', width - 7);
  mvaddch(bottom - 2, right, '|');

  mvaddch(bottom - 1, body_left, '|');
  mvaddch(bottom - 1, body_left + 1, ' ');
  mvaddch(bottom - 1, body_left + 2, '/');
  mvaddch(bottom - 1, body_left + 3, '_');
  mvaddch(bottom - 1, body_left + 4, '\\');
  mvhline(bottom - 1, body_left + 6, ' ', width - 8);
  mvaddch(bottom - 1, right + 1, '\\');

  mvaddch(bottom, body_left + 1, '\\');
  mvaddch(bottom, body_left + 2, '_');
  mvaddch(bottom, body_left + 3, '_');
  mvaddch(bottom, body_left + 4, '/');
  mvaddch(bottom, body_left + 5, '_');
  mvhline(bottom, body_left + 6, '_', width - 8);
  mvaddch(bottom, right + 1, '/');
}

static void draw_scroll_text(
  const char *text, int offset, int total_entries, int top, int left, int height,
  int width
) {
  const int body_top = top + 3;
  const int body_left = left + 5;
  const int body_rows = height - 6;
  const int log_rows = body_rows > 1 ? body_rows - 1 : 1;
  const int body_width = width - 9;
  int current = 0;
  int drawn = 0;
  const char *line = text;

  while (*line != '\0' && drawn < log_rows) {
    const char *end = strchr(line, '\n');
    const int len = end == NULL ? (int) strlen(line) : (int) (end - line);
    if (current >= offset) {
      mvaddnstr(
        body_top + drawn, body_left, line, len < body_width ? len : body_width
      );
      drawn++;
    }
    current++;
    if (end == NULL) break;
    line = end + 1;
  }

  const int last_visible =
    total_entries == 0 ? 0 : offset + drawn < total_entries ? offset + drawn
                                                           : total_entries;
  mvprintw(
    body_top + body_rows - 1, body_left, "Entries: %d    Last visible: %d",
    total_entries, last_visible
  );
}

static void draw_ascii_art(
  const struct ascii_art *art, int top, int left, int height, int width,
  int float_offset
) {
  if (art->text[0] == '\0' || height <= 0 || width <= 0) return;

  const int base_y = top + (height > art->rows ? (height - art->rows) / 2 : 0);
  const int start_y = base_y + float_offset;
  const int start_x = left + (width > art->cols ? (width - art->cols) / 2 : 0);
  const char *line = art->text;

  for (int y = start_y; *line != '\0' && y < top + height; y++) {
    const char *end = strchr(line, '\n');
    const int len = end == NULL ? (int) strlen(line) : (int) (end - line);
    if (y >= top) mvaddnstr(y, start_x, line, len);
    if (end == NULL) break;
    line = end + 1;
  }
}

static void draw_access_log_page(
  const char *text, int offset, const struct ascii_art *reaper, int frame
) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);
  erase();

  if (rows < 10 || cols < 60) {
    mvaddstr(0, 0, "terminal too small");
    refresh();
    return;
  }

  const int footer_row = rows - 1;
  const int left_width = (cols * 2) / 3;
  const int right_width = cols - left_width;
  const int scroll_height = rows - 2;
  const int scroll_width = left_width - 2;
  const int scroll_top = 0;
  const int scroll_left = 0;
  const int reaper_top = 0;
  const int reaper_left = left_width;
  const int reaper_height = rows - 2;
  const int reaper_width = right_width;
  const int float_offset =
    reaper_height > reaper->rows && (frame / 2) % 2 == 1 ? -1 : 0;

  draw_scroll_box(scroll_top, scroll_left, scroll_height, scroll_width);
  const int total_entries = log_entry_count(text);
  draw_scroll_text(
    text, offset, total_entries, scroll_top, scroll_left, scroll_height,
    scroll_width
  );
  draw_ascii_art(
    reaper, reaper_top, reaper_left, reaper_height, reaper_width, float_offset
  );

  mvaddnstr(
    footer_row, 0, "Up/Down/PgUp/PgDn: scroll    r: refresh    b/Esc: back",
    cols - 1
  );
  refresh();
}

void run_access_log_page(const struct ui_state *state) {
  char *text = ui_fetch_access_log_text(state->mon_fd);
  struct ascii_art reaper = {0};
  int offset = 0;
  int frame = 0;
  if (text == NULL) text = ui_copy_text("out of memory");
  if (text == NULL) return;
  load_ascii_art(&reaper, ACCESS_LOG_REAPER_PATH);

  keypad(stdscr, TRUE);
  timeout(ACCESS_LOG_FRAME_DELAY_MS);
  bool scroll_to_bottom = true;
  for (;;) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    (void) cols;
    const int body_rows = rows > 8 ? rows - 8 : 1;
    const int log_rows = body_rows > 1 ? body_rows - 1 : 1;
    const int max_offset =
      text_line_count(text) > log_rows ? text_line_count(text) - log_rows : 0;
    if (scroll_to_bottom) {
      offset = max_offset;
      scroll_to_bottom = false;
    }
    if (offset > max_offset) offset = max_offset;

    draw_access_log_page(text, offset, &reaper, frame);
    frame++;
    const int ch = getch();
    if (ch == ERR) continue;
    if (is_back_key(ch)) break;
    if (ch == KEY_RESIZE) continue;
    if (is_up_key(ch)) {
      if (offset > 0) offset--;
    } else if (is_down_key(ch)) {
      if (offset < max_offset) offset++;
    } else if (ch == KEY_PPAGE) {
      offset = offset > body_rows ? offset - body_rows : 0;
    } else if (ch == KEY_NPAGE) {
      offset += body_rows;
      if (offset > max_offset) offset = max_offset;
    } else if (ch == 'r' || ch == 'R') {
      char *fresh = ui_fetch_access_log_text(state->mon_fd);
      if (fresh != NULL) {
        free(text);
        text = fresh;
        scroll_to_bottom = true;
      }
    }
  }

  timeout(-1);
  free(text);
}
