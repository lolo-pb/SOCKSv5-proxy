#include "intro_animation.h"

#include <ncurses.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define INTRO_ANIMATION_PATH "src/client/ui/open_animation.txt"
#define MAX_FRAMES 32
#define MAX_FRAME_SIZE 8192
#define FRAME_DELAY_MS 150

static size_t utf8_columns(const char *s, size_t len) {
  size_t cols = 0;
  for (size_t i = 0; i < len; i++) {
    if (((unsigned char) s[i] & 0xC0) != 0x80) cols++;
  }
  return cols;
}

static void draw_frame(const char *frame) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  int frame_rows = 0;
  size_t max_cols = 0;
  const char *line = frame;
  while (*line != '\0') {
    const char *end = strchr(line, '\n');
    const size_t len = end == NULL ? strlen(line) : (size_t) (end - line);
    const size_t line_cols = utf8_columns(line, len);
    if (line_cols > max_cols) max_cols = line_cols;
    frame_rows++;
    if (end == NULL) break;
    line = end + 1;
  }

  const int start_y = frame_rows < rows ? (rows - frame_rows) / 2 : 0;
  const int start_x = (int) max_cols < cols ? (cols - (int) max_cols) / 2 : 0;

  erase();
  line = frame;
  for (int y = start_y; *line != '\0' && y < rows; y++) {
    const char *end = strchr(line, '\n');
    const int len = end == NULL ? (int) strlen(line) : (int) (end - line);
    mvaddnstr(y, start_x, line, len);
    if (end == NULL) break;
    line = end + 1;
  }
  refresh();
}

static int load_frames(char frames[MAX_FRAMES][MAX_FRAME_SIZE]) {
  FILE *f = fopen(INTRO_ANIMATION_PATH, "r");
  if (f == NULL) return -1;

  int frame_count = 0;
  size_t offset = 0;
  char line[1024];
  while (fgets(line, sizeof(line), f) != NULL && frame_count < MAX_FRAMES) {
    if (strcmp(line, "#\n") == 0 || strcmp(line, "#\r\n") == 0) {
      frames[frame_count][offset] = '\0';
      frame_count++;
      offset = 0;
      continue;
    }

    const size_t len = strlen(line);
    if (offset + len + 1 >= MAX_FRAME_SIZE) continue;
    memcpy(frames[frame_count] + offset, line, len);
    offset += len;
  }

  if (offset > 0 && frame_count < MAX_FRAMES) {
    frames[frame_count][offset] = '\0';
    frame_count++;
  }

  fclose(f);
  return frame_count;
}

static void play_intro_animation(bool reverse) {
  char frames[MAX_FRAMES][MAX_FRAME_SIZE];
  const int frame_count = load_frames(frames);
  if (frame_count <= 0) {
    erase();
    mvaddstr(0, 0, "client: could not load intro animation");
    refresh();
    napms(1000);
    return;
  }

  nodelay(stdscr, TRUE);
  if (reverse) {
    for (int i = 0; i < frame_count; i++) {
      if (getch() != ERR) break;
      draw_frame(frames[i]);
      napms(FRAME_DELAY_MS);
    }
  } else {
    for (int i = frame_count - 1; i >= 0; i--) {
      if (getch() != ERR) break;
      draw_frame(frames[i]);
      napms(FRAME_DELAY_MS);
    }
  }
  nodelay(stdscr, FALSE);
  napms(250);
}

void play_intro(void) { play_intro_animation(false); }

void play_outro(void) { play_intro_animation(true); }
