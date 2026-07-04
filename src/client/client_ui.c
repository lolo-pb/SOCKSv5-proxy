#include "client_ui.h"

#include <locale.h>
#include <ncurses.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define INTRO_ANIMATION_PATH "src/client/ui/open_animation.txt"
#define MAX_FRAMES 32
#define MAX_FRAME_SIZE 8192
#define MAX_CREDENTIAL_LEN 255
#define FRAME_DELAY_MS 200

struct ui_state {
  char username[MAX_CREDENTIAL_LEN + 1];
  char password[MAX_CREDENTIAL_LEN + 1];
  bool authenticated;
};

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

static void play_intro(void) {
  char frames[MAX_FRAMES][MAX_FRAME_SIZE];
  const int frame_count = load_frames(frames);
  if (frame_count <= 0) {
    erase();
    mvaddstr(0, 0, "client: could not load intro animation");
    refresh();
    napms(1000);
    return;
  }

  for (int i = frame_count - 1; i >= 0; i--) {
    draw_frame(frames[i]);
    napms(FRAME_DELAY_MS);
  }
  napms(250);
}

static void draw_login_form(const struct ui_state *state, int field) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  const int width = 42;
  const int start_y = rows > 10 ? (rows - 10) / 2 : 0;
  const int start_x = cols > width ? (cols - width) / 2 : 0;

  erase();
  mvaddstr(start_y, start_x, "SOCKS5 Manager");
  mvhline(start_y + 1, start_x, ACS_HLINE, width);

  mvaddstr(start_y + 3, start_x, field == 0 ? "> Username: " : "  Username: ");
  addnstr(state->username, MAX_CREDENTIAL_LEN);

  mvaddstr(start_y + 5, start_x, field == 1 ? "> Password: " : "  Password: ");
  for (size_t i = 0; i < strlen(state->password); i++) addch('*');

  mvaddstr(start_y + 8, start_x, "Enter: next/login    Esc: quit");
  refresh();
}

static bool append_char(char *dst, int ch) {
  const size_t len = strlen(dst);
  if (len >= MAX_CREDENTIAL_LEN) return false;
  dst[len] = (char) ch;
  dst[len + 1] = '\0';
  return true;
}

static void delete_char(char *dst) {
  const size_t len = strlen(dst);
  if (len > 0) dst[len - 1] = '\0';
}

static bool run_login(struct ui_state *state) {
  int field = 0;
  keypad(stdscr, TRUE);

  for (;;) {
    draw_login_form(state, field);
    const int ch = getch();

    if (ch == 27) return false;
    if (ch == KEY_RESIZE) continue;
    if (ch == '\t' || ch == KEY_DOWN || ch == KEY_UP) {
      field = 1 - field;
      continue;
    }
    if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
      if (field == 0) {
        field = 1;
      } else if (state->username[0] != '\0' && state->password[0] != '\0') {
        state->authenticated = true;
        return true;
      }
      continue;
    }
    if (ch == KEY_BACKSPACE || ch == 127 || ch == '\b') {
      delete_char(field == 0 ? state->username : state->password);
      continue;
    }
    if (ch >= 32 && ch <= 126) {
      append_char(field == 0 ? state->username : state->password, ch);
    }
  }
}

static void show_logged_in(const struct ui_state *state) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  erase();
  mvaddstr(rows / 2 - 1, (cols - 16) / 2, "SOCKS5 Manager");
  mvprintw(rows / 2 + 1, (cols - 18) / 2, "Logged in as %s", state->username);
  mvaddstr(rows / 2 + 3, (cols - 18) / 2, "Press any key");
  refresh();
  getch();
}

int client_ui_run(const struct client_args *args) {
  struct ui_state state;
  memset(&state, 0, sizeof(state));
  if (args->username != NULL && args->password != NULL) {
    strncpy(state.username, args->username, MAX_CREDENTIAL_LEN);
    strncpy(state.password, args->password, MAX_CREDENTIAL_LEN);
    state.authenticated = true;
  }

  setlocale(LC_ALL, "");
  initscr();
  cbreak();
  noecho();
  curs_set(0);

  play_intro();
  if (!state.authenticated && !run_login(&state)) {
    endwin();
    return 0;
  }
  show_logged_in(&state);

  endwin();
  return 0;
}
