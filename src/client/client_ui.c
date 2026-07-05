#include "client_ui.h"

#include <limits.h>
#include <locale.h>
#include <ncurses.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ui/intro_animation.h"
#include "ui/metrics_view.h"
#include "ui/menu_animation.h"
#include "ui/ui_mng_session.h"
#include "mng_client.h"
#include "mon_protocol.h"

#define METRICS_REFRESH_MS 1000

static bool is_enter_key(int ch) {
  return ch == '\n' || ch == '\r' || ch == KEY_ENTER;
}

static bool is_back_key(int ch) {
  return ch == 27 || ch == 'b' || ch == 'B' || ch == 'q' || ch == 'Q';
}

static bool is_backspace_key(int ch) {
  return ch == KEY_BACKSPACE || ch == 127 || ch == '\b';
}

static bool is_up_key(int ch) {
  return ch == KEY_UP || ch == 'k' || ch == 'K';
}

static bool is_down_key(int ch) {
  return ch == KEY_DOWN || ch == 'j' || ch == 'J';
}

static bool is_printable_ascii(int ch) {
  return ch >= 32 && ch <= 126;
}

static int previous_menu_index(int selected, int item_count) {
  return selected == 0 ? item_count - 1 : selected - 1;
}

static int next_menu_index(int selected, int item_count) {
  return selected == item_count - 1 ? 0 : selected + 1;
}

static void draw_login_form(const struct ui_state *state, int field) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  const int box_width = cols < 42 ? cols : 42;
  const int box_height = rows < 13 ? rows : 13;
  if (box_width < 4 || box_height < 4) {
    erase();
    mvaddstr(0, 0, "terminal too small");
    refresh();
    return;
  }

  const int top = rows > box_height ? (rows - box_height) / 2 : 0;
  const int left = cols > box_width ? (cols - box_width) / 2 : 0;
  const int start_y = top + 2;
  const int start_x = left + 2;
  const int content_width = box_width - 4;

  erase();
  mvaddstr(start_y, start_x, "SOCKS5 Manager");
  mvhline(start_y + 1, start_x, ACS_HLINE, content_width);

  mvaddstr(start_y + 3, start_x, field == 0 ? "> Username: " : "  Username: ");
  addnstr(state->username, MAX_CREDENTIAL_LEN);

  mvaddstr(start_y + 5, start_x, field == 1 ? "> Password: " : "  Password: ");
  for (size_t i = 0; i < strlen(state->password); i++) addch('*');

  mvaddstr(start_y + 8, start_x, "Enter: next/login    Esc: quit");
  if (state->status[0] != '\0')
    mvaddnstr(start_y + 9, start_x, state->status, content_width);
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
    if (is_enter_key(ch)) {
      if (field == 0) {
        field = 1;
      } else if (state->username[0] != '\0' && state->password[0] != '\0') {
        snprintf(state->status, sizeof(state->status), "authenticating...");
        draw_login_form(state, field);
        if (ui_authenticate(state)) return true;
      }
      continue;
    }
    if (is_backspace_key(ch)) {
      delete_char(field == 0 ? state->username : state->password);
      continue;
    }
    if (is_printable_ascii(ch)) {
      append_char(field == 0 ? state->username : state->password, ch);
    }
  }
}

static int text_line_count(const char *text) {
  int lines = 1;
  for (const char *p = text; *p != '\0'; p++) {
    if (*p == '\n') lines++;
  }
  return lines;
}

static void draw_text_screen_with_footer(
  const char *title, const char *text, int offset, const char *footer
) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  erase();
  mvaddnstr(0, 0, title, cols - 1);
  mvhline(1, 0, ACS_HLINE, cols);

  const int body_rows = rows > 4 ? rows - 4 : 0;
  int current = 0;
  int drawn = 0;
  const char *line = text;
  while (*line != '\0' && drawn < body_rows) {
    const char *end = strchr(line, '\n');
    const int len = end == NULL ? (int) strlen(line) : (int) (end - line);
    if (current >= offset) {
      mvaddnstr(2 + drawn, 0, line, len < cols ? len : cols - 1);
      drawn++;
    }
    current++;
    if (end == NULL) break;
    line = end + 1;
  }

  mvaddnstr(rows - 1, 0, footer, cols - 1);
  refresh();
}

static void draw_text_screen(const char *title, const char *text, int offset) {
  draw_text_screen_with_footer(
    title, text, offset, "Up/Down/PgUp/PgDn: scroll    b/Esc: back"
  );
}

static void show_text_screen(const char *title, const char *text) {
  int offset = 0;
  keypad(stdscr, TRUE);

  for (;;) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    (void) cols;
    const int body_rows = rows > 4 ? rows - 4 : 1;
    const int max_offset = text_line_count(text) > body_rows
                             ? text_line_count(text) - body_rows
                             : 0;
    if (offset > max_offset) offset = max_offset;

    draw_text_screen(title, text, offset);
    const int ch = getch();
    if (is_back_key(ch)) return;
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
    }
  }
}

static void show_message_screen(const char *title, const char *message) {
  show_text_screen(title, message);
}

static void fetch_and_show(
  const struct ui_state *state, uint8_t cmd, const char *title,
  payload_formatter formatter
) {
  struct ui_response resp;
  char message[STATUS_LEN];
  if (!ui_run_command(state, cmd, 0, NULL, NULL, &resp, message, sizeof(message))) {
    show_message_screen(title, message);
    return;
  }

  char *text = ui_format_payload(&resp, formatter);
  if (text == NULL) {
    show_message_screen(title, "Malformed server response");
    return;
  }

  show_text_screen(title, text);
  free(text);
}

static void show_live_metrics(const struct ui_state *state) {
  if (state->mng_fd < 0) {
    show_message_screen("Metrics", "not connected");
    return;
  }

  keypad(stdscr, TRUE);
  timeout(METRICS_REFRESH_MS);
  const int access_log_offset = INT_MAX;
  unsigned metrics_updates = 0;
  struct metrics_graph graph;
  metrics_graph_init(&graph);

  for (;;) {
    struct metrics_view_data metrics = {0};
    char *access_log = ui_fetch_access_log_text(state->mng_fd);
    if (access_log == NULL) access_log = ui_copy_text("out of memory");
    if (!ui_fetch_metrics_data(state->mng_fd, &metrics)) {
      free(access_log);
      timeout(-1);
      show_message_screen("Metrics", "metrics request failed");
      return;
    }

    metrics_updates++;
    if (metrics_updates % 2 == 0)
      metrics_graph_record(&graph, metrics.current_connections);

    draw_metrics_view(
      &metrics, access_log != NULL ? access_log : "", access_log_offset, &graph
    );
    free(access_log);

    const int ch = getch();
    if (is_back_key(ch)) {
      timeout(-1);
      return;
    }
    if (ch == ERR || ch == KEY_RESIZE || ch == 'r' || ch == 'R') continue;
  }
}

static void draw_user_form(
  const char *title, const char *user, const char *pass, int field,
  bool password_required, const char *message
) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  const int width = 48;
  const int height = password_required ? 12 : 10;
  const int start_y = rows > height ? (rows - height) / 2 : 0;
  const int start_x = cols > width ? (cols - width) / 2 : 0;

  erase();
  mvaddstr(start_y, start_x, title);
  mvhline(start_y + 1, start_x, ACS_HLINE, width);

  mvaddstr(start_y + 3, start_x, field == 0 ? "> Username: " : "  Username: ");
  addnstr(user, MAX_CREDENTIAL_LEN);

  if (password_required) {
    mvaddstr(start_y + 5, start_x, field == 1 ? "> Password: " : "  Password: ");
    for (size_t i = 0; i < strlen(pass); i++) addch('*');
  }

  mvaddstr(
    start_y + (password_required ? 8 : 6), start_x,
    "Enter: submit/next    Tab: switch    Esc: cancel"
  );
  if (message != NULL && message[0] != '\0')
    mvaddnstr(start_y + (password_required ? 10 : 8), start_x, message, width);
  refresh();
}

static bool run_user_form(
  const char *title, char *user, char *pass, bool password_required
) {
  int field = 0;
  char message[STATUS_LEN] = "";
  user[0] = '\0';
  pass[0] = '\0';
  keypad(stdscr, TRUE);

  for (;;) {
    draw_user_form(title, user, pass, field, password_required, message);
    const int ch = getch();

    if (ch == 27) return false;
    if (ch == KEY_RESIZE) continue;
    if (ch == '\t' || ch == KEY_DOWN || ch == KEY_UP) {
      if (password_required) field = 1 - field;
      continue;
    }
    if (is_backspace_key(ch)) {
      delete_char(field == 0 ? user : pass);
      continue;
    }
    if (is_enter_key(ch)) {
      if (password_required && field == 0) {
        field = 1;
        continue;
      }
      if (user[0] == '\0' || (password_required && pass[0] == '\0')) {
        snprintf(message, sizeof(message), "all fields are required");
        continue;
      }
      return true;
    }
    if (is_printable_ascii(ch)) append_char(field == 0 ? user : pass, ch);
  }
}

static void user_command(
  const struct ui_state *state, uint8_t cmd, const char *user, const char *pass
) {
  struct ui_response resp;
  char message[STATUS_LEN];
  unsigned nargs = cmd == MON_CMD_ADD_USER ? 2 : 1;
  ui_run_command(state, cmd, nargs, user, pass, &resp, message, sizeof(message));
  show_message_screen("Users", message);
}

enum {
  USERS_MENU_LIST,
  USERS_MENU_ADD,
  USERS_MENU_DELETE,
  USERS_MENU_BACK,
  USERS_MENU_COUNT
};

static void draw_users_menu(int selected, const char *message) {
  static const char *items[] = {"List Users", "Add User", "Delete User", "Back"};

  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  const int width = 42;
  const int start_y = rows > 14 ? (rows - 14) / 2 : 0;
  const int start_x = cols > width ? (cols - width) / 2 : 0;

  erase();
  mvaddstr(start_y, start_x, "Users");
  mvhline(start_y + 1, start_x, ACS_HLINE, width);
  for (int i = 0; i < USERS_MENU_COUNT; i++) {
    mvprintw(
      start_y + 3 + i, start_x, "%s %s", selected == i ? ">" : " ", items[i]
    );
  }
  mvaddstr(start_y + 9, start_x, "Enter: select    b/Esc: back");
  if (message != NULL && message[0] != '\0')
    mvaddnstr(start_y + 10, start_x, message, width);
  refresh();
}

static void run_users_menu(const struct ui_state *state) {
  int selected = 0;
  const char *message = "";
  keypad(stdscr, TRUE);

  for (;;) {
    draw_users_menu(selected, message);
    const int ch = getch();

    if (is_back_key(ch)) return;
    if (ch == KEY_RESIZE) continue;
    if (is_up_key(ch)) {
      selected = previous_menu_index(selected, USERS_MENU_COUNT);
      message = "";
      continue;
    }
    if (is_down_key(ch)) {
      selected = next_menu_index(selected, USERS_MENU_COUNT);
      message = "";
      continue;
    }
    if (is_enter_key(ch)) {
      char user[MAX_CREDENTIAL_LEN + 1];
      char pass[MAX_CREDENTIAL_LEN + 1];
      if (selected == USERS_MENU_LIST) {
        fetch_and_show(state, MON_CMD_LIST_USERS, "Users", mng_format_users);
      } else if (selected == USERS_MENU_ADD) {
        if (run_user_form("Add User", user, pass, true))
          user_command(state, MON_CMD_ADD_USER, user, pass);
      } else if (selected == USERS_MENU_DELETE) {
        if (run_user_form("Delete User", user, pass, false))
          user_command(state, MON_CMD_DEL_USER, user, NULL);
      } else {
        return;
      }
    }
  }
}

enum {
  MAIN_MENU_METRICS,
  MAIN_MENU_USERS,
  MAIN_MENU_ACCESS_LOG,
  MAIN_MENU_QUIT,
  MAIN_MENU_COUNT
};

static void draw_main_menu(
  const struct ui_state *state, int selected, const char *message
) {
  static const char *items[] = {"Metrics", "Users", "Access Log", "Quit"};

  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  const int box_width = cols < 42 ? cols : 42;
  const int box_height = rows < 16 ? rows : 16;
  if (box_width < 4 || box_height < 4) {
    erase();
    mvaddstr(0, 0, "terminal too small");
    refresh();
    return;
  }

  const int top = rows > box_height ? (rows - box_height) / 2 : 0;
  const int left = cols > box_width ? (cols - box_width) / 2 : 0;
  const int start_y = top + 2;
  const int start_x = left + 2;
  const int content_width = box_width - 4;

  erase();
  draw_cube_frame(top, left, box_height, box_width);

  mvaddstr(start_y, start_x, "SOCKS5 Manager");
  mvhline(start_y + 1, start_x, ACS_HLINE, content_width);
  mvprintw(start_y + 3, start_x, "Logged in as %s", state->username);

  for (int i = 0; i < MAIN_MENU_COUNT; i++) {
    mvprintw(
      start_y + 5 + i, start_x, "%s %s", selected == i ? ">" : " ", items[i]
    );
  }

  mvaddstr(start_y + 11, start_x, "Enter: select    q/Esc: quit");
  if (message != NULL && message[0] != '\0')
    mvaddnstr(start_y + 12, start_x, message, content_width);
  refresh();
}

static void animate_main_menu_box(void) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  const int box_width = cols < 42 ? cols : 42;
  const int box_height = rows < 16 ? rows : 16;
  if (box_width < 4 || box_height < 4) return;

  const int top = rows > box_height ? (rows - box_height) / 2 : 0;
  const int left = cols > box_width ? (cols - box_width) / 2 : 0;
  animate_menu_box(top, left, box_height, box_width);
}

static void run_main_menu(const struct ui_state *state) {
  int selected = 0;
  const char *message = "";
  keypad(stdscr, TRUE);
  animate_main_menu_box();

  for (;;) {
    draw_main_menu(state, selected, message);
    const int ch = getch();

    if (ch == 27 || ch == 'q' || ch == 'Q') return;
    if (ch == KEY_RESIZE) continue;
    if (is_up_key(ch)) {
      selected = previous_menu_index(selected, MAIN_MENU_COUNT);
      message = "";
      continue;
    }
    if (is_down_key(ch)) {
      selected = next_menu_index(selected, MAIN_MENU_COUNT);
      message = "";
      continue;
    }
    if (is_enter_key(ch)) {
      if (selected == MAIN_MENU_QUIT) return;
      if (selected == MAIN_MENU_METRICS) {
        show_live_metrics(state);
      } else if (selected == MAIN_MENU_USERS) {
        run_users_menu(state);
      } else if (selected == MAIN_MENU_ACCESS_LOG) {
        fetch_and_show(
          state, MON_CMD_GET_ACCESS_LOG, "Access Log", mng_format_access_log
        );
      }
      animate_main_menu_box();
      message = "";
    }
  }
}

int client_ui_run(const struct client_args *args) {
  struct ui_state state;
  memset(&state, 0, sizeof(state));
  state.mng_addr = args->mng_addr;
  state.mng_port = args->mng_port;
  state.mng_fd = -1;
  if (args->username != NULL && args->password != NULL) {
    strncpy(state.username, args->username, MAX_CREDENTIAL_LEN);
    strncpy(state.password, args->password, MAX_CREDENTIAL_LEN);
  }

  setlocale(LC_ALL, "");
  initscr();
  set_escdelay(25);
  cbreak();
  noecho();
  curs_set(0);
  metrics_view_init_colors();

  play_intro();
  if (state.username[0] != '\0' && state.password[0] != '\0') {
    snprintf(state.status, sizeof(state.status), "authenticating...");
    if (!ui_authenticate(&state)) state.password[0] = '\0';
  }
  if (!state.authenticated && !run_login(&state)) {
    if (state.mng_fd >= 0) close(state.mng_fd);
    play_outro();
    endwin();
    return 0;
  }
  run_main_menu(&state);

  if (state.mng_fd >= 0) close(state.mng_fd);
  play_outro();
  endwin();
  return 0;
}
