#include "users_view.h"

#include <ncurses.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "mon_protocol.h"

#define USERS_SKULL_PATH "src/client/ui/skull.txt"
#define USERS_SKULL_MAX_FRAMES 16
#define USERS_SKULL_MAX_FRAME_SIZE 2048
#define USERS_SKULL_FRAME_DELAY_MS 200
#define USERS_MAX_COUNT 256
#define USERS_SKULL_MAX_ROWS 10
#define USERS_SKULL_MAX_COLS 24
#define USERS_DETAIL_LEN 128
#define USERS_DETAIL_BOX_WIDTH 39
#define USERS_MIN_LIST_WIDTH 18

struct users_page_data {
  char names[USERS_MAX_COUNT][MAX_CREDENTIAL_LEN + 1];
  char passwords[USERS_MAX_COUNT][MAX_CREDENTIAL_LEN + 1];
  char last_connections[USERS_MAX_COUNT][USERS_DETAIL_LEN];
  char last_destinations[USERS_MAX_COUNT][USERS_DETAIL_LEN];
  int count;
};

struct known_user_passwords {
  char names[USERS_MAX_COUNT][MAX_CREDENTIAL_LEN + 1];
  char passwords[USERS_MAX_COUNT][MAX_CREDENTIAL_LEN + 1];
  int count;
};

struct users_skull_frames {
  char frames[USERS_SKULL_MAX_FRAMES][USERS_SKULL_MAX_FRAME_SIZE];
  int count;
};

struct frame_size {
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

static bool is_enter_key(int ch) {
  return ch == '\n' || ch == '\r' || ch == KEY_ENTER;
}

static bool is_backspace_key(int ch) {
  return ch == KEY_BACKSPACE || ch == 127 || ch == '\b';
}

static bool is_printable_ascii(int ch) { return ch >= 32 && ch <= 126; }

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

static uint16_t ui_be_u16(const uint8_t *p) {
  return (uint16_t) ((p[0] << 8) | p[1]);
}

static uint64_t ui_be_u64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
  return v;
}

static void draw_ui_box(int top, int left, int height, int width) {
  if (height < 2 || width < 2) return;

  mvaddch(top, left, '+');
  mvhline(top, left + 1, '-', width - 2);
  mvaddch(top, left + width - 1, '+');
  mvvline(top + 1, left, '|', height - 2);
  mvvline(top + 1, left + width - 1, '|', height - 2);
  mvaddch(top + height - 1, left, '+');
  mvhline(top + height - 1, left + 1, '-', width - 2);
  mvaddch(top + height - 1, left + width - 1, '+');
}

static size_t ui_utf8_columns(const char *s, size_t len) {
  size_t cols = 0;
  for (size_t i = 0; i < len; i++) {
    if (((unsigned char) s[i] & 0xC0) != 0x80) cols++;
  }
  return cols;
}

static struct frame_size measure_frame(const char *frame) {
  struct frame_size size = {0, 0};
  const char *line = frame;
  while (*line != '\0') {
    const char *end = strchr(line, '\n');
    const size_t len = end == NULL ? strlen(line) : (size_t) (end - line);
    const int cols = (int) ui_utf8_columns(line, len);
    if (cols > size.cols) size.cols = cols;
    size.rows++;
    if (end == NULL) break;
    line = end + 1;
  }
  return size;
}

static void add_skull_frame(struct users_skull_frames *out, const char *frame) {
  if (out->count >= USERS_SKULL_MAX_FRAMES || frame[0] == '\0') return;

  const struct frame_size size = measure_frame(frame);
  if (size.rows > USERS_SKULL_MAX_ROWS || size.cols > USERS_SKULL_MAX_COLS)
    return;

  snprintf(
    out->frames[out->count], sizeof(out->frames[out->count]), "%s", frame
  );
  out->count++;
}

static int load_users_skull_frames(struct users_skull_frames *out) {
  FILE *f = fopen(USERS_SKULL_PATH, "r");
  if (f == NULL) return -1;

  out->count = 0;
  size_t offset = 0;
  char frame[USERS_SKULL_MAX_FRAME_SIZE];
  char line[256];
  while (fgets(line, sizeof(line), f) != NULL) {
    if (strcmp(line, "#\n") == 0 || strcmp(line, "#\r\n") == 0) {
      frame[offset] = '\0';
      add_skull_frame(out, frame);
      offset = 0;
      continue;
    }

    const size_t len = strlen(line);
    if (offset + len + 1 >= sizeof(frame)) continue;
    memcpy(frame + offset, line, len);
    offset += len;
  }

  if (offset > 0) {
    frame[offset] = '\0';
    add_skull_frame(out, frame);
  }

  fclose(f);
  return out->count;
}

static bool parse_user_payload(
  const uint8_t *payload, size_t len, struct users_page_data *users
) {
  if (payload == NULL || len < 1) return false;

  const uint8_t count = payload[0];
  size_t off = 1;
  users->count = 0;
  for (uint8_t i = 0; i < count && users->count < USERS_MAX_COUNT; i++) {
    if (off >= len) return false;
    const uint8_t name_len = payload[off++];
    if (off + name_len > len) return false;

    const size_t copy_len =
      name_len < MAX_CREDENTIAL_LEN ? name_len : MAX_CREDENTIAL_LEN;
    memcpy(users->names[users->count], payload + off, copy_len);
    users->names[users->count][copy_len] = '\0';
    users->passwords[users->count][0] = '\0';
    snprintf(
      users->last_connections[users->count],
      sizeof(users->last_connections[users->count]), "%s", "(none)"
    );
    users->last_destinations[users->count][0] = '\0';
    users->count++;
    off += name_len;
  }

  return true;
}

static void remember_user_password(
  struct known_user_passwords *known, const char *user, const char *pass
) {
  if (user == NULL || pass == NULL || user[0] == '\0') return;

  for (int i = 0; i < known->count; i++) {
    if (strcmp(known->names[i], user) == 0) {
      snprintf(known->passwords[i], sizeof(known->passwords[i]), "%s", pass);
      return;
    }
  }

  if (known->count >= USERS_MAX_COUNT) return;
  snprintf(
    known->names[known->count], sizeof(known->names[known->count]), "%s", user
  );
  snprintf(
    known->passwords[known->count], sizeof(known->passwords[known->count]),
    "%s", pass
  );
  known->count++;
}

static void
forget_user_password(struct known_user_passwords *known, const char *user) {
  for (int i = 0; i < known->count; i++) {
    if (strcmp(known->names[i], user) == 0) {
      known->count--;
      if (i != known->count) {
        memmove(
          known->names[i], known->names[known->count], sizeof(known->names[i])
        );
        memmove(
          known->passwords[i], known->passwords[known->count],
          sizeof(known->passwords[i])
        );
      }
      return;
    }
  }
}

static const char *
known_password_for(const struct known_user_passwords *known, const char *user) {
  for (int i = 0; i < known->count; i++) {
    if (strcmp(known->names[i], user) == 0) return known->passwords[i];
  }
  return NULL;
}

static void apply_known_passwords(
  struct users_page_data *users, const struct known_user_passwords *known
) {
  for (int i = 0; i < users->count; i++) {
    const char *pass = known_password_for(known, users->names[i]);
    if (pass != NULL)
      snprintf(users->passwords[i], sizeof(users->passwords[i]), "%s", pass);
  }
}

static int
user_index_by_name(const struct users_page_data *users, const char *name) {
  for (int i = 0; i < users->count; i++) {
    if (strcmp(users->names[i], name) == 0) return i;
  }
  return -1;
}

static bool fetch_users_page_data(
  const struct ui_state *state, struct users_page_data *users, char *message,
  size_t message_len
) {
  struct ui_response resp;
  users->count = 0;
  if (!ui_run_command(
        state, MON_CMD_LIST_USERS, 0, NULL, NULL, &resp, message, message_len
      ))
    return false;

  if (!parse_user_payload(resp.payload, resp.payload_len, users)) {
    snprintf(message, message_len, "malformed users response");
    return false;
  }

  message[0] = '\0';
  return true;
}

static bool fetch_user_last_connections(
  const struct ui_state *state, struct users_page_data *users, char *message,
  size_t message_len
) {
  struct ui_response resp;
  if (!ui_run_command(
        state, MON_CMD_GET_ACCESS_LOG, 0, NULL, NULL, &resp, message,
        message_len
      ))
    return false;

  if (resp.payload == NULL || resp.payload_len < 2) {
    snprintf(message, message_len, "malformed access log response");
    return false;
  }

  const uint16_t count = ui_be_u16(resp.payload);
  size_t off = 2;
  for (uint16_t i = 0; i < count; i++) {
    if (off + 8 + 2 + 1 > resp.payload_len) {
      snprintf(message, message_len, "malformed access log response");
      return false;
    }
    const uint64_t ts = ui_be_u64(resp.payload + off);
    off += 8;
    const uint16_t port = ui_be_u16(resp.payload + off);
    off += 2;
    const uint8_t user_len = resp.payload[off++];
    if (off + user_len + 1 > resp.payload_len) {
      snprintf(message, message_len, "malformed access log response");
      return false;
    }
    const uint8_t *user = resp.payload + off;
    off += user_len;
    const uint8_t addr_len = resp.payload[off++];
    if (off + addr_len > resp.payload_len) {
      snprintf(message, message_len, "malformed access log response");
      return false;
    }
    const uint8_t *addr = resp.payload + off;
    off += addr_len;

    for (int j = 0; j < users->count; j++) {
      if (
        strlen(users->names[j]) != user_len ||
        memcmp(users->names[j], user, user_len) != 0
      )
        continue;

      char tbuf[32];
      const time_t t = (time_t) ts;
      struct tm tm;
      if (gmtime_r(&t, &tm) != NULL) {
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);
      } else {
        snprintf(tbuf, sizeof(tbuf), "%llu", (unsigned long long) ts);
      }
      snprintf(
        users->last_connections[j], sizeof(users->last_connections[j]), "%s",
        tbuf
      );
      snprintf(
        users->last_destinations[j], sizeof(users->last_destinations[j]),
        "%.*s:%u", (int) addr_len, addr, port
      );
    }
  }

  message[0] = '\0';
  return true;
}

static void refresh_users_page_data(
  const struct ui_state *state, struct users_page_data *users,
  const struct known_user_passwords *known, char *message, size_t message_len
) {
  if (!fetch_users_page_data(state, users, message, message_len)) return;
  apply_known_passwords(users, known);
  fetch_user_last_connections(state, users, message, message_len);
}

static void draw_add_user_form(
  const char *user, const char *pass, int field, const char *message
) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  const int box_width = cols < 48 ? cols : 48;
  const int box_height = rows < 12 ? rows : 12;
  if (box_width < 8 || box_height < 8) {
    erase();
    mvaddstr(0, 0, "terminal too small");
    refresh();
    return;
  }

  const int top = rows > box_height ? (rows - box_height) / 2 : 0;
  const int left = cols > box_width ? (cols - box_width) / 2 : 0;
  const int content_width = box_width - 4;

  erase();
  draw_ui_box(top, left, box_height, box_width);
  mvaddstr(top + 1, left + 2, "Add User");
  mvhline(top + 2, left + 2, '-', content_width);

  mvaddstr(top + 4, left + 2, field == 0 ? "> Username: " : "  Username: ");
  addnstr(user, MAX_CREDENTIAL_LEN);

  mvaddstr(top + 6, left + 2, field == 1 ? "> Password: " : "  Password: ");
  for (size_t i = 0; i < strlen(pass); i++) addch('*');

  mvaddstr(top + 9, left + 2, "Enter: next/add    Tab: switch    Esc: cancel");
  if (message != NULL && message[0] != '\0')
    mvaddnstr(top + 10, left + 2, message, content_width);
  refresh();
}

static bool run_add_user_form(char *user, char *pass) {
  int field = 0;
  char message[STATUS_LEN] = "";
  user[0] = '\0';
  pass[0] = '\0';
  keypad(stdscr, TRUE);

  for (;;) {
    draw_add_user_form(user, pass, field, message);
    const int ch = getch();

    if (ch == 27) return false;
    if (ch == KEY_RESIZE) continue;
    if (ch == '\t' || ch == KEY_DOWN || ch == KEY_UP) {
      field = 1 - field;
      continue;
    }
    if (is_backspace_key(ch)) {
      delete_char(field == 0 ? user : pass);
      continue;
    }
    if (is_enter_key(ch)) {
      if (field == 0) {
        field = 1;
        continue;
      }
      if (user[0] == '\0' || pass[0] == '\0') {
        snprintf(message, sizeof(message), "all fields are required");
        continue;
      }
      return true;
    }
    if (is_printable_ascii(ch)) append_char(field == 0 ? user : pass, ch);
  }
}

static bool add_user(
  const struct ui_state *state, const char *user, const char *pass,
  char *message, size_t message_len
) {
  struct ui_response resp;
  return ui_run_command(
    state, MON_CMD_ADD_USER, 2, user, pass, &resp, message, message_len
  );
}

static bool delete_user(
  const struct ui_state *state, const char *user, char *message,
  size_t message_len
) {
  struct ui_response resp;
  return ui_run_command(
    state, MON_CMD_DEL_USER, 1, user, NULL, &resp, message, message_len
  );
}

static void draw_users_list(
  const struct users_page_data *users, int selected, int scroll,
  int page_height, int left_width
) {
  mvaddnstr(0, 2, "Users", left_width - 3);
  mvvline(1, left_width, '|', page_height - 2);
  mvhline(page_height - 4, 1, '-', left_width - 1);

  const int list_rows = page_height > 7 ? page_height - 7 : 1;
  for (int i = 0; i < list_rows; i++) {
    const int idx = scroll + i;
    if (idx >= users->count) break;

    mvprintw(2 + i, 2, "%c ", idx == selected ? '>' : ' ');
    if (idx == selected) attron(A_REVERSE);
    mvaddnstr(2 + i, 4, users->names[idx], left_width - 5);
    if (idx == selected) attroff(A_REVERSE);
  }

  mvaddnstr(page_height - 3, 2, "[a] Add a user", left_width - 4);
}

static void
draw_skull_frame(int top, int left, int height, int width, const char *frame) {
  const struct frame_size size = measure_frame(frame);
  const int start_y = top + (height > size.rows ? (height - size.rows) / 2 : 0);
  const int start_x = left + (width > size.cols ? (width - size.cols) / 2 : 0);

  const char *line = frame;
  for (int y = start_y; *line != '\0' && y < top + height; y++) {
    const char *end = strchr(line, '\n');
    const int len = end == NULL ? (int) strlen(line) : (int) (end - line);
    mvaddnstr(y, start_x, line, len);
    if (end == NULL) break;
    line = end + 1;
  }
}

static void draw_user_detail_box(
  const struct users_page_data *users, int selected,
  const struct users_skull_frames *skull, int skull_frame, int page_height,
  int left_width, int page_width
) {
  const int right_left = left_width + 1;
  const int right_width = page_width - right_left - 1;
  const struct frame_size skull_size =
    skull->count > 0 ? measure_frame(skull->frames[0])
                     : (struct frame_size){.rows = 7, .cols = 16};
  const int skull_rows = skull_size.rows;
  const int skull_area_width = skull_size.cols + 2;
  const int box_height = skull_rows + 2;
  const int box_width = USERS_DETAIL_BOX_WIDTH;
  const int details_width = box_width - skull_area_width - 3;
  if (
    right_width < box_width || page_height < box_height + 1 ||
    details_width < 11
  ) {
    mvaddstr(1, right_left + 1, "terminal too small");
    return;
  }

  const int top =
    page_height > box_height + 1 ? (page_height - box_height - 1) / 2 : 0;
  const int left = right_left + (right_width - box_width) / 2;
  draw_ui_box(top, left, box_height, box_width);

  const int inner_top = top + 1;
  const int inner_left = left + 1;
  const int inner_height = box_height - 2;
  const int divider = inner_left + skull_area_width;
  const int details_left = divider + 1;
  const char *name =
    users->count > 0 && selected >= 0 ? users->names[selected] : "(no users)";
  const char *password =
    users->count > 0 && selected >= 0 && users->passwords[selected][0] != '\0'
      ? users->passwords[selected]
      : "(unknown)";
  const char *last_connection = users->count > 0 && selected >= 0
                                  ? users->last_connections[selected]
                                  : "(none)";
  const char *last_destination =
    users->count > 0 && selected >= 0 &&
        users->last_destinations[selected][0] != '\0'
      ? users->last_destinations[selected]
      : "";

  if (skull->count > 0)
    draw_skull_frame(
      inner_top, inner_left, inner_height, skull_area_width,
      skull->frames[skull_frame % skull->count]
    );

  mvvline(inner_top, divider, '|', inner_height);
  mvprintw(inner_top, details_left, "Name    : ");
  addnstr(name, details_width - 10);
  mvprintw(inner_top + 1, details_left, "Password: ");
  addnstr(password, details_width - 10);
  mvaddnstr(inner_top + 3, details_left, "Last connect:", details_width);
  mvaddnstr(inner_top + 4, details_left, last_connection, details_width);
  mvaddnstr(inner_top + 5, details_left, last_destination, details_width);

  mvaddnstr(top + box_height, left + 1, "[x]Terminate user", box_width - 2);
}

static void draw_users_page(
  const struct users_page_data *users, int selected, int scroll,
  const struct users_skull_frames *skull, int skull_frame, const char *message
) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  erase();
  if (rows < 12 || cols < USERS_MIN_LIST_WIDTH + USERS_DETAIL_BOX_WIDTH + 2) {
    mvaddstr(0, 0, "terminal too small");
    refresh();
    return;
  }

  const int page_height = rows - 1;
  const int page_width = cols;
  int left_width = cols - USERS_DETAIL_BOX_WIDTH - 2;
  if (left_width > cols / 3) left_width = cols / 3;
  if (left_width < USERS_MIN_LIST_WIDTH) left_width = USERS_MIN_LIST_WIDTH;

  draw_ui_box(0, 0, page_height, page_width);
  draw_users_list(users, selected, scroll, page_height, left_width);
  draw_user_detail_box(
    users, selected, skull, skull_frame, page_height, left_width, page_width
  );

  if (message != NULL && message[0] != '\0')
    mvaddnstr(rows - 1, 0, message, cols - 1);
  else
    mvaddnstr(
      rows - 1, 0,
      "Up/Down: scroll users    a: add user    x: terminate user    r: refresh "
      "   b/Esc: back",
      cols - 1
    );
  refresh();
}

void run_users_page(const struct ui_state *state) {
  struct users_page_data users;
  struct users_skull_frames skull;
  struct known_user_passwords known = {0};
  char message[STATUS_LEN];
  int selected = 0;
  int scroll = 0;
  int skull_frame = 0;

  remember_user_password(&known, state->username, state->password);
  refresh_users_page_data(state, &users, &known, message, sizeof(message));
  if (users.count == 0) selected = -1;
  if (load_users_skull_frames(&skull) <= 0) skull.count = 0;

  keypad(stdscr, TRUE);
  timeout(USERS_SKULL_FRAME_DELAY_MS);

  for (;;) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    const int page_height = rows - 1;
    const int list_rows = page_height > 7 ? page_height - 7 : 1;
    if (users.count > 0) {
      if (selected < 0) selected = 0;
      if (selected >= users.count) selected = users.count - 1;
      if (scroll > selected) scroll = selected;
      if (selected >= scroll + list_rows) scroll = selected - list_rows + 1;
      if (scroll < 0) scroll = 0;
    }

    (void) cols;
    draw_users_page(&users, selected, scroll, &skull, skull_frame, message);
    skull_frame++;
    const int ch = getch();

    if (is_back_key(ch)) {
      timeout(-1);
      return;
    }
    if (ch == ERR) continue;
    if (ch == KEY_RESIZE) continue;
    if (is_up_key(ch)) {
      if (selected > 0) selected--;
      continue;
    }
    if (is_down_key(ch)) {
      if (selected + 1 < users.count) selected++;
      continue;
    }
    if (ch == 'r' || ch == 'R') {
      char selected_user[MAX_CREDENTIAL_LEN + 1] = "";
      if (selected >= 0 && selected < users.count)
        snprintf(
          selected_user, sizeof(selected_user), "%s", users.names[selected]
        );

      refresh_users_page_data(state, &users, &known, message, sizeof(message));
      if (selected_user[0] != '\0') {
        const int refreshed_index = user_index_by_name(&users, selected_user);
        if (refreshed_index >= 0) selected = refreshed_index;
      }
      if (users.count == 0) selected = -1;
      continue;
    }
    if (ch == 'a' || ch == 'A') {
      char user[MAX_CREDENTIAL_LEN + 1];
      char pass[MAX_CREDENTIAL_LEN + 1];
      timeout(-1);
      if (run_add_user_form(user, pass)) {
        if (add_user(state, user, pass, message, sizeof(message))) {
          remember_user_password(&known, user, pass);
          refresh_users_page_data(
            state, &users, &known, message, sizeof(message)
          );
          selected = user_index_by_name(&users, user);
        }
      }
      timeout(USERS_SKULL_FRAME_DELAY_MS);
      continue;
    }
    if ((ch == 'x' || ch == 'X') && selected >= 0 && selected < users.count) {
      char deleted[MAX_CREDENTIAL_LEN + 1];
      snprintf(deleted, sizeof(deleted), "%s", users.names[selected]);
      if (delete_user(state, deleted, message, sizeof(message))) {
        forget_user_password(&known, deleted);
        refresh_users_page_data(
          state, &users, &known, message, sizeof(message)
        );
        if (users.count == 0) {
          selected = -1;
        } else if (selected >= users.count) {
          selected = users.count - 1;
        }
      }
    }
  }
}
