#include "client_ui.h"

#include <limits.h>
#include <locale.h>
#include <ncurses.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "ui/metrics_view.h"
#include "ui/menu_animation.h"
#include "mng_client.h"
#include "mon_protocol.h"

#define AUTH_TIMEOUT_SEC 5
#define INTRO_ANIMATION_PATH "src/client/ui/open_animation.txt"
#define MAX_FRAMES 32
#define MAX_FRAME_SIZE 8192
#define MAX_CREDENTIAL_LEN 255
#define STATUS_LEN 128
#define FRAME_DELAY_MS 150
#define METRICS_REFRESH_MS 1000
#define UI_RESPONSE_BUF_LEN (MON_RESPONSE_HEADER_LEN + (1 << 16))

struct ui_response {
  uint8_t status;
  uint16_t payload_len;
  const uint8_t *payload;
  uint8_t raw[UI_RESPONSE_BUF_LEN];
};

struct ui_state {
  const char *mng_addr;
  unsigned short mng_port;
  int mng_fd;
  char username[MAX_CREDENTIAL_LEN + 1];
  char password[MAX_CREDENTIAL_LEN + 1];
  char status[STATUS_LEN];
  bool authenticated;
};

static int connect_authenticated(
  const struct ui_state *state, char *message, size_t message_len
);

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

static void play_intro(void) { play_intro_animation(false); }

static void play_outro(void) { play_intro_animation(true); }

static const char *mon_status_message(uint8_t status) {
  switch (status) {
    case MON_STATUS_OK:
      return "ok";
    case MON_STATUS_AUTH_FAIL:
      return "authentication failed";
    case MON_STATUS_UNKNOWN_CMD:
      return "unknown command";
    case MON_STATUS_USER_EXISTS:
      return "user already exists";
    case MON_STATUS_USER_NOT_FOUND:
      return "user not found";
    case MON_STATUS_INTERNAL_ERROR:
      return "server error";
    default:
      return "unexpected server response";
  }
}

static bool
fill_arg(struct mon_request *req, unsigned idx, const char *s) {
  const size_t len = strlen(s);
  if (len > MON_MAX_ARG_LEN) return false;
  req->arg_lens[idx] = (uint8_t) len;
  memcpy(req->args[idx], s, len);
  req->args[idx][len] = '\0';
  return true;
}

static bool encode_request(
  uint8_t cmd, unsigned nargs, const char *arg0, const char *arg1, uint8_t *buf,
  size_t buf_len, int *request_len
) {
  struct mon_request req;
  memset(&req, 0, sizeof(req));
  req.version = MON_VERSION;
  req.cmd = cmd;
  req.nargs = (uint8_t) nargs;

  if (nargs > 0 && !fill_arg(&req, 0, arg0)) return false;
  if (nargs > 1 && !fill_arg(&req, 1, arg1)) return false;

  *request_len = mon_request_encode(&req, buf, buf_len);
  return *request_len > 0;
}

static bool build_auth_request(
  const struct ui_state *state, uint8_t *buf, size_t buf_len, int *request_len
) {
  return encode_request(
    MON_CMD_AUTH, 2, state->username, state->password, buf, buf_len, request_len
  );
}

static bool send_all(int fd, const uint8_t *buf, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    const ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
    if (n <= 0) return false;
    sent += (size_t) n;
  }
  return true;
}

static bool recv_response(int fd, struct ui_response *out) {
  size_t used = 0;

  while (used < sizeof(out->raw)) {
    const ssize_t n = recv(fd, out->raw + used, sizeof(out->raw) - used, 0);
    if (n <= 0) return false;
    used += (size_t) n;

    struct mon_response resp;
    size_t consumed;
    switch (mon_response_decode(out->raw, used, &resp, &consumed)) {
      case MON_DECODE_NEED_MORE:
        break;
      case MON_DECODE_ERROR:
        return false;
      case MON_DECODE_OK:
        out->status = resp.status;
        out->payload_len = resp.payload_len;
        out->payload = resp.payload;
        return true;
    }
  }
  return false;
}

static bool send_command_on_fd(
  int fd, uint8_t cmd, unsigned nargs, const char *arg0, const char *arg1,
  struct ui_response *out
) {
  uint8_t request[3 + MON_MAX_ARGS * (1 + MON_MAX_ARG_LEN)];
  int request_len = 0;
  return encode_request(
           cmd, nargs, arg0, arg1, request, sizeof(request), &request_len
         ) &&
         send_all(fd, request, (size_t) request_len) && recv_response(fd, out);
}

static uint64_t ui_be_u64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
  return v;
}

static bool authenticate(struct ui_state *state) {
  if (state->mng_fd >= 0) {
    close(state->mng_fd);
    state->mng_fd = -1;
  }

  state->mng_fd =
    connect_authenticated(state, state->status, sizeof(state->status));
  if (state->mng_fd >= 0)
    snprintf(state->status, sizeof(state->status), "%s", mon_status_message(MON_STATUS_OK));
  state->authenticated = state->mng_fd >= 0;
  return state->authenticated;
}

static bool run_command(
  const struct ui_state *state, uint8_t cmd, unsigned nargs, const char *arg0,
  const char *arg1, struct ui_response *out, char *message, size_t message_len
) {
  if (state->mng_fd < 0) {
    snprintf(message, message_len, "not connected");
    return false;
  }

  if (!send_command_on_fd(state->mng_fd, cmd, nargs, arg0, arg1, out)) {
    snprintf(message, message_len, "command request failed");
    return false;
  }

  snprintf(message, message_len, "%s", mon_status_message(out->status));
  return out->status == MON_STATUS_OK;
}

static int connect_authenticated_at_addr(
  const struct ui_state *state, const struct addrinfo *rp, char *message,
  size_t message_len
) {
  const int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
  if (fd < 0) return -1;

  const struct timeval timeout = {.tv_sec = AUTH_TIMEOUT_SEC, .tv_usec = 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  if (connect(fd, rp->ai_addr, rp->ai_addrlen) < 0) {
    close(fd);
    return -1;
  }

  uint8_t request[3 + MON_MAX_ARGS * (1 + MON_MAX_ARG_LEN)];
  int request_len = 0;
  struct ui_response auth_resp;
  if (!build_auth_request(state, request, sizeof(request), &request_len) ||
      !send_all(fd, request, (size_t) request_len) ||
      !recv_response(fd, &auth_resp)) {
    close(fd);
    snprintf(message, message_len, "authentication request failed");
    return -2;
  }

  if (auth_resp.status != MON_STATUS_OK) {
    close(fd);
    snprintf(message, message_len, "%s", mon_status_message(auth_resp.status));
    return -2;
  }

  return fd;
}

static int connect_authenticated(
  const struct ui_state *state, char *message, size_t message_len
) {
  char port[6];
  snprintf(port, sizeof(port), "%u", state->mng_port);

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *res = NULL;
  const int gai = getaddrinfo(state->mng_addr, port, &hints, &res);
  if (gai != 0) {
    snprintf(message, message_len, "cannot resolve %s:%s", state->mng_addr, port);
    return -1;
  }

  bool reached = false;
  int fd = -1;
  for (const struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
    fd = connect_authenticated_at_addr(state, rp, message, message_len);
    if (fd >= 0) {
      reached = true;
      break;
    }
    if (fd == -2) {
      reached = true;
      break;
    }
  }
  freeaddrinfo(res);

  if (!reached)
    snprintf(message, message_len, "could not connect to %s:%s", state->mng_addr, port);

  return fd;
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
    if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
      if (field == 0) {
        field = 1;
      } else if (state->username[0] != '\0' && state->password[0] != '\0') {
        snprintf(state->status, sizeof(state->status), "authenticating...");
        draw_login_form(state, field);
        if (authenticate(state)) return true;
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

typedef int (*payload_formatter)(const uint8_t *payload, size_t len, FILE *out);

static char *
format_payload(const struct ui_response *resp, payload_formatter formatter) {
  char *text = NULL;
  size_t len = 0;
  FILE *out = open_memstream(&text, &len);
  if (out == NULL) return NULL;

  if (formatter(resp->payload, resp->payload_len, out) != 0) {
    fclose(out);
    free(text);
    return NULL;
  }

  fclose(out);
  return text;
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
    if (ch == 27 || ch == 'b' || ch == 'B' || ch == 'q' || ch == 'Q') return;
    if (ch == KEY_RESIZE) continue;
    if (ch == KEY_UP || ch == 'k' || ch == 'K') {
      if (offset > 0) offset--;
    } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
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
  if (!run_command(state, cmd, 0, NULL, NULL, &resp, message, sizeof(message))) {
    show_message_screen(title, message);
    return;
  }

  char *text = format_payload(&resp, formatter);
  if (text == NULL) {
    show_message_screen(title, "Malformed server response");
    return;
  }

  show_text_screen(title, text);
  free(text);
}

static char *copy_text(const char *text) {
  const size_t len = strlen(text);
  char *copy = malloc(len + 1);
  if (copy == NULL) return NULL;
  memcpy(copy, text, len + 1);
  return copy;
}

static bool fetch_metrics_data(int fd, struct metrics_view_data *metrics) {
  struct ui_response resp;
  if (!send_command_on_fd(fd, MON_CMD_GET_METRICS, 0, NULL, NULL, &resp))
    return false;
  if (resp.status != MON_STATUS_OK)
    return false;
  if (resp.payload_len != MON_METRICS_PAYLOAD_LEN) return false;

  metrics->historic_connections = ui_be_u64(resp.payload);
  metrics->current_connections = ui_be_u64(resp.payload + 8);
  metrics->bytes_transferred = ui_be_u64(resp.payload + 16);
  return true;
}

static char *fetch_access_log_text(int fd) {
  struct ui_response resp;
  if (!send_command_on_fd(fd, MON_CMD_GET_ACCESS_LOG, 0, NULL, NULL, &resp))
    return copy_text("access log request failed");
  if (resp.status != MON_STATUS_OK)
    return copy_text(mon_status_message(resp.status));

  char *text = format_payload(&resp, mng_format_access_log);
  if (text == NULL) return copy_text("Malformed access log response");
  return text;
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
    char *access_log = fetch_access_log_text(state->mng_fd);
    if (access_log == NULL) access_log = copy_text("out of memory");
    if (!fetch_metrics_data(state->mng_fd, &metrics)) {
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
    if (ch == 27 || ch == 'b' || ch == 'B' || ch == 'q' || ch == 'Q') {
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
    if (ch == KEY_BACKSPACE || ch == 127 || ch == '\b') {
      delete_char(field == 0 ? user : pass);
      continue;
    }
    if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
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
    if (ch >= 32 && ch <= 126) append_char(field == 0 ? user : pass, ch);
  }
}

static void user_command(
  const struct ui_state *state, uint8_t cmd, const char *user, const char *pass
) {
  struct ui_response resp;
  char message[STATUS_LEN];
  unsigned nargs = cmd == MON_CMD_ADD_USER ? 2 : 1;
  run_command(state, cmd, nargs, user, pass, &resp, message, sizeof(message));
  show_message_screen("Users", message);
}

static void draw_users_menu(int selected, const char *message) {
  static const char *items[] = {"List Users", "Add User", "Delete User", "Back"};
  const int item_count = (int) (sizeof(items) / sizeof(items[0]));

  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  const int width = 42;
  const int start_y = rows > 14 ? (rows - 14) / 2 : 0;
  const int start_x = cols > width ? (cols - width) / 2 : 0;

  erase();
  mvaddstr(start_y, start_x, "Users");
  mvhline(start_y + 1, start_x, ACS_HLINE, width);
  for (int i = 0; i < item_count; i++) {
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

    if (ch == 27 || ch == 'b' || ch == 'B' || ch == 'q' || ch == 'Q') return;
    if (ch == KEY_RESIZE) continue;
    if (ch == KEY_UP || ch == 'k' || ch == 'K') {
      selected = selected == 0 ? 3 : selected - 1;
      message = "";
      continue;
    }
    if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
      selected = selected == 3 ? 0 : selected + 1;
      message = "";
      continue;
    }
    if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
      char user[MAX_CREDENTIAL_LEN + 1];
      char pass[MAX_CREDENTIAL_LEN + 1];
      if (selected == 0) {
        fetch_and_show(state, MON_CMD_LIST_USERS, "Users", mng_format_users);
      } else if (selected == 1) {
        if (run_user_form("Add User", user, pass, true))
          user_command(state, MON_CMD_ADD_USER, user, pass);
      } else if (selected == 2) {
        if (run_user_form("Delete User", user, pass, false))
          user_command(state, MON_CMD_DEL_USER, user, NULL);
      } else {
        return;
      }
    }
  }
}

static void draw_main_menu(
  const struct ui_state *state, int selected, const char *message
) {
  static const char *items[] = {"Metrics", "Users", "Access Log", "Quit"};
  const int item_count = (int) (sizeof(items) / sizeof(items[0]));

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

  for (int i = 0; i < item_count; i++) {
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
    if (ch == KEY_UP || ch == 'k' || ch == 'K') {
      selected = selected == 0 ? 3 : selected - 1;
      message = "";
      continue;
    }
    if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
      selected = selected == 3 ? 0 : selected + 1;
      message = "";
      continue;
    }
    if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
      if (selected == 3) return;
      if (selected == 0) {
        show_live_metrics(state);
      } else if (selected == 1) {
        run_users_menu(state);
      } else if (selected == 2) {
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
    if (!authenticate(&state)) state.password[0] = '\0';
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
