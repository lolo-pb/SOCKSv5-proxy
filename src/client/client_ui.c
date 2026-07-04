#include "client_ui.h"

#include <locale.h>
#include <ncurses.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "mon_protocol.h"

#define AUTH_TIMEOUT_SEC 5
#define INTRO_ANIMATION_PATH "src/client/ui/open_animation.txt"
#define MAX_FRAMES 32
#define MAX_FRAME_SIZE 8192
#define MAX_CREDENTIAL_LEN 255
#define STATUS_LEN 128
#define FRAME_DELAY_MS 150

struct ui_state {
  const char *mng_addr;
  unsigned short mng_port;
  char username[MAX_CREDENTIAL_LEN + 1];
  char password[MAX_CREDENTIAL_LEN + 1];
  char status[STATUS_LEN];
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

  nodelay(stdscr, TRUE);
  for (int i = frame_count - 1; i >= 0; i--) {
    if (getch() != ERR) break;
    draw_frame(frames[i]);
    napms(FRAME_DELAY_MS);
  }
  nodelay(stdscr, FALSE);
  napms(250);
}

static const char *mon_status_message(uint8_t status) {
  switch (status) {
    case MON_STATUS_OK:
      return "login ok";
    case MON_STATUS_AUTH_FAIL:
      return "authentication failed";
    case MON_STATUS_INTERNAL_ERROR:
      return "server error";
    default:
      return "unexpected server response";
  }
}

static bool
fill_auth_arg(struct mon_request *req, unsigned idx, const char *s) {
  const size_t len = strlen(s);
  if (len > MON_MAX_ARG_LEN) return false;
  req->arg_lens[idx] = (uint8_t) len;
  memcpy(req->args[idx], s, len);
  req->args[idx][len] = '\0';
  return true;
}

static bool build_auth_request(
  const struct ui_state *state, uint8_t *buf, size_t buf_len, int *request_len
) {
  struct mon_request req;
  memset(&req, 0, sizeof(req));
  req.version = MON_VERSION;
  req.cmd = MON_CMD_AUTH;
  req.nargs = 2;

  if (!fill_auth_arg(&req, 0, state->username) ||
      !fill_auth_arg(&req, 1, state->password)) {
    return false;
  }

  *request_len = mon_request_encode(&req, buf, buf_len);
  return *request_len > 0;
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

static bool recv_auth_response(int fd, uint8_t *status) {
  uint8_t buf[MON_RESPONSE_HEADER_LEN + 16];
  size_t used = 0;

  while (used < sizeof(buf)) {
    const ssize_t n = recv(fd, buf + used, sizeof(buf) - used, 0);
    if (n <= 0) return false;
    used += (size_t) n;

    struct mon_response resp;
    size_t consumed;
    switch (mon_response_decode(buf, used, &resp, &consumed)) {
      case MON_DECODE_NEED_MORE:
        break;
      case MON_DECODE_ERROR:
        return false;
      case MON_DECODE_OK:
        *status = resp.status;
        return true;
    }
  }
  return false;
}

static bool try_auth_at_addr(
  const struct ui_state *state, const struct addrinfo *rp, uint8_t *status
) {
  const int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
  if (fd < 0) return false;

  const struct timeval timeout = {.tv_sec = AUTH_TIMEOUT_SEC, .tv_usec = 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  if (connect(fd, rp->ai_addr, rp->ai_addrlen) < 0) {
    close(fd);
    return false;
  }

  uint8_t request[3 + MON_MAX_ARGS * (1 + MON_MAX_ARG_LEN)];
  int request_len = 0;
  if (!build_auth_request(state, request, sizeof(request), &request_len)) {
    close(fd);
    *status = MON_STATUS_AUTH_FAIL;
    return true;
  }

  const bool ok = send_all(fd, request, (size_t) request_len) &&
                  recv_auth_response(fd, status);
  close(fd);
  return ok;
}

static bool authenticate(struct ui_state *state) {
  char port[6];
  snprintf(port, sizeof(port), "%u", state->mng_port);

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *res = NULL;
  const int gai = getaddrinfo(state->mng_addr, port, &hints, &res);
  if (gai != 0) {
    snprintf(
      state->status, sizeof(state->status), "cannot resolve %s:%s",
      state->mng_addr, port
    );
    return false;
  }

  uint8_t status = MON_STATUS_INTERNAL_ERROR;
  bool reached = false;
  for (const struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
    if (try_auth_at_addr(state, rp, &status)) {
      reached = true;
      break;
    }
  }
  freeaddrinfo(res);

  if (!reached) {
    snprintf(
      state->status, sizeof(state->status), "could not connect to %s:%s",
      state->mng_addr, port
    );
    return false;
  }

  snprintf(
    state->status, sizeof(state->status), "%s", mon_status_message(status)
  );
  state->authenticated = status == MON_STATUS_OK;
  return state->authenticated;
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
  if (state->status[0] != '\0')
    mvaddnstr(start_y + 9, start_x, state->status, STATUS_LEN);
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
  state.mng_addr = args->mng_addr;
  state.mng_port = args->mng_port;
  if (args->username != NULL && args->password != NULL) {
    strncpy(state.username, args->username, MAX_CREDENTIAL_LEN);
    strncpy(state.password, args->password, MAX_CREDENTIAL_LEN);
  }

  setlocale(LC_ALL, "");
  initscr();
  cbreak();
  noecho();
  curs_set(0);

  play_intro();
  if (state.username[0] != '\0' && state.password[0] != '\0') {
    snprintf(state.status, sizeof(state.status), "authenticating...");
    if (!authenticate(&state)) state.password[0] = '\0';
  }
  if (!state.authenticated && !run_login(&state)) {
    endwin();
    return 0;
  }
  show_logged_in(&state);

  endwin();
  return 0;
}
