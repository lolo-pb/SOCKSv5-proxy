#include "ui_mng_session.h"

#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "mng_client.h"

#define AUTH_TIMEOUT_SEC 5

static bool fill_arg(struct mon_request *req, unsigned idx, const char *s) {
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
    snprintf(message, message_len, "%s", ui_mon_status_message(auth_resp.status));
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

const char *ui_mon_status_message(uint8_t status) {
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

bool ui_authenticate(struct ui_state *state) {
  if (state->mng_fd >= 0) {
    close(state->mng_fd);
    state->mng_fd = -1;
  }

  state->mng_fd =
    connect_authenticated(state, state->status, sizeof(state->status));
  if (state->mng_fd >= 0)
    snprintf(
      state->status, sizeof(state->status), "%s",
      ui_mon_status_message(MON_STATUS_OK)
    );
  state->authenticated = state->mng_fd >= 0;
  return state->authenticated;
}

bool ui_run_command(
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

  snprintf(message, message_len, "%s", ui_mon_status_message(out->status));
  return out->status == MON_STATUS_OK;
}

char *ui_format_payload(
  const struct ui_response *resp, payload_formatter formatter
) {
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

char *ui_copy_text(const char *text) {
  const size_t len = strlen(text);
  char *copy = malloc(len + 1);
  if (copy == NULL) return NULL;
  memcpy(copy, text, len + 1);
  return copy;
}

bool ui_fetch_metrics_data(int fd, struct metrics_view_data *metrics) {
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

char *ui_fetch_access_log_text(int fd) {
  struct ui_response resp;
  if (!send_command_on_fd(fd, MON_CMD_GET_ACCESS_LOG, 0, NULL, NULL, &resp))
    return ui_copy_text("access log request failed");
  if (resp.status != MON_STATUS_OK)
    return ui_copy_text(ui_mon_status_message(resp.status));

  char *text = ui_format_payload(&resp, mng_format_access_log);
  if (text == NULL) return ui_copy_text("Malformed access log response");
  return text;
}
