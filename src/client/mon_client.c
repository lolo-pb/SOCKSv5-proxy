#include "mon_client.h"

#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define ATTACHMENT(key) ((struct mon_client *) (key)->data)

/* state machine states (must stay correlative, see stm_init) */
enum mon_state {
  ST_CONNECTING = 0,
  ST_SEND_AUTH,
  ST_RECV_AUTH,
  ST_SEND_CMD,
  ST_RECV_CMD,
  ST_DONE,
  ST_ERROR,
};

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static uint16_t be_u16(const uint8_t *p) {
  return (uint16_t) ((p[0] << 8) | p[1]);
}

static uint64_t be_u64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
  return v;
}

static const char *status_str(uint8_t status) {
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
      return "internal server error";
    default:
      return "unknown status";
  }
}

/* ------------------------------------------------------------------ */
/* request building                                                   */
/* ------------------------------------------------------------------ */

static bool fill_arg(struct mon_request *req, unsigned idx, const char *s) {
  const size_t l = strlen(s);
  if (l > MON_MAX_ARG_LEN) return false;
  req->arg_lens[idx] = (uint8_t) l;
  memcpy(req->args[idx], s, l);
  req->args[idx][l] = '\0';
  return true;
}

static bool build_auth_request(struct mon_client *d, struct mon_request *req) {
  memset(req, 0, sizeof(*req));
  req->version = MON_VERSION;
  req->cmd = MON_CMD_AUTH;
  req->nargs = 2;
  return fill_arg(req, 0, d->args->username) &&
         fill_arg(req, 1, d->args->password);
}

static bool build_cmd_request(struct mon_client *d, struct mon_request *req) {
  memset(req, 0, sizeof(*req));
  req->version = MON_VERSION;
  switch (d->args->cmd) {
    case CLIENT_CMD_METRICS:
      req->cmd = MON_CMD_GET_METRICS;
      return true;
    case CLIENT_CMD_LIST_USERS:
      req->cmd = MON_CMD_LIST_USERS;
      return true;
    case CLIENT_CMD_ACCESS_LOG:
      req->cmd = MON_CMD_GET_ACCESS_LOG;
      return true;
    case CLIENT_CMD_ADD_USER:
      req->cmd = MON_CMD_ADD_USER;
      req->nargs = 2;
      return fill_arg(req, 0, d->args->arg_user) &&
             fill_arg(req, 1, d->args->arg_pass);
    case CLIENT_CMD_DEL_USER:
      req->cmd = MON_CMD_DEL_USER;
      req->nargs = 1;
      return fill_arg(req, 0, d->args->arg_user);
    default:
      return false;
  }
}

/* encode req and append it to the write buffer */
static bool queue_request(struct mon_client *d, const struct mon_request *req) {
  uint8_t tmp[3 + MON_MAX_ARGS * (1 + MON_MAX_ARG_LEN)];
  const int n = mon_request_encode(req, tmp, sizeof(tmp));
  if (n < 0) return false;
  size_t space;
  uint8_t *p = buffer_write_ptr(&d->write_buffer, &space);
  if ((size_t) n > space) return false;
  memcpy(p, tmp, (size_t) n);
  buffer_write_adv(&d->write_buffer, n);
  return true;
}

/* ------------------------------------------------------------------ */
/* response payload formatters                                        */
/* ------------------------------------------------------------------ */

int mon_format_metrics(const uint8_t *payload, size_t len, FILE *out) {
  if (payload == NULL || len != MON_METRICS_PAYLOAD_LEN) return -1;
  fprintf(out, "Historic connections: %" PRIu64 "\n", be_u64(payload));
  fprintf(out, "Current connections:  %" PRIu64 "\n", be_u64(payload + 8));
  fprintf(out, "Bytes transferred:    %" PRIu64 "\n", be_u64(payload + 16));
  return 0;
}

int mon_format_users(const uint8_t *payload, size_t len, FILE *out) {
  if (payload == NULL || len < 1) return -1;
  const uint8_t count = payload[0];
  size_t off = 1;
  for (uint8_t i = 0; i < count; i++) {
    if (off >= len) return -1;
    const uint8_t nl = payload[off++];
    if (off + nl > len) return -1;
    fprintf(out, "%.*s\n", (int) nl, payload + off);
    off += nl;
  }
  if (count == 0) fprintf(out, "(no users)\n");
  return 0;
}

int mon_format_access_log(const uint8_t *payload, size_t len, FILE *out) {
  if (payload == NULL || len < 2) return -1;
  const uint16_t count = be_u16(payload);
  size_t off = 2;
  for (uint16_t i = 0; i < count; i++) {
    if (off + 8 + 2 + 1 > len) return -1;
    const uint64_t ts = be_u64(payload + off);
    off += 8;
    const uint16_t port = be_u16(payload + off);
    off += 2;
    const uint8_t ul = payload[off++];
    if (off + ul + (size_t) 1 > len) return -1;
    const uint8_t *user = payload + off;
    off += ul;
    const uint8_t al = payload[off++];
    if (off + al > len) return -1;
    const uint8_t *addr = payload + off;
    off += al;

    char tbuf[32];
    const time_t t = (time_t) ts;
    struct tm tm;
    if (gmtime_r(&t, &tm) != NULL) {
      strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    } else {
      snprintf(tbuf, sizeof(tbuf), "%" PRIu64, ts);
    }
    fprintf(
      out, "%s  %.*s  %.*s:%u\n", tbuf, (int) ul, user, (int) al, addr, port
    );
  }
  if (count == 0) fprintf(out, "(empty log)\n");
  return 0;
}

/* ------------------------------------------------------------------ */
/* state handlers                                                     */
/* ------------------------------------------------------------------ */

static unsigned
on_auth_ok(struct selector_key *key, const struct mon_response *resp);
static unsigned
on_cmd_ok(struct selector_key *key, const struct mon_response *resp);

/* OP_WRITE: connect() has completed (or failed) */
static unsigned on_connecting(struct selector_key *key) {
  struct mon_client *d = ATTACHMENT(key);
  int soerr = 0;
  socklen_t l = sizeof(soerr);
  if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &soerr, &l) < 0 || soerr != 0) {
    d->connect_failed = true; /* let main() try the next address */
    return ST_ERROR;
  }
  struct mon_request req;
  if (!build_auth_request(d, &req) || !queue_request(d, &req)) {
    fprintf(stderr, "client: credentials too long\n");
    d->result = MON_EXIT_IO;
    return ST_ERROR;
  }
  return ST_SEND_AUTH; /* interest is already OP_WRITE */
}

/* drain the write buffer; when empty switch to reading the response */
static unsigned
send_buffer(struct selector_key *key, unsigned self, unsigned next) {
  struct mon_client *d = ATTACHMENT(key);
  size_t n;
  uint8_t *p = buffer_read_ptr(&d->write_buffer, &n);
  const ssize_t sent = send(key->fd, p, n, 0);
  if (sent < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return self;
    d->result = MON_EXIT_IO;
    return ST_ERROR;
  }
  buffer_read_adv(&d->write_buffer, sent);
  if (buffer_can_read(&d->write_buffer)) return self; /* partial write */
  if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
    d->result = MON_EXIT_IO;
    return ST_ERROR;
  }
  return next;
}

static unsigned on_send_auth(struct selector_key *key) {
  return send_buffer(key, ST_SEND_AUTH, ST_RECV_AUTH);
}

static unsigned on_send_cmd(struct selector_key *key) {
  return send_buffer(key, ST_SEND_CMD, ST_RECV_CMD);
}

/* accumulate bytes until a full response frame can be decoded */
static unsigned
recv_response(struct selector_key *key, unsigned self, bool is_auth) {
  struct mon_client *d = ATTACHMENT(key);
  size_t space;
  uint8_t *ptr = buffer_write_ptr(&d->read_buffer, &space);
  if (space == 0) {
    fprintf(stderr, "client: response too large\n");
    d->result = MON_EXIT_MALFORMED;
    return ST_ERROR;
  }
  const ssize_t n = recv(key->fd, ptr, space, 0);
  if (n == 0) {
    fprintf(stderr, "client: server closed the connection\n");
    d->result = MON_EXIT_IO;
    return ST_ERROR;
  }
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return self;
    d->result = MON_EXIT_IO;
    return ST_ERROR;
  }
  buffer_write_adv(&d->read_buffer, n);

  size_t avail;
  uint8_t *rp = buffer_read_ptr(&d->read_buffer, &avail);
  struct mon_response resp;
  size_t consumed;
  switch (mon_response_decode(rp, avail, &resp, &consumed)) {
    case MON_DECODE_NEED_MORE:
      return self;
    case MON_DECODE_ERROR:
      fprintf(stderr, "client: malformed response\n");
      d->result = MON_EXIT_MALFORMED;
      return ST_ERROR;
    case MON_DECODE_OK:
      buffer_read_adv(&d->read_buffer, consumed);
      return is_auth ? on_auth_ok(key, &resp) : on_cmd_ok(key, &resp);
  }
  return ST_ERROR; /* unreachable */
}

static unsigned on_recv_auth(struct selector_key *key) {
  return recv_response(key, ST_RECV_AUTH, true);
}

static unsigned on_recv_cmd(struct selector_key *key) {
  return recv_response(key, ST_RECV_CMD, false);
}

static unsigned
on_auth_ok(struct selector_key *key, const struct mon_response *resp) {
  struct mon_client *d = ATTACHMENT(key);
  if (resp->status != MON_STATUS_OK) {
    fprintf(stderr, "client: %s\n", status_str(resp->status));
    d->result = MON_EXIT_AUTH;
    return ST_ERROR;
  }
  struct mon_request req;
  if (!build_cmd_request(d, &req) || !queue_request(d, &req)) {
    fprintf(stderr, "client: argument too long\n");
    d->result = MON_EXIT_IO;
    return ST_ERROR;
  }
  if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
    d->result = MON_EXIT_IO;
    return ST_ERROR;
  }
  return ST_SEND_CMD;
}

static unsigned
on_cmd_ok(struct selector_key *key, const struct mon_response *resp) {
  struct mon_client *d = ATTACHMENT(key);
  if (resp->status != MON_STATUS_OK) {
    fprintf(stderr, "client: %s\n", status_str(resp->status));
    d->result = MON_EXIT_CMD;
    return ST_ERROR;
  }
  int rc = 0;
  switch (d->args->cmd) {
    case CLIENT_CMD_METRICS:
      rc = mon_format_metrics(resp->payload, resp->payload_len, stdout);
      break;
    case CLIENT_CMD_LIST_USERS:
      rc = mon_format_users(resp->payload, resp->payload_len, stdout);
      break;
    case CLIENT_CMD_ACCESS_LOG:
      rc = mon_format_access_log(resp->payload, resp->payload_len, stdout);
      break;
    case CLIENT_CMD_ADD_USER:
      fprintf(stdout, "user '%s' added\n", d->args->arg_user);
      break;
    case CLIENT_CMD_DEL_USER:
      fprintf(stdout, "user '%s' deleted\n", d->args->arg_user);
      break;
    default:
      rc = -1;
  }
  if (rc != 0) {
    fprintf(stderr, "client: malformed response payload\n");
    d->result = MON_EXIT_MALFORMED;
    return ST_ERROR;
  }
  d->result = MON_EXIT_OK;
  return ST_DONE;
}

/* ------------------------------------------------------------------ */
/* state table + top level handlers                                   */
/* ------------------------------------------------------------------ */

static const struct state_definition states[] = {
  {.state = ST_CONNECTING, .on_write_ready = on_connecting},
  {.state = ST_SEND_AUTH, .on_write_ready = on_send_auth},
  {.state = ST_RECV_AUTH, .on_read_ready = on_recv_auth},
  {.state = ST_SEND_CMD, .on_write_ready = on_send_cmd},
  {.state = ST_RECV_CMD, .on_read_ready = on_recv_cmd},
  {.state = ST_DONE},
  {.state = ST_ERROR},
};

static void mon_finish(struct selector_key *key) {
  struct mon_client *d = ATTACHMENT(key);
  d->finished = true;
  selector_unregister_fd(key->s, key->fd);
  close(key->fd);
}

static void mon_read(struct selector_key *key) {
  const unsigned st = stm_handler_read(&ATTACHMENT(key)->stm, key);
  if (st == ST_DONE || st == ST_ERROR) mon_finish(key);
}

static void mon_write(struct selector_key *key) {
  const unsigned st = stm_handler_write(&ATTACHMENT(key)->stm, key);
  if (st == ST_DONE || st == ST_ERROR) mon_finish(key);
}

static void mon_close(struct selector_key *key) {
  (void) key; /* the struct is owned and freed by main() */
}

static const struct fd_handler handler = {
  .handle_read = mon_read,
  .handle_write = mon_write,
  .handle_close = mon_close,
  .handle_block_done = NULL,
};

const struct fd_handler *mon_client_handler(void) { return &handler; }

void mon_client_init(struct mon_client *c, const struct client_args *args) {
  c->args = args;
  c->finished = false;
  c->connect_failed = false;
  c->result = MON_EXIT_OK;
  buffer_init(&c->read_buffer, sizeof(c->raw_read), c->raw_read);
  buffer_init(&c->write_buffer, sizeof(c->raw_write), c->raw_write);
  c->stm.initial = ST_CONNECTING;
  c->stm.max_state = ST_ERROR;
  c->stm.states = states;
  stm_init(&c->stm);
}
