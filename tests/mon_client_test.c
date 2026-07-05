/*
 * Tests for the monitoring client.
 *
 *   - unit tests for mon_response_decode and the payload formatters
 *   - a loopback integration test that drives the real non-blocking client
 *     (selector + state machine) against a forked mock server.
 *
 * Build (ad hoc, like the other standalone tests):
 *   gcc -std=c11 -D_POSIX_C_SOURCE=200809L -Wall \
 *       -I src/shared/include -I src/server/include -I src/client/include \
 *       -I src/shared -I src/client \
 *       tests/mon_client_test.c src/shared/buffer.c src/shared/selector.c \
 *       src/shared/stm.c -o /tmp/mon_client_test && /tmp/mon_client_test
 */
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* pull in the units under test (and their static helpers) */
#include "mon_client.c"
#include "mon_protocol.c"

/* ------------------------------------------------------------------ */
/* unit tests                                                         */
/* ------------------------------------------------------------------ */

static void test_decode_roundtrip(void) {
  const uint8_t pl[] = {0x10, 0x20, 0x30};
  const struct mon_response in = {
    .version = MON_VERSION,
    .status = MON_STATUS_OK,
    .payload_len = sizeof(pl),
    .payload = pl,
  };
  uint8_t buf[64];
  const int n = mon_response_encode(&in, buf, sizeof(buf));
  assert(n == (int) (MON_RESPONSE_HEADER_LEN + sizeof(pl)));

  struct mon_response out;
  size_t consumed = 0;
  assert(mon_response_decode(buf, n, &out, &consumed) == MON_DECODE_OK);
  assert(out.status == MON_STATUS_OK);
  assert(out.payload_len == sizeof(pl));
  assert(consumed == (size_t) n);
  assert(out.payload[0] == 0x10 && out.payload[2] == 0x30);
}

static void test_decode_need_more_and_bad_version(void) {
  const uint8_t pl[] = {0xAA, 0xBB, 0xCC};
  const struct mon_response in = {
    .version = MON_VERSION,
    .status = MON_STATUS_OK,
    .payload_len = sizeof(pl),
    .payload = pl,
  };
  uint8_t buf[64];
  const int n = mon_response_encode(&in, buf, sizeof(buf));
  struct mon_response out;
  size_t consumed = 0;

  /* fewer than the header */
  assert(mon_response_decode(buf, 2, &out, &consumed) == MON_DECODE_NEED_MORE);
  /* header complete but payload short */
  assert(
    mon_response_decode(buf, n - 1, &out, &consumed) == MON_DECODE_NEED_MORE
  );
  /* bad version */
  buf[0] = 0xFF;
  assert(mon_response_decode(buf, n, &out, &consumed) == MON_DECODE_ERROR);
}

/* render a payload through a formatter into a stack buffer */
static int render(
  int (*fn)(const uint8_t *, size_t, FILE *), const uint8_t *p, size_t len,
  char *out, size_t out_len
) {
  FILE *f = fmemopen(out, out_len, "w");
  assert(f != NULL);
  const int rc = fn(p, len, f);
  fclose(f);
  return rc;
}

static void test_format_metrics(void) {
  uint8_t p[MON_METRICS_PAYLOAD_LEN];
  memset(p, 0, sizeof(p));
  p[7] = 5;     /* historic = 5     */
  p[15] = 2;    /* current  = 2     */
  p[22] = 0x03; /* bytes    = 1000  */
  p[23] = 0xE8;
  char out[256] = {0};
  assert(render(mon_format_metrics, p, sizeof(p), out, sizeof(out)) == 0);
  assert(strstr(out, "Historic connections: 5") != NULL);
  assert(strstr(out, "Current connections:  2") != NULL);
  assert(strstr(out, "Bytes transferred:    1000") != NULL);
  /* wrong length is rejected */
  assert(render(mon_format_metrics, p, sizeof(p) - 1, out, sizeof(out)) == -1);
}

static void test_format_users(void) {
  const uint8_t ok[] = {2, 5, 'a', 'l', 'i', 'c', 'e', 3, 'b', 'o', 'b'};
  char out[128] = {0};
  assert(render(mon_format_users, ok, sizeof(ok), out, sizeof(out)) == 0);
  assert(strstr(out, "alice") != NULL);
  assert(strstr(out, "bob") != NULL);

  /* claims 2 users but only carries one */
  const uint8_t bad[] = {2, 5, 'a', 'l', 'i', 'c', 'e'};
  assert(render(mon_format_users, bad, sizeof(bad), out, sizeof(out)) == -1);

  const uint8_t empty[] = {0};
  assert(render(mon_format_users, empty, sizeof(empty), out, sizeof(out)) == 0);
}

static void test_format_access_log(void) {
  const uint8_t e[] = {
    0,    1,                                  /* count = 1               */
    0,    0,    0,   0,   0,   0,   0,   0,   /* timestamp = epoch       */
    0x1F, 0x90,                               /* port = 8080             */
    3,    'b',  'o', 'b',                     /* user = bob              */
    7,    '1',  '.', '2', '.', '3', '.', '4', /* addr = 1.2.3.4     */
  };
  char out[256] = {0};
  assert(render(mon_format_access_log, e, sizeof(e), out, sizeof(out)) == 0);
  assert(strstr(out, "1970-01-01T00:00:00Z") != NULL);
  assert(strstr(out, "bob") != NULL);
  assert(strstr(out, "1.2.3.4:8080") != NULL);

  /* truncated last byte */
  assert(
    render(mon_format_access_log, e, sizeof(e) - 1, out, sizeof(out)) == -1
  );

  const uint8_t empty[] = {0, 0};
  assert(
    render(mon_format_access_log, empty, sizeof(empty), out, sizeof(out)) == 0
  );
}

/* ------------------------------------------------------------------ */
/* loopback integration test                                          */
/* ------------------------------------------------------------------ */

static void read_n(int fd, uint8_t *buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    const ssize_t r = recv(fd, buf + off, n - off, 0);
    if (r <= 0) _exit(1);
    off += (size_t) r;
  }
}

static void write_n(int fd, const uint8_t *buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    const ssize_t w = send(fd, buf + off, n - off, 0);
    if (w <= 0) _exit(1);
    off += (size_t) w;
  }
}

/* read and discard one whole request frame (VER CMD NARGS LENs PAYLOAD) */
static void drain_request(int fd) {
  uint8_t hdr[3];
  read_n(fd, hdr, 3);
  const uint8_t nargs = hdr[2];
  uint8_t lens[MON_MAX_ARGS];
  if (nargs > 0) read_n(fd, lens, nargs);
  size_t payload = 0;
  for (uint8_t i = 0; i < nargs; i++) payload += lens[i];
  uint8_t scratch[MON_MAX_ARGS * (MON_MAX_ARG_LEN + 1)];
  if (payload > 0) read_n(fd, scratch, payload);
}

static void
send_response(int fd, uint8_t status, const uint8_t *payload, uint16_t plen) {
  uint8_t hdr[MON_RESPONSE_HEADER_LEN] = {
    MON_VERSION, status, (uint8_t) (plen >> 8), (uint8_t) (plen & 0xFF)
  };
  write_n(fd, hdr, sizeof(hdr));
  if (plen > 0) write_n(fd, payload, plen);
}

/* child: a minimal blocking server speaking the monitoring protocol */
static void mock_server(int listenfd, uint8_t auth_status, uint8_t cmd_status) {
  const int c = accept(listenfd, NULL, NULL);
  if (c < 0) _exit(1);
  drain_request(c); /* AUTH */
  send_response(c, auth_status, NULL, 0);
  if (auth_status == MON_STATUS_OK) {
    drain_request(c); /* command */
    const uint8_t empty_users[] = {0};
    send_response(c, cmd_status, empty_users, sizeof(empty_users));
  }
  close(c);
  close(listenfd);
  _exit(0);
}

/* parent: drive the real non-blocking client against 127.0.0.1:port */
static int
run_client(fd_selector s, unsigned short port, struct client_args *args) {
  struct mon_client *c = malloc(sizeof(*c));
  assert(c != NULL);
  mon_client_init(c, args);

  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  assert(fd >= 0);
  assert(selector_fd_set_nio(fd) != -1);

  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(port);
  if (
    connect(fd, (struct sockaddr *) &a, sizeof(a)) < 0 && errno != EINPROGRESS
  ) {
    _exit(1);
  }
  assert(
    selector_register(s, fd, mon_client_handler(), OP_WRITE, c) ==
    SELECTOR_SUCCESS
  );

  while (!c->finished) assert(selector_select(s) == SELECTOR_SUCCESS);
  const int result = c->result;
  free(c);
  return result;
}

static void run_scenario(
  fd_selector s, uint8_t auth_status, uint8_t cmd_status, enum client_cmd cmd,
  int expected
) {
  int lfd = socket(AF_INET, SOCK_STREAM, 0);
  assert(lfd >= 0);
  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = 0; /* ephemeral */
  assert(bind(lfd, (struct sockaddr *) &a, sizeof(a)) == 0);
  assert(listen(lfd, 1) == 0);
  socklen_t alen = sizeof(a);
  assert(getsockname(lfd, (struct sockaddr *) &a, &alen) == 0);
  const unsigned short port = ntohs(a.sin_port);

  const pid_t pid = fork();
  assert(pid >= 0);
  if (pid == 0) {
    mock_server(lfd, auth_status, cmd_status); /* never returns */
  }
  close(lfd); /* parent does not accept */

  struct client_args args;
  memset(&args, 0, sizeof(args));
  args.username = "admin";
  args.password = "pass";
  args.cmd = cmd;
  args.arg_user = "victim";
  args.arg_pass = "pw";

  const int got = run_client(s, port, &args);
  int status = 0;
  waitpid(pid, &status, 0);
  assert(got == expected);
}

static void integration_tests(void) {
  signal(SIGPIPE, SIG_IGN);
  const struct selector_init conf = {
    .signal = SIGALRM,
    .select_timeout = {.tv_sec = 2, .tv_nsec = 0}
  };
  assert(selector_init(&conf) == 0);
  fd_selector s = selector_new(16);
  assert(s != NULL);

  /* auth ok + command ok -> success */
  run_scenario(
    s, MON_STATUS_OK, MON_STATUS_OK, CLIENT_CMD_LIST_USERS, MON_EXIT_OK
  );
  /* auth rejected -> exit 3 */
  run_scenario(
    s, MON_STATUS_AUTH_FAIL, 0, CLIENT_CMD_LIST_USERS, MON_EXIT_AUTH
  );
  /* auth ok but command error -> exit 4 */
  run_scenario(
    s, MON_STATUS_OK, MON_STATUS_USER_NOT_FOUND, CLIENT_CMD_DEL_USER,
    MON_EXIT_CMD
  );

  selector_destroy(s);
  selector_close();
}

int main(void) {
  test_decode_roundtrip();
  test_decode_need_more_and_bad_version();
  test_format_metrics();
  test_format_users();
  test_format_access_log();
  integration_tests();
  printf("mon_client: all tests passed\n");
  return 0;
}
