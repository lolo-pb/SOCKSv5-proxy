#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "client_args.h"
#include "client_ui.h"
#include "mng_client.h"
#include "selector.h"

/* overall deadline for the whole exchange (connect + auth + command) */
#define CLIENT_TIMEOUT_SEC 10

static int run_against_addr(
  fd_selector s, struct mng_client *client, const struct client_args *args,
  const struct addrinfo *rp, time_t deadline
);

int main(int argc, char *argv[]) {
  struct client_args args;
  client_parse_args(argc, argv, &args); /* exits on error / -h / -v */
  if (args.cmd == CLIENT_CMD_NONE) return client_ui_run(&args);

  /* a closed peer must not kill us with SIGPIPE; we check send()/recv(). */
  signal(SIGPIPE, SIG_IGN);

  char portstr[6];
  snprintf(portstr, sizeof(portstr), "%u", args.mng_port);

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *res = NULL;
  const int gai = getaddrinfo(args.mng_addr, portstr, &hints, &res);
  if (gai != 0) {
    fprintf(
      stderr, "client: cannot resolve %s:%s: %s\n", args.mng_addr, portstr,
      gai_strerror(gai)
    );
    return MNG_EXIT_IO;
  }

  const struct selector_init conf = {
    .signal = SIGALRM,
    .select_timeout = {.tv_sec = 1, .tv_nsec = 0},
  };
  if (selector_init(&conf) != 0) {
    fprintf(stderr, "client: cannot initialize selector\n");
    freeaddrinfo(res);
    return MNG_EXIT_IO;
  }

  fd_selector s = selector_new(16);
  struct mng_client *client = malloc(sizeof(*client));
  int exit_code = MNG_EXIT_IO;
  if (s == NULL || client == NULL) {
    fprintf(stderr, "client: out of memory\n");
    goto finally;
  }

  const time_t deadline = time(NULL) + CLIENT_TIMEOUT_SEC;

  /* robustness: try each resolved address until one works */
  bool connected = false;
  for (const struct addrinfo *rp = res; rp != NULL && !connected;
       rp = rp->ai_next) {
    const int rc = run_against_addr(s, client, &args, rp, deadline);
    if (rc >= 0) {
      exit_code = rc;
      connected = true;
    }
  }
  if (!connected) {
    fprintf(
      stderr, "client: could not connect to %s:%s\n", args.mng_addr, portstr
    );
    exit_code = MNG_EXIT_IO;
  }

finally:
  free(client);
  if (s != NULL) selector_destroy(s);
  selector_close();
  freeaddrinfo(res);
  return exit_code;
}

/**
 * Run one connection attempt against a single resolved address.
 * Returns the process exit code (>= 0) once the exchange completes, or -1 if
 * the connection itself failed and the caller should try the next address.
 */
static int run_against_addr(
  fd_selector s, struct mng_client *client, const struct client_args *args,
  const struct addrinfo *rp, time_t deadline
) {
  const int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
  if (fd < 0) return -1;
  if (selector_fd_set_nio(fd) == -1) {
    close(fd);
    return -1;
  }
  if (connect(fd, rp->ai_addr, rp->ai_addrlen) < 0 && errno != EINPROGRESS) {
    close(fd); /* immediate failure -> try next address */
    return -1;
  }

  mng_client_init(client, args);
  if (
    selector_register(s, fd, mng_client_handler(), OP_WRITE, client) !=
    SELECTOR_SUCCESS
  ) {
    close(fd);
    return -1;
  }

  while (!client->finished) {
    if (selector_select(s) != SELECTOR_SUCCESS) {
      selector_unregister_fd(s, fd);
      close(fd);
      return MNG_EXIT_IO;
    }
    if (time(NULL) >= deadline) {
      fprintf(stderr, "client: timed out\n");
      selector_unregister_fd(s, fd);
      close(fd);
      return MNG_EXIT_IO;
    }
  }

  /* mng_finish() already unregistered + closed the fd */
  if (client->connect_failed) return -1; /* try the next address */
  return client->result;
}
