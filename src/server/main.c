/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de línea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en éste hilo.
 *
 * Se descargará en otro hilos las operaciones bloqueantes (resolución de
 * DNS utilizando getaddrinfo), pero toda esa complejidad está oculta en
 * el selector.
 */
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>// socket
#include <sys/types.h> // socket
#include <unistd.h>

#include "access_log.h"
#include "args.h"
#include "metrics.h"
#include "mon_nio.h"
#include "selector.h"
#include "socks5nio.h"
#include "user_table.h"

#define SERVER_BACKLOG SOMAXCONN

static volatile sig_atomic_t shutdown_signals = 0;

static void sigterm_handler(const int signal) {
  if ((signal == SIGTERM || signal == SIGINT) && shutdown_signals < 2) {
    shutdown_signals++;
  }
}

static void stop_accepting(fd_selector selector, int *server) {
  if (*server < 0) { return; }

  if (selector != NULL) { selector_unregister_fd(selector, *server); }
  close(*server);
  *server = -1;
}

static void print_startup_banner(const struct socks5args *args) {
  fprintf(stdout, "\033[H\033[2J\033[3J\033[H");
  fprintf(stdout, "  ______             _                _______  \n");
  fprintf(stdout, " / _____)           | |              ( ______) \n");
  fprintf(stdout, "( (____   ___   ____| |  _  ___ _   _| |____   \n");
  fprintf(stdout, " \\____ \\ / _ \\ / ___) |_/ )/___) | | (_____ \\  \n");
  fprintf(stdout, " _____) ) |_| ( (___|  _ ((___ )\\ V / _____) ) \n");
  fprintf(stdout, "(______/ \\___/ \\____)_| \\_(___/  \\_/ (______/  \n");
  fprintf(
    stdout, "Listening on TCP %s:%d\n", args->socks_addr, args->socks_port
  );
  fprintf(stdout, "Monitoring on TCP %s:%d\n", args->mng_addr, args->mng_port);
  fflush(stdout);
}

int main(const int argc, char **argv) {
  struct socks5args args;
  parse_args(argc, argv, &args);

  user_table_init();
  metrics_init();
  access_log_init();

  // load initial users from args
  for (unsigned i = 0; i < MAX_USERS; i++) {
    if (args.users[i].name != NULL) {
      user_table_add(args.users[i].name, args.users[i].pass);
    }
  }

  // nothing to read from stdin
  close(0);

  const char *err_msg = NULL;
  selector_status ss = SELECTOR_SUCCESS;
  fd_selector selector = NULL;
  int mng_server = -1;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(args.socks_port);
  if (inet_pton(AF_INET, args.socks_addr, &addr.sin_addr) != 1) {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }

  int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (server < 0) {
    err_msg = "unable to create socket";
    goto finally;
  }

  fprintf(stdout, "\033[2J\033[H");
  fprintf(stdout, "  ______             _                _______  \n");
  fprintf(stdout, " / _____)           | |              ( ______) \n");
  fprintf(stdout, "( (____   ___   ____| |  _  ___ _   _| |____   \n");
  fprintf(stdout, " \\____ \\ / _ \\ / ___) |_/ )/___) | | (_____ \\  \n");
  fprintf(stdout, " _____) ) |_| ( (___|  _ ((___ )\\ V / _____) ) \n");
  fprintf(stdout, "(______/ \\___/ \\____)_| \\_(___/  \\_/ (______/  \n");
  fprintf(stdout, "Listening on TCP %s:%d\n", args.socks_addr, args.socks_port);

  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

  if (bind(server, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    err_msg = "unable to bind socket";
    goto finally;
  }

  if (listen(server, SERVER_BACKLOG) < 0) {
    err_msg = "unable to listen";
    goto finally;
  }

  // signal handling for graceful shutdown

  struct sigaction shutdown_action = {
    .sa_handler = sigterm_handler,
  };
  sigemptyset(&shutdown_action.sa_mask);
  if (sigaction(SIGTERM, &shutdown_action, NULL) == -1 ||
      sigaction(SIGINT, &shutdown_action, NULL) == -1) {
    err_msg = "registering signal handlers";
    goto finally;
  }
  signal(SIGPIPE, SIG_IGN);

  if (selector_fd_set_nio(server) == -1) {
    err_msg = "getting server socket flags";
    goto finally;
  }
  const struct selector_init conf = {
    .signal = SIGALRM,
    .select_timeout =
      {
        .tv_sec = 10,
        .tv_nsec = 0,
      },
  };
  if (0 != selector_init(&conf)) {
    err_msg = "initializing selector";
    goto finally;
  }

  selector = selector_new(1024);
  if (selector == NULL) {
    err_msg = "unable to create selector";
    goto finally;
  }
  const struct fd_handler socksv5 = {

    .handle_read = socksv5_passive_accept,
    .handle_write = NULL,
    .handle_close = NULL,
  };
  ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
  if (ss != SELECTOR_SUCCESS) {
    err_msg = "registering fd";
    goto finally;
  }

  // monitoring passive socket
  {
    struct sockaddr_in mng_addr;
    memset(&mng_addr, 0, sizeof(mng_addr));
    mng_addr.sin_family = AF_INET;
    mng_addr.sin_port = htons(args.mng_port);
    if (inet_pton(AF_INET, args.mng_addr, &mng_addr.sin_addr) != 1) {
      mng_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    mng_server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (mng_server < 0) {
      err_msg = "unable to create monitoring socket";
      goto finally;
    }
    setsockopt(mng_server, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    if (bind(mng_server, (struct sockaddr *) &mng_addr, sizeof(mng_addr)) < 0) {
      err_msg = "unable to bind monitoring socket";
      goto finally;
    }
    if (listen(mng_server, 5) < 0) {
      err_msg = "unable to listen on monitoring socket";
      goto finally;
    }
    if (selector_fd_set_nio(mng_server) == -1) {
      err_msg = "setting monitoring socket non-blocking";
      goto finally;
    }
    const struct fd_handler mon = {
      .handle_read = mon_passive_accept,
      .handle_write = NULL,
      .handle_close = NULL,
    };
    ss = selector_register(selector, mng_server, &mon, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
      err_msg = "registering monitoring fd";
      goto finally;
    }
  }
  print_startup_banner(&args);

  bool draining = false;
  for (;;) {
    if (shutdown_signals > 0 && !draining) {
      fprintf(
        stderr, " : shutdown requested, waiting for active connections\n"
      );
      stop_accepting(selector, &server);
      stop_accepting(selector, &mng_server);
      draining = true;
    }
    if (shutdown_signals > 1) {
      fprintf(stderr, " : force shutdown requested\n");
      stop_accepting(selector, &server);
      stop_accepting(selector, &mng_server);
      socksv5_pool_force_shutdown(selector);
      break;
    }
    if (draining && socksv5_active_connections() == 0) { break; }

    err_msg = NULL;
    ss = selector_select(selector);
    if (ss != SELECTOR_SUCCESS) {
      err_msg = "serving";
      goto finally;
    }
  }

  int ret = 0;
finally:
  if (ss != SELECTOR_SUCCESS) {
    fprintf(
      stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
      ss == SELECTOR_IO ? strerror(errno) : selector_error(ss)
    );
    ret = 2;
  } else if (err_msg) {
    perror(err_msg);
    ret = 1;
  }
  if (selector != NULL) { socksv5_pool_force_shutdown(selector); }
  if (selector != NULL) { selector_destroy(selector); }
  selector_close();

  socksv5_pool_destroy();

  if (server >= 0) { close(server); }
  if (mng_server >= 0) { close(mng_server); }
  return ret;
}
