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

#include "args.h"
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

static int passive_socket(const char *listen_addr, unsigned short listen_port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(listen_port);
  if (inet_pton(AF_INET, listen_addr, &addr.sin_addr) != 1) {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }

  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) { return -1; }

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

  if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
      listen(fd, SERVER_BACKLOG) < 0) {
    close(fd);
    return -1;
  }

  return fd;
}

static void init_management_users(const struct socks5args *args) {
  user_table_init();
  for (unsigned i = 0; i < MAX_USERS; i++) {
    if (args->users[i].name != NULL && args->users[i].pass != NULL) {
      user_table_add(args->users[i].name, args->users[i].pass);
    }
  }
}

int main(const int argc, char **argv) {
  struct socks5args args;
  parse_args(argc, argv, &args);
  socksv5_init(&args);
  init_management_users(&args);

  // no tenemos nada que leer de stdin
  close(0);

  const char *err_msg = NULL;
  selector_status ss = SELECTOR_SUCCESS;
  fd_selector selector = NULL;
  int server = -1;
  int mng_server = -1;

  server = passive_socket(args.socks_addr, args.socks_port);
  if (server < 0) {
    err_msg = "unable to create SOCKS socket";
    goto finally;
  }
  mng_server = passive_socket(args.mng_addr, args.mng_port);
  if (mng_server < 0) {
    err_msg = "unable to create management socket";
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
  fprintf(
    stdout, "Management on TCP %s:%d\n", args.mng_addr, args.mng_port
  );

  // registrar sigterm es útil para terminar el programa normalmente.
  // esto ayuda mucho en herramientas como valgrind.
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
  if (selector_fd_set_nio(mng_server) == -1) {
    err_msg = "getting management socket flags";
    goto finally;
  }
  const struct selector_init conf = {
    .signal = SIGALRM,
    .select_timeout = {
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
    // aca va la salsa del socks5nio.c
    .handle_read = socksv5_passive_accept,
    .handle_write = NULL,
    .handle_close = NULL,// nada que liberar
  };
  ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
  if (ss != SELECTOR_SUCCESS) {
    err_msg = "registering SOCKS fd";
    goto finally;
  }
  const struct fd_handler mon = {
    .handle_read = mon_passive_accept,
    .handle_write = NULL,
    .handle_close = NULL,
  };
  ss = selector_register(selector, mng_server, &mon, OP_READ, NULL);
  if (ss != SELECTOR_SUCCESS) {
    err_msg = "registering management fd";
    goto finally;
  }
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
