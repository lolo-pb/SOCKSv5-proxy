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
#include "selector.h"
#include "socks5nio.h"

static bool done = false;

static void sigterm_handler(const int signal) {
  printf("signal %d, cleaning up and exiting\n", signal);
  done = true;
}

int main(const int argc, char **argv) {
  struct socks5args args;
  parse_args(argc, argv, &args);
  socksv5_init(&args);

  // no tenemos nada que leer de stdin
  close(0);

  const char *err_msg = NULL;
  selector_status ss = SELECTOR_SUCCESS;
  fd_selector selector = NULL;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(args.socks_port);
  if (inet_pton(AF_INET, args.socks_addr, &addr.sin_addr) != 1) {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }

  const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (server < 0) {
    err_msg = "unable to create socket";
    goto finally;
  }

  fprintf(stdout, "  ______             _                _______  \n");
  fprintf(stdout, " / _____)           | |              ( ______) \n");
  fprintf(stdout, "( (____   ___   ____| |  _  ___ _   _| |____   \n");
  fprintf(stdout, " \\____ \\ / _ \\ / ___) |_/ )/___) | | (_____ \\  \n");
  fprintf(stdout, " _____) ) |_| ( (___|  _ ((___ )\\ V / _____) ) \n");
  fprintf(stdout, "(______/ \\___/ \\____)_| \\_(___/  \\_/ (______/  \n");

  fprintf(stdout, "Listening on TCP %s:%d\n", args.socks_addr, args.socks_port);

  // man 7 ip. no importa reportar nada si falla.
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

  if (bind(server, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    err_msg = "unable to bind socket";
    goto finally;
  }

  if (listen(server, 20) < 0) {// TODO : hardcoded 20, noc bien que es
    err_msg = "unable to listen";
    goto finally;
  }

  // registrar sigterm es útil para terminar el programa normalmente.
  // esto ayuda mucho en herramientas como valgrind.
  signal(SIGTERM, sigterm_handler);
  signal(SIGINT, sigterm_handler);
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
    // TODO : aca va la salsa del socks5nio.c
    .handle_read = socksv5_passive_accept,
    .handle_write = NULL,
    .handle_close = NULL,// nada que liberar
  };
  ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
  if (ss != SELECTOR_SUCCESS) {
    err_msg = "registering fd";
    goto finally;
  }
  for (; !done;) {
    err_msg = NULL;
    ss = selector_select(selector);
    if (ss != SELECTOR_SUCCESS) {
      err_msg = "serving";
      goto finally;
    }
  }
  if (err_msg == NULL) { err_msg = "closing"; }

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
  if (selector != NULL) { selector_destroy(selector); }
  selector_close();

  socksv5_pool_destroy();

  if (server >= 0) { close(server); }
  return ret;
}
