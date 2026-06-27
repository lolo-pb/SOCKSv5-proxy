#include <errno.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <string.h> /* memset, strcpy */

#include "args.h"

#define DEFAULT_USERS_FILE "users.conf"

static unsigned short port(const char *s) {
  char *end = 0;
  const long sl = strtol(s, &end, 10);

  if (end == s || '\0' != *end ||
      ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 ||
      sl > USHRT_MAX) {
    fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
    exit(1);
    return 1;
  }
  return (unsigned short) sl;
}

static void user(char *s, struct users *user) {
  char *p = strchr(s, ':');
  if (p == NULL) {
    fprintf(stderr, "password not found\n");
    exit(1);
  } else {
    *p = 0;
    p++;
    user->name = s;
    user->pass = p;
  }
}

static void add_user(char *s, struct socks5args *args, int *nusers) {
  if (*nusers >= MAX_USERS) {
    fprintf(stderr, "maximun number of users reached: %d.\n", MAX_USERS);
    exit(1);
  }
  user(s, args->users + *nusers);
  *nusers += 1;
}

static void users_file(const char *path, struct socks5args *args, int *nusers) {
  FILE *f = fopen(path, "r");
  if (f == NULL) {
    perror(path);
    exit(1);
  }

  char line[512];
  while (fgets(line, sizeof(line), f) != NULL) {
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '\0' || line[0] == '#') { continue; }
    if (*nusers >= MAX_USERS) {
      fprintf(stderr, "maximun number of users reached: %d.\n", MAX_USERS);
      fclose(f);
      exit(1);
    }
    strcpy(args->users_storage[*nusers], line);
    add_user(args->users_storage[*nusers], args, nusers);
  }

  fclose(f);
}

static void version(void) {
  fprintf(
    stderr, "socks5v version 0.0\n"
            "ITBA Protocolos de Comunicación 2025/1 -- Grupo X\n"
            "AQUI VA LA LICENCIA\n"
  );
}

//** AK estan todos los comandos, se pueden ver */
static void usage(const char *progname) {
  fprintf(
    stderr,
    "Usage: %s [OPTION]...\n"
    "\n"
    "   -h               Imprime la ayuda y termina.\n"
    "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
    "   -L <conf  addr>  Dirección donde servirá el servicio de management.\n"
    "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
    "   -P <conf port>   Puerto entrante conexiones configuracion\n"
    "   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el "
    "proxy. Hasta 10.\n"
    "   -U[users file]   Archivo con usuarios, uno por línea: <name>:<pass>.\n"
    "                    Si no se indica archivo usa users.conf.\n"
    "   -v               Imprime información sobre la versión versión y "
    "termina.\n"

    "\n",
    progname
  );
  exit(1);
}

void parse_args(const int argc, char **argv, struct socks5args *args) {
  memset(
    args, 0, sizeof(*args)
  );// sobre todo para setear en null los punteros de users

  args->socks_addr = "0.0.0.0";
  args->socks_port = 1080;

  args->mng_addr = "127.0.0.1";
  args->mng_port = 8080;

  args->disectors_enabled = true;

  int c;
  int nusers = 0;

  while (true) {
    int option_index = 0;
    static struct option long_options[] = {{0, 0, 0, 0}};

    c = getopt_long(argc, argv, "hl:L:Np:P:u:U::v", long_options, &option_index);
    if (c == -1) break;

    switch (c) {
      case 'h':
        usage(argv[0]);
        break;
      case 'l':
        args->socks_addr = optarg;
        break;
      case 'L':
        args->mng_addr = optarg;
        break;
      case 'N':
        args->disectors_enabled = false;
        break;
      case 'p':
        args->socks_port = port(optarg);
        break;
      case 'P':
        args->mng_port = port(optarg);
        break;
      case 'u':
        add_user(optarg, args, &nusers);
        break;
      case 'U':
        if (optarg == NULL && optind < argc && argv[optind][0] != '-') {
          optarg = argv[optind++];
        }
        users_file(optarg == NULL ? DEFAULT_USERS_FILE : optarg, args, &nusers);
        break;
      case 'v':
        version();
        exit(0);
      default:
        fprintf(stderr, "unknown argument %d.\n", c);
        exit(1);
    }
  }
  if (optind < argc) {
    fprintf(stderr, "argument not accepted: ");
    while (optind < argc) { fprintf(stderr, "%s ", argv[optind++]); }
    fprintf(stderr, "\n");
    exit(1);
  }
}
