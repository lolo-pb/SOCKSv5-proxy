#include "client_args.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_MNG_ADDR "127.0.0.1"
#define DEFAULT_MNG_PORT 8080

/* long-only option ids (above the ASCII range) */
#define OPT_ACCESS_LOG 256

static void usage(const char *progname) {
  fprintf(
    stderr,
    "Usage: %s [-L addr] [-P port] [-u user:pass] [command]\n"
    "\n"
    "  -L <addr>       management address (default " DEFAULT_MNG_ADDR ")\n"
    "  -P <port>       management port (default %d)\n"
    "  -u <user:pass>  admin credentials\n"
    "  -h              print this help and exit\n"
    "  -v              print version and exit\n"
    "\n"
    "Commands (optional; omit to open interactive UI):\n"
    "  -m              get metrics\n"
    "  -U              list users\n"
    "  -a <user:pass>  add user\n"
    "  -d <user>       delete user\n"
    "  --access-log    dump the access log\n",
    progname, DEFAULT_MNG_PORT
  );
}

static unsigned short parse_port(const char *s) {
  char *end = NULL;
  errno = 0;
  const long v = strtol(s, &end, 10);
  if (end == s || *end != '\0' || errno == ERANGE || v <= 0 || v > USHRT_MAX) {
    fprintf(stderr, "client: invalid port: %s\n", s);
    exit(1);
  }
  return (unsigned short) v;
}

bool client_split_credentials(char *spec, char **user, char **pass) {
  if (spec == NULL) return false;
  char *colon = strchr(spec, ':');
  if (colon == NULL || colon == spec || colon[1] == '\0') return false;
  *colon = '\0';
  *user = spec;
  *pass = colon + 1;
  return true;
}

/* select a command, refusing if one was already chosen */
static void
set_cmd(struct client_args *args, enum client_cmd cmd, const char *progname) {
  if (args->cmd != CLIENT_CMD_NONE) {
    fprintf(stderr, "client: only one command may be given\n");
    usage(progname);
    exit(1);
  }
  args->cmd = cmd;
}

void client_parse_args(int argc, char **argv, struct client_args *args) {
  memset(args, 0, sizeof(*args));
  args->mng_addr = DEFAULT_MNG_ADDR;
  args->mng_port = DEFAULT_MNG_PORT;
  args->cmd = CLIENT_CMD_NONE;

  static const struct option long_options[] = {
    {"access-log", no_argument, NULL, OPT_ACCESS_LOG},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {NULL, 0, NULL, 0},
  };

  int c;
  while ((c = getopt_long(argc, argv, "hvmUa:d:L:P:u:", long_options, NULL)) !=
         -1) {
    switch (c) {
      case 'h':
        usage(argv[0]);
        exit(0);
      case 'v':
        fprintf(stdout, "mng_client 1.0\n");
        exit(0);
      case 'L':
        args->mng_addr = optarg;
        break;
      case 'P':
        args->mng_port = parse_port(optarg);
        break;
      case 'u':
        if (!client_split_credentials(
              optarg, &args->username, &args->password
            )) {
          fprintf(stderr, "client: -u expects user:pass\n");
          exit(1);
        }
        break;
      case 'm':
        set_cmd(args, CLIENT_CMD_METRICS, argv[0]);
        break;
      case 'U':
        set_cmd(args, CLIENT_CMD_LIST_USERS, argv[0]);
        break;
      case 'a':
        set_cmd(args, CLIENT_CMD_ADD_USER, argv[0]);
        if (!client_split_credentials(
              optarg, &args->arg_user, &args->arg_pass
            )) {
          fprintf(stderr, "client: -a expects user:pass\n");
          exit(1);
        }
        break;
      case 'd':
        set_cmd(args, CLIENT_CMD_DEL_USER, argv[0]);
        args->arg_user = optarg;
        break;
      case OPT_ACCESS_LOG:
        set_cmd(args, CLIENT_CMD_ACCESS_LOG, argv[0]);
        break;
      default:
        usage(argv[0]);
        exit(1);
    }
  }

  if (optind < argc) {
    fprintf(stderr, "client: unexpected argument: %s\n", argv[optind]);
    usage(argv[0]);
    exit(1);
  }
  if (args->cmd != CLIENT_CMD_NONE && args->username == NULL) {
    fprintf(stderr, "client: credentials required (-u user:pass)\n");
    usage(argv[0]);
    exit(1);
  }
}
