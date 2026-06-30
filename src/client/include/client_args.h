#ifndef CLIENT_ARGS_H
#define CLIENT_ARGS_H

#include <stdbool.h>

/** monitoring command selected on the command line (exactly one) */
enum client_cmd {
  CLIENT_CMD_NONE = 0,
  CLIENT_CMD_METRICS,    /* -m            */
  CLIENT_CMD_LIST_USERS, /* -U            */
  CLIENT_CMD_ADD_USER,   /* -a user:pass  */
  CLIENT_CMD_DEL_USER,   /* -d user       */
  CLIENT_CMD_ACCESS_LOG, /* --access-log  */
};

struct client_args {
  /* connection */
  char *mng_addr;          /* default 127.0.0.1 */
  unsigned short mng_port; /* default 8080      */

  /* credentials sent via MON_CMD_AUTH */
  char *username;
  char *password;

  /* selected command and its operands */
  enum client_cmd cmd;
  char *arg_user; /* add/del: target user name */
  char *arg_pass; /* add: target user password */
};

/**
 * Split a "user:pass" string in place: replaces the first ':' with '\0' and
 * makes *user / *pass point inside spec. Returns false if there is no ':' or
 * either side is empty. Used for -u and -a.
 */
bool client_split_credentials(char *spec, char **user, char **pass);

/**
 * Parse argv (getopt-style) into args, applying defaults first. On a usage
 * error prints a message + usage to stderr and exits(1); on -h/-v prints and
 * exits(0). On return, args is valid and exactly one command is selected.
 */
void client_parse_args(int argc, char **argv, struct client_args *args);

#endif
