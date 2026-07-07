#ifndef MON_CLIENT_H
#define MON_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "buffer.h"
#include "client_args.h"
#include "mon_protocol.h"
#include "selector.h"
#include "stm.h"

/* process exit codes */
#define MON_EXIT_OK 0
#define MON_EXIT_IO 2        /* connection / socket error            */
#define MON_EXIT_AUTH 3      /* server rejected the credentials      */
#define MON_EXIT_CMD 4       /* server returned an error for the cmd */
#define MON_EXIT_MALFORMED 5 /* unparseable / oversized response     */

/* a response payload fits in LEN (uint16), so header + 64KiB is always enough */
#define MON_READ_BUF_SIZE (MON_RESPONSE_HEADER_LEN + (1 << 16))
#define MON_WRITE_BUF_SIZE 1024

/**
 * State held for one monitoring-client connection. The struct is owned by
 * main(): it is attached as the selector key's `data`, reused across connect
 * retries, and freed by main() at the end (handle_close does NOT free it).
 */
struct mon_client {
  struct state_machine stm;
  const struct client_args *args;

  buffer read_buffer;
  buffer write_buffer;
  uint8_t raw_read[MON_READ_BUF_SIZE];
  uint8_t raw_write[MON_WRITE_BUF_SIZE];

  bool finished;       /* the selector loop for the current fd should stop  */
  bool connect_failed; /* stop reason was a connect failure -> try next addr */
  int result;          /* exit code, valid when finished && !connect_failed */
};

/** (re)initialise a client for a fresh connection attempt (resets stm+buffers). */
void mon_client_init(struct mon_client *c, const struct client_args *args);

/** the fd_handler to register a connecting client socket with. */
const struct fd_handler *mon_client_handler(void);

/* response payload formatters - exposed for unit testing.
 * Each returns 0 on success, -1 if the payload is malformed/truncated. */
int mon_format_metrics(const uint8_t *payload, size_t len, FILE *out);
int mon_format_users(const uint8_t *payload, size_t len, FILE *out);
int mon_format_access_log(const uint8_t *payload, size_t len, FILE *out);

#endif
