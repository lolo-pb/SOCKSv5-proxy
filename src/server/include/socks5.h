#ifndef SOCKS5_H
#define SOCKS5_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "args.h"
#include "auth.h"
#include "buffer.h"
#include "hello.h"
#include "request.h"
#include "selector.h"
#include "stm.h"

#define SOCKS5_VERSION 0x05

#define AUTH_VERSION 0x01
#define AUTH_STATUS_SUCCESS 0x00
#define AUTH_STATUS_FAILURE 0x01

struct addrinfo;
// That is a forward declaration, real definition comes
// from <netdb.h> in socks5.c.

typedef enum {
  SOCKS5_STATE_HELLO_READ,
  SOCKS5_STATE_HELLO_WRITE,
  SOCKS5_STATE_AUTH_READ,
  SOCKS5_STATE_AUTH_WRITE,
  SOCKS5_STATE_REQUEST_READ,
  SOCKS5_STATE_CONNECTING,
  SOCKS5_STATE_REQUEST_WRITE,
  SOCKS5_STATE_RELAY,
  SOCKS5_STATE_DONE,
  SOCKS5_STATE_ERROR,
} socks5_state;

typedef enum {
  SOCKS5_ACTION_NONE,
  SOCKS5_ACTION_NOOP,
  SOCKS5_ACTION_READ,
  SOCKS5_ACTION_WRITE,
  SOCKS5_ACTION_CLOSE,
} socks5_action;

struct socks5 {
  // lifecycle
  atomic_uint references;
  struct state_machine stm;
  struct socks5 *pool_next;// this makes this a linked list fir cleanup


  // sockets
  int client_fd;
  int origin_fd;

  // dns
  int dns_error;
  struct addrinfo *dns_result;
  struct addrinfo *dns_next;
  pthread_mutex_t dns_mutex;// this is for dns response buffer writing it isn't
                            // really needed but its beter practice so fuck it

  // buffers
  uint8_t raw_read_buffer[4096];
  uint8_t raw_write_buffer[4096];
  buffer read_buffer; // used as client-to-origin buffer during relay
  buffer write_buffer;// used as origin-to-client buffer during relay

  // parsers
  struct hello_parser hello;
  struct auth_parser auth;
  struct request_parser request;

  // protocol results
  uint8_t selected_method;
  uint8_t auth_status;
  uint8_t request_reply;

  // flags
  bool closing;          // true while connection_close is already running
  bool client_registered;// client fd is still registered in the selector
  bool origin_registered;// origin fd is still registered in the selector
  bool relay_started;
  bool client_eof;           // client will not send us more bytes
  bool origin_eof;           // origin will not send us more bytes
  bool client_write_shutdown;// proxy will not write more bytes to client
  bool origin_write_shutdown;// proxy will not write more bytes to origin
  bool dns_pending;
  bool cancelled;
};

void socks5_set_args(struct socks5args *args);
void socks5_init(struct socks5 *socks);
void socks5_ref(struct socks5 *socks);
void socks5_release(struct socks5 *socks);
void socks5_set_client_fd(struct socks5 *socks, int client_fd);
void socks5_cancel(struct socks5 *socks);
void socks5_connection_close(struct socks5 *socks, fd_selector selector);
bool socks5_is_relaying(struct socks5 *socks);
socks5_action
socks5_relay_client_read(struct socks5 *socks, struct selector_key *key);
socks5_action
socks5_relay_client_write(struct socks5 *socks, struct selector_key *key);
socks5_action
socks5_handle_read(struct socks5 *socks, struct selector_key *key);
socks5_action
socks5_handle_write(struct socks5 *socks, struct selector_key *key);
socks5_action
socks5_handle_block_done(struct socks5 *socks, struct selector_key *key);

#endif
