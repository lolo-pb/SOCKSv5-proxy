#ifndef SOCKS5_H
#define SOCKS5_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "args.h"
#include "auth.h"
#include "buffer.h"
#include "hello.h"
#include "selector.h"
#include "stm.h"

#define SOCKS5_VERSION 0x05

#define AUTH_VERSION 0x01
#define AUTH_STATUS_SUCCESS 0x00
#define AUTH_STATUS_FAILURE 0x01

typedef enum {
  SOCKS5_STATE_HELLO_READ,
  SOCKS5_STATE_HELLO_WRITE,
  SOCKS5_STATE_AUTH_READ,
  SOCKS5_STATE_AUTH_WRITE,
  SOCKS5_STATE_REQUEST_READ,
  SOCKS5_STATE_DONE,
  SOCKS5_STATE_ERROR,
} socks5_state;

typedef enum {
  SOCKS5_ACTION_READ,
  SOCKS5_ACTION_WRITE,
  SOCKS5_ACTION_CLOSE,
} socks5_action;

struct socks5 {
  struct state_machine stm;
  uint8_t raw_read_buffer[4096];
  uint8_t raw_write_buffer[4096];
  buffer read_buffer;
  buffer write_buffer;
  struct hello_parser hello;
  struct auth_parser auth;
  uint8_t selected_method;
  uint8_t auth_status;
};

void socks5_set_args(struct socks5args *args);
void socks5_init(struct socks5 *socks);
socks5_action
socks5_handle_read(struct socks5 *socks, struct selector_key *key);
socks5_action
socks5_handle_write(struct socks5 *socks, struct selector_key *key);

#endif
