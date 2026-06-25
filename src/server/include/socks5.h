#ifndef SOCKS5_H
#define SOCKS5_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "selector.h"
#include "stm.h"

#define SOCKS5_VERSION 0x05

typedef enum {
  SOCKS5_STATE_HELLO_READ,
  SOCKS5_STATE_REQUEST_READ,
} socks5_state;

typedef enum {
  SOCKS5_ACTION_READ,
  SOCKS5_ACTION_WRITE,
  SOCKS5_ACTION_CLOSE,
} socks5_action;

struct socks5 {
  struct state_machine stm;
  uint8_t read_buffer[1024];
  ssize_t read_bytes;
  uint8_t response[16];
  size_t response_bytes;
  int close_after_write;
};

void socks5_init(struct socks5 *socks);
socks5_action socks5_handle_read(struct socks5 *socks, struct selector_key *key);
socks5_action socks5_handle_write(
  struct socks5 *socks, struct selector_key *key, const uint8_t **data,
  size_t *bytes
);

#endif
