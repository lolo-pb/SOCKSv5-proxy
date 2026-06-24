#ifndef SOCKS5_H
#define SOCKS5_H

#include <stddef.h>
#include <stdint.h>

#include "selector.h"

#define SOCKS5_VERSION 0x05

typedef enum {
  SOCKS5_ACTION_READ,
  SOCKS5_ACTION_WRITE,
  SOCKS5_ACTION_CLOSE,
} socks5_action;

socks5_action socks5_handle_read(struct selector_key *key);

#endif
