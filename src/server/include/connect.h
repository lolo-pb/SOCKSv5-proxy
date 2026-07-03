#ifndef CONNECT_H
#define CONNECT_H

#include <stdint.h>

#include "selector.h"

struct socks5;

/**
 * Starts the origin connection based on the parsed request address type.
 * Returns 0 on immediate success, EINPROGRESS if async, or errno on failure.
 */
int connect_to_origin(struct socks5 *socks, struct selector_key *key);

/**
 * Maps an errno from connect() to the appropriate SOCKS5 reply code.
 */
uint8_t connect_reply_from_errno(int error);

/**
 * Writes the SOCKS reply (success or error) into the client write buffer.
 * Returns the next STM state (REQUEST_WRITE or ERROR).
 */
unsigned connect_marshall_reply(struct socks5 *socks);

/**
 * Returns the fd_handler for the origin fd (used during connect and relay).
 */
const struct fd_handler *connect_origin_handler(void);

#endif
