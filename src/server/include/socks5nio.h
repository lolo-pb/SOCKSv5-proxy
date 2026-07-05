#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H

/**
 * socks5nio.h - non-blocking I/O layer for SOCKS connections.
 *
 * Manages the client fd lifecycle: accept, read/write dispatch (to the
 * STM or relay), pool tracking, and graceful shutdown.
 */

#include <stddef.h>

#include "selector.h"

void socksv5_passive_accept(struct selector_key *key);
size_t socksv5_active_connections(void);
void socksv5_pool_force_shutdown(fd_selector selector);
void socksv5_pool_destroy(void);

#endif
