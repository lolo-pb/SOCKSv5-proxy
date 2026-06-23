#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H

#include "selector.h"

void socksv5_passive_accept(struct selector_key *key);
void socksv5_pool_destroy(void);

#endif
