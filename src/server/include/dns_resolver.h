#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include "selector.h"

struct socks5;

/**
 * Starts async DNS resolution for the FQDN in socks->request.address.
 * Returns EINPROGRESS on success (result delivered via selector_notify_block),
 * or an errno value on failure.
 */
int dns_resolve_start(struct socks5 *socks, struct selector_key *key);

#endif
