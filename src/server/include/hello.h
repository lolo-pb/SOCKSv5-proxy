#ifndef HELLO_H
#define HELLO_H

/**
 * hello.h - SOCKSv5 method negotiation parser (RFC 1928 section 3).
 *
 *   +----+----------+----------+
 *   |VER | NMETHODS | METHODS  |
 *   +----+----------+----------+
 *   | 1  |    1     | 1 to 255 |
 *   +----+----------+----------+
 */

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"

#define SOCKS_HELLO_NOAUTHENTICATION_REQUIRED 0x00
#define SOCKS_HELLO_GSSAPI 0x01
#define SOCKS_HELLO_USERNAME_PASSWORD 0x02
#define SOCKS_HELLO_NO_ACCEPTABLE_METHODS 0xFF

enum hello_state {
  hello_version,
  hello_nmethods,
  hello_methods,
  hello_done,
  hello_error_unsupported_version,
};

struct hello_parser {
  void (*on_authentication_method)(
    struct hello_parser *parser, const uint8_t method
  );
  void *data;

  enum hello_state state;
  uint8_t remaining;
};

void hello_parser_init(struct hello_parser *p);
enum hello_state hello_parser_feed(struct hello_parser *p, const uint8_t b);
enum hello_state
hello_consume(buffer *b, struct hello_parser *p, bool *errored);
bool hello_is_done(const enum hello_state state, bool *errored);
int hello_marshall(buffer *b, const uint8_t method);

#endif
