#ifndef AUTH_H
#define AUTH_H

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"

enum auth_state {
  auth_version,
  auth_ulen,
  auth_uname,
  auth_plen,
  auth_passwd,
  auth_done,
  auth_error_unsupported_version,
};

struct auth_parser {
  enum auth_state state;
  uint8_t ulen, plen;
  uint8_t i;
  char uname[256];
  char passwd[256];
};

void auth_parser_init(struct auth_parser *p);
enum auth_state auth_parser_feed(struct auth_parser *p, const uint8_t b);
enum auth_state auth_consume(buffer *b, struct auth_parser *p, bool *errored);
bool auth_is_done(const enum auth_state state, bool *errored);
int auth_marshall(buffer *b, const uint8_t status);

#endif
