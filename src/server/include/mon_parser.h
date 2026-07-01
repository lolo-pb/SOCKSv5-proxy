#ifndef MON_PARSER_H
#define MON_PARSER_H

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"
#include "mon_protocol.h"

/**
 * Byte-by-byte parser for monitoring protocol requests.
 *
 * Feeds bytes from a buffer and populates a mon_request struct.
 */

enum mon_parser_state {
  mon_parser_version,
  mon_parser_cmd,
  mon_parser_nargs,
  mon_parser_arg_len,
  mon_parser_arg_data,
  mon_parser_done,
  mon_parser_error,
};

struct mon_parser {
  enum mon_parser_state state;
  struct mon_request request;
  uint8_t current_arg;
  uint8_t current_arg_offset;
};

void mon_parser_init(struct mon_parser *p);
enum mon_parser_state mon_parser_feed(struct mon_parser *p, uint8_t b);
enum mon_parser_state
mon_parser_consume(buffer *b, struct mon_parser *p, bool *errored);
bool mon_parser_is_done(enum mon_parser_state state, bool *errored);

#endif
