#include "mon_parser.h"

void mon_parser_init(struct mon_parser *p) {
  p->state = mon_parser_version;
  p->current_arg = 0;
  p->current_arg_offset = 0;
  p->request.version = 0;
  p->request.cmd = 0;
  p->request.nargs = 0;
}

enum mon_parser_state mon_parser_feed(struct mon_parser *p, uint8_t b) {
  switch (p->state) {
    case mon_parser_version:
      if (b != MON_VERSION) {
        p->state = mon_parser_error;
      } else {
        p->request.version = b;
        p->state = mon_parser_cmd;
      }
      break;

    case mon_parser_cmd:
      p->request.cmd = b;
      p->state = mon_parser_nargs;
      break;

    case mon_parser_nargs:
      if (b > MON_MAX_ARGS) {
        p->state = mon_parser_error;
      } else {
        p->request.nargs = b;
        p->current_arg = 0;
        p->state = (b == 0) ? mon_parser_done : mon_parser_arg_len;
      }
      break;

    case mon_parser_arg_len:
      if (b > MON_MAX_ARG_LEN) {
        p->state = mon_parser_error;
        break;
      }
      p->request.arg_lens[p->current_arg] = b;
      p->current_arg++;
      if (p->current_arg >= p->request.nargs) {
        p->current_arg = 0;
        p->current_arg_offset = 0;
        while (p->current_arg < p->request.nargs &&
               p->request.arg_lens[p->current_arg] == 0) {
          p->request.args[p->current_arg][0] = '\0';
          p->current_arg++;
        }
        p->state = p->current_arg >= p->request.nargs ? mon_parser_done
                                                      : mon_parser_arg_data;
      }
      break;

    case mon_parser_arg_data:
      p->request.args[p->current_arg][p->current_arg_offset++] = (char) b;
      if (p->current_arg_offset >= p->request.arg_lens[p->current_arg]) {
        p->request.args[p->current_arg][p->current_arg_offset] = '\0';
        p->current_arg++;
        p->current_arg_offset = 0;
        while (p->current_arg < p->request.nargs &&
               p->request.arg_lens[p->current_arg] == 0) {
          p->request.args[p->current_arg][0] = '\0';
          p->current_arg++;
        }
        if (p->current_arg >= p->request.nargs) { p->state = mon_parser_done; }
      }
      break;

    case mon_parser_done:
    case mon_parser_error:
      break;
  }
  return p->state;
}

bool mon_parser_is_done(enum mon_parser_state state, bool *errored) {
  if (state == mon_parser_error) {
    if (errored != NULL) *errored = true;
    return true;
  }
  return state == mon_parser_done;
}

enum mon_parser_state
mon_parser_consume(buffer *b, struct mon_parser *p, bool *errored) {
  enum mon_parser_state st = p->state;
  while (buffer_can_read(b)) {
    st = mon_parser_feed(p, buffer_read(b));
    if (mon_parser_is_done(st, errored)) break;
  }
  return st;
}
