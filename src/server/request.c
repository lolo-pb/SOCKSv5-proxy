#include "request.h"

#include "socks5.h"

void request_parser_init(struct request_parser *p) {
  p->state = request_version;
  p->command = 0;
  p->atyp = 0;
  p->address_len = 0;
  p->address_index = 0;
  p->port[0] = 0;
  p->port[1] = 0;
  p->port_index = 0;
}

enum request_state request_parser_feed(struct request_parser *p, const uint8_t b) {
  switch (p->state) {
    case request_version:
      p->state = (b == SOCKS5_VERSION) ? request_command
                                       : request_error_unsupported_version;
      break;
    case request_command:
      p->command = b;
      p->state = request_reserved;
      break;
    case request_reserved:
      p->state = (b == 0x00) ? request_atyp : request_error_unsupported_version;
      break;
    case request_atyp:
      p->atyp = b;
      p->address_index = 0;
      if (b == SOCKS5_ATYP_IPV4) {
        p->address_len = 4;
        p->state = request_dst_addr;
      } else if (b == SOCKS5_ATYP_IPV6) {
        p->address_len = 16;
        p->state = request_dst_addr;
      } else if (b == SOCKS5_ATYP_DOMAINNAME) {
        p->address_len = 0;
        p->state = request_dst_addr;
      } else {
        p->state = request_error_unsupported_atyp;
      }
      break;
    case request_dst_addr:
      if (p->atyp == SOCKS5_ATYP_DOMAINNAME && p->address_len == 0) {
        p->address_len = b;
        if (p->address_len == 0) { p->state = request_error_unsupported_atyp; }
      } else {
        p->address[p->address_index++] = b;
        if (p->address_index == p->address_len) {
          p->port_index = 0;
          p->state = request_dst_port;
        }
      }
      break;
    case request_dst_port:
      p->port[p->port_index++] = b;
      if (p->port_index == 2) { p->state = request_done; }
      break;
    case request_done:
    case request_error_unsupported_version:
    case request_error_unsupported_atyp:
      break;
  }
  return p->state;
}

bool request_is_done(const enum request_state state, bool *errored) {
  bool ret;
  switch (state) {
    case request_error_unsupported_version:
    case request_error_unsupported_atyp:
      if (errored != NULL) { *errored = true; }
      ret = true;
      break;
    case request_done:
      ret = true;
      break;
    default:
      ret = false;
      break;
  }
  return ret;
}

enum request_state
request_consume(buffer *b, struct request_parser *p, bool *errored) {
  enum request_state st = p->state;
  while (buffer_can_read(b)) {
    const uint8_t c = buffer_read(b);
    st = request_parser_feed(p, c);
    if (request_is_done(st, errored)) { break; }
  }
  return st;
}

int request_marshall_reply(buffer *b, const uint8_t reply) {
  size_t n;
  uint8_t *buff = buffer_write_ptr(b, &n);
  if (n < 10) { return -1; }
  buff[0] = SOCKS5_VERSION;
  buff[1] = reply;
  buff[2] = 0x00;
  buff[3] = SOCKS5_ATYP_IPV4;
  buff[4] = 0x00;
  buff[5] = 0x00;
  buff[6] = 0x00;
  buff[7] = 0x00;
  buff[8] = 0x00;
  buff[9] = 0x00;
  buffer_write_adv(b, 10);
  return 10;
}
