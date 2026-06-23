/**
 * auth.c - parser de la sub-negociación usuario/contraseña (RFC1929).
 */
#include "auth.h"
#include "socks5.h"

void auth_parser_init(struct auth_parser *p) {
  p->state = auth_version;
  p->ulen = 0;
  p->plen = 0;
  p->i = 0;
  p->uname[0] = '\0';
  p->passwd[0] = '\0';
}

enum auth_state auth_parser_feed(struct auth_parser *p, const uint8_t b) {
  switch (p->state) {
    case auth_version:
      if (AUTH_VERSION == b) {
        p->state = auth_ulen;
      } else {
        p->state = auth_error_unsupported_version;
      }
      break;
    case auth_ulen:
      p->ulen = b;
      p->i = 0;
      // RFC1929 exige ULEN >= 1, pero toleramos 0 (usuario vacío)
      p->state = (b == 0) ? auth_plen : auth_uname;
      break;
    case auth_uname:
      p->uname[p->i++] = (char) b;
      if (p->i == p->ulen) {
        p->uname[p->i] = '\0';
        p->state = auth_plen;
      }
      break;
    case auth_plen:
      p->plen = b;
      p->i = 0;
      if (b == 0) {
        p->passwd[0] = '\0';
        p->state = auth_done;
      } else {
        p->state = auth_passwd;
      }
      break;
    case auth_passwd:
      p->passwd[p->i++] = (char) b;
      if (p->i == p->plen) {
        p->passwd[p->i] = '\0';
        p->state = auth_done;
      }
      break;
    case auth_done:
    case auth_error_unsupported_version:
      // nada para hacer, ya terminamos
      break;
  }
  return p->state;
}

bool auth_is_done(const enum auth_state state, bool *errored) {
  bool ret;
  switch (state) {
    case auth_error_unsupported_version:
      if (errored != NULL) { *errored = true; }
      ret = true;
      break;
    case auth_done:
      ret = true;
      break;
    default:
      ret = false;
      break;
  }
  return ret;
}

enum auth_state auth_consume(buffer *b, struct auth_parser *p, bool *errored) {
  enum auth_state st = p->state;
  while (buffer_can_read(b)) {
    const uint8_t c = buffer_read(b);
    st = auth_parser_feed(p, c);
    if (auth_is_done(st, errored)) { break; }
  }
  return st;
}

int auth_marshall(buffer *b, const uint8_t status) {
  size_t n;
  uint8_t *buff = buffer_write_ptr(b, &n);
  if (n < 2) { return -1; }
  buff[0] = AUTH_VERSION;
  buff[1] = status;
  buffer_write_adv(b, 2);
  return 2;
}
