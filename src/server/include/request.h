#ifndef REQUEST_H
#define REQUEST_H

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"

#define SOCKS5_CMD_CONNECT 0x01

#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAINNAME 0x03
#define SOCKS5_ATYP_IPV6 0x04

#define SOCKS5_REPLY_SUCCEEDED 0x00
#define SOCKS5_REPLY_GENERAL_FAILURE 0x01
#define SOCKS5_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS5_REPLY_CONNECTION_REFUSED 0x05
#define SOCKS5_REPLY_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED 0x08

/** Esto tiene un stm interno para ir parseando la request byte por byte */


/** Parser states for the SOCKS5 request message:
 *  VER CMD RSV ATYP DST.ADDR DST.PORT.
 */
enum request_state {
  request_version,
  request_command,
  request_reserved,
  request_atyp,
  request_dst_addr,
  request_dst_port,
  request_done,
  request_error_unsupported_version,
  request_error_unsupported_atyp,
};

/** Incremental parser state for one SOCKS5 request. */
struct request_parser {
  enum request_state state;
  uint8_t command;
  uint8_t atyp;
  uint8_t address[256];
  uint8_t address_len;
  uint8_t address_index;
  uint8_t port[2];
  uint8_t port_index;
};

/** Reset parser fields before reading a new request. */
void request_parser_init(struct request_parser *p);

/** Feed one byte and advance the request parser state. */
enum request_state
request_parser_feed(struct request_parser *p, const uint8_t b);

/** Consume all currently buffered bytes until the request is done or incomplete. */
enum request_state
request_consume(buffer *b, struct request_parser *p, bool *errored);

/** Tell whether a request parser state is terminal. */
bool request_is_done(const enum request_state state, bool *errored);

/** Build a SOCKS5 request reply into the output buffer. */
int request_marshall_reply(buffer *b, const uint8_t reply);

#endif
