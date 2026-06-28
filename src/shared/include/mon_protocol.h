#ifndef MON_PROTOCOL_H
#define MON_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

/**
 * Monitoring protocol - binary request/response over TCP.
 *
 * Request format:
 *   +-----+-----+-------+-------+-------+---------+
 *   | VER | CMD | NARGS | LEN_1 | LEN_2 | PAYLOAD |
 *   +-----+-----+-------+-------+-------+---------+
 *     1B    1B     1B      1B      1B     variable
 *
 * Response format:
 *   +-----+--------+-----+---------+
 *   | VER | STATUS | LEN | PAYLOAD |
 *   +-----+--------+-----+---------+
 *     1B     1B      2B   variable
 *                   (BE)
 */

#define MON_VERSION 0x01

/* commands */
#define MON_CMD_AUTH 0x00
#define MON_CMD_ADD_USER 0x01
#define MON_CMD_DEL_USER 0x02
#define MON_CMD_LIST_USERS 0x03
#define MON_CMD_GET_METRICS 0x04
#define MON_CMD_GET_ACCESS_LOG 0x05

/* status codes */
#define MON_STATUS_OK 0x00
#define MON_STATUS_AUTH_FAIL 0x01
#define MON_STATUS_UNKNOWN_CMD 0x02
#define MON_STATUS_USER_EXISTS 0x03
#define MON_STATUS_USER_NOT_FOUND 0x04
#define MON_STATUS_INTERNAL_ERROR 0x05

#define MON_MAX_ARG_LEN 255
#define MON_MAX_ARGS 2
#define MON_RESPONSE_HEADER_LEN 4 /* VER + STATUS + LEN(2) */

/* parsed request */
struct mon_request {
  uint8_t version;
  uint8_t cmd;
  uint8_t nargs;
  uint8_t arg_lens[MON_MAX_ARGS];
  char args[MON_MAX_ARGS][MON_MAX_ARG_LEN + 1];
};

/* response to send */
struct mon_response {
  uint8_t version;
  uint8_t status;
  uint16_t payload_len;
  const uint8_t *payload;
};

/**
 * Encode a request into buf. Returns bytes written, or -1 if buf too small.
 * Used by the client.
 */
int mon_request_encode(
  const struct mon_request *req, uint8_t *buf, size_t buf_len
);

/**
 * Encode a response header + payload into buf.
 * Returns bytes written, or -1 if buf too small.
 * Used by the server.
 */
int mon_response_encode(
  const struct mon_response *resp, uint8_t *buf, size_t buf_len
);

#endif
