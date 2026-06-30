#include "mon_protocol.h"

#include <string.h>

int mon_request_encode(
  const struct mon_request *req, uint8_t *buf, size_t buf_len
) {
  /* calculate total size: VER + CMD + NARGS + len bytes + payload */
  size_t total = 3 + req->nargs;
  for (uint8_t i = 0; i < req->nargs; i++) total += req->arg_lens[i];
  if (buf_len < total) return -1;

  size_t off = 0;
  buf[off++] = req->version;
  buf[off++] = req->cmd;
  buf[off++] = req->nargs;
  for (uint8_t i = 0; i < req->nargs; i++) buf[off++] = req->arg_lens[i];
  for (uint8_t i = 0; i < req->nargs; i++) {
    memcpy(buf + off, req->args[i], req->arg_lens[i]);
    off += req->arg_lens[i];
  }
  return (int) off;
}

int mon_response_encode(
  const struct mon_response *resp, uint8_t *buf, size_t buf_len
) {
  size_t total = MON_RESPONSE_HEADER_LEN + resp->payload_len;
  if (buf_len < total) return -1;

  size_t off = 0;
  buf[off++] = resp->version;
  buf[off++] = resp->status;
  buf[off++] = (resp->payload_len >> 8) & 0xFF;
  buf[off++] = resp->payload_len & 0xFF;
  if (resp->payload_len > 0 && resp->payload != NULL) {
    memcpy(buf + off, resp->payload, resp->payload_len);
    off += resp->payload_len;
  }
  return (int) off;
}
