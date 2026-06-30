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

mon_decode_status mon_response_decode(
  const uint8_t *buf, size_t len, struct mon_response *out, size_t *consumed
) {
  if (len < MON_RESPONSE_HEADER_LEN) return MON_DECODE_NEED_MORE;
  if (buf[0] != MON_VERSION) return MON_DECODE_ERROR;

  const uint16_t payload_len = (uint16_t) ((buf[2] << 8) | buf[3]);
  const size_t total = MON_RESPONSE_HEADER_LEN + payload_len;
  if (len < total) return MON_DECODE_NEED_MORE;

  out->version = buf[0];
  out->status = buf[1];
  out->payload_len = payload_len;
  out->payload = payload_len > 0 ? buf + MON_RESPONSE_HEADER_LEN : NULL;
  *consumed = total;
  return MON_DECODE_OK;
}
