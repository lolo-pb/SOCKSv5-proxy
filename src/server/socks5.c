#include "socks5.h"

#include <stdio.h>

static unsigned hello_read(struct selector_key *key);
static unsigned request_read(struct selector_key *key);

static const struct state_definition socks5_states[] = {
  {
    .state = SOCKS5_STATE_HELLO_READ,
    .on_read_ready = hello_read,
  },
  {
    .state = SOCKS5_STATE_REQUEST_READ,
    .on_read_ready = request_read,
  },
};

void socks5_init(struct socks5 *socks) {
  socks->stm.initial = SOCKS5_STATE_HELLO_READ;
  socks->stm.states = socks5_states;
  socks->stm.max_state = SOCKS5_STATE_REQUEST_READ;
  stm_init(&socks->stm);
  socks->read_bytes = 0;
  socks->response_bytes = 0;
  socks->close_after_write = 0;
}


socks5_action
socks5_handle_read(struct socks5 *socks, struct selector_key *key) {
  fprintf(stderr, "Read %zd bytes from fd=%d: \n", socks->read_bytes, key->fd);
  fwrite(socks->read_buffer, 1, socks->read_bytes, stderr);
  fprintf(stderr, "\n");

  stm_handler_read(&socks->stm, key);

  socks->read_bytes = 0;

  return socks->response_bytes > 0 ? SOCKS5_ACTION_WRITE : SOCKS5_ACTION_READ;
}

/**
  * Esta es mas rara, por lo mismo q la otra, los buffes los maneja socks5nio.c
  * pero este decide como se interpreta loq se lee
  */
socks5_action socks5_handle_write(
  struct socks5 *socks, struct selector_key *key, const uint8_t **data,
  size_t *bytes
) {

  *data = socks->response;
  *bytes = socks->response_bytes;
  socks->response_bytes = 0;

  return socks->close_after_write ? SOCKS5_ACTION_CLOSE : SOCKS5_ACTION_READ;
}

static unsigned hello_read(struct selector_key *key) {

  struct socks5 *socks = key->data;
  const uint8_t *data = socks->read_buffer;
  const ssize_t bytes = socks->read_bytes;

  if (bytes < 3 || data[0] != SOCKS5_VERSION || bytes < 2 + data[1]) {
    socks->response[0] = SOCKS5_VERSION;
    socks->response[1] = 0xFF;
    socks->response_bytes = 2;
    socks->close_after_write = 1;
    return SOCKS5_STATE_HELLO_READ;
  }

  for (uint8_t i = 0; i < data[1]; i++) {
    if (data[2 + i] == 0x00) {
      socks->response[0] = SOCKS5_VERSION;
      socks->response[1] = 0x00;
      socks->response_bytes = 2;
      return SOCKS5_STATE_REQUEST_READ;
    }
  }

  socks->response[0] = SOCKS5_VERSION;
  socks->response[1] = 0xFF;
  socks->response_bytes = 2;
  socks->close_after_write = 1;
  return SOCKS5_STATE_HELLO_READ;
}

static unsigned request_read(struct selector_key *key) {
  return SOCKS5_STATE_REQUEST_READ;
}
