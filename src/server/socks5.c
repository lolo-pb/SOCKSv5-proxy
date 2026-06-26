#include "socks5.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static struct socks5args *socks5_args;

static void hello_read_init(const unsigned state, struct selector_key *key);
static unsigned hello_read(struct selector_key *key);
static unsigned hello_write(struct selector_key *key);
static void auth_read_init(const unsigned state, struct selector_key *key);
static unsigned auth_read(struct selector_key *key);
static unsigned auth_write(struct selector_key *key);
static unsigned request_read(struct selector_key *key);

static const struct state_definition socks5_states[] = {
  {
    .state = SOCKS5_STATE_HELLO_READ,
    .on_arrival = hello_read_init,
    .on_read_ready = hello_read,
  },
  {
    .state = SOCKS5_STATE_HELLO_WRITE,
    .on_write_ready = hello_write,
  },
  {
    .state = SOCKS5_STATE_AUTH_READ,
    .on_arrival = auth_read_init,
    .on_read_ready = auth_read,
  },
  {
    .state = SOCKS5_STATE_AUTH_WRITE,
    .on_write_ready = auth_write,
  },
  {
    .state = SOCKS5_STATE_REQUEST_READ,
    .on_read_ready = request_read,
  },
  {
    .state = SOCKS5_STATE_DONE,
  },
  {
    .state = SOCKS5_STATE_ERROR,
  },
};

void socks5_set_args(struct socks5args *args) { socks5_args = args; }

void socks5_init(struct socks5 *socks) {
  memset(socks, 0, sizeof(*socks));
  socks->stm.initial = SOCKS5_STATE_HELLO_READ;
  socks->stm.states = socks5_states;
  socks->stm.max_state = SOCKS5_STATE_ERROR;
  stm_init(&socks->stm);
  buffer_init(
    &socks->read_buffer, sizeof(socks->raw_read_buffer), socks->raw_read_buffer
  );
  buffer_init(
    &socks->write_buffer, sizeof(socks->raw_write_buffer),
    socks->raw_write_buffer
  );
}

socks5_action
socks5_handle_read(struct socks5 *socks, struct selector_key *key) {
  // esto llama al read que corresponda segun el state, osea hello_read o auth_read etc idem lors otros stm_handler
  const unsigned state = stm_handler_read(&socks->stm, key);

  if (state == SOCKS5_STATE_ERROR || state == SOCKS5_STATE_DONE) {
    return SOCKS5_ACTION_CLOSE;
  }
  return buffer_can_read(&socks->write_buffer) ? SOCKS5_ACTION_WRITE
                                               : SOCKS5_ACTION_READ;
}

socks5_action
socks5_handle_write(struct socks5 *socks, struct selector_key *key) {
  const unsigned state = stm_handler_write(&socks->stm, key);// idem ^^^^

  if (state == SOCKS5_STATE_ERROR || state == SOCKS5_STATE_DONE) {
    return SOCKS5_ACTION_CLOSE;
  }
  return buffer_can_read(&socks->write_buffer) ? SOCKS5_ACTION_WRITE
                                               : SOCKS5_ACTION_READ;
}

static void on_hello_method(struct hello_parser *p, const uint8_t method) {
  uint8_t *selected = p->data;
  if (SOCKS_HELLO_USERNAME_PASSWORD == method) { *selected = method; }
}

static void hello_read_init(const unsigned state, struct selector_key *key) {
  struct socks5 *socks = key->data;

  socks->selected_method = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;
  socks->hello.data = &socks->selected_method;
  socks->hello.on_authentication_method = on_hello_method;
  hello_parser_init(&socks->hello);
}

static unsigned hello_read(struct selector_key *key) {
  struct socks5 *socks = key->data;
  bool error = false;
  const enum hello_state state =
    hello_consume(&socks->read_buffer, &socks->hello, &error);

  if (error) { return SOCKS5_STATE_ERROR; }
  if (!hello_is_done(state, NULL)) { return SOCKS5_STATE_HELLO_READ; }
  if (-1 == hello_marshall(&socks->write_buffer, socks->selected_method)) {
    return SOCKS5_STATE_ERROR;
  }
  return SOCKS5_STATE_HELLO_WRITE;
}

static unsigned hello_write(struct selector_key *key) {
  struct socks5 *socks = key->data;

  if (buffer_can_read(&socks->write_buffer)) {
    return SOCKS5_STATE_HELLO_WRITE;
  }
  if (socks->selected_method == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) {
    return SOCKS5_STATE_ERROR;
  }
  return SOCKS5_STATE_AUTH_READ;
}

static void auth_read_init(const unsigned state, struct selector_key *key) {
  struct socks5 *socks = key->data;

  socks->auth_status = AUTH_STATUS_FAILURE;
  auth_parser_init(&socks->auth);
}

static bool credentials_match(const char *user, const char *pass) {
  if (socks5_args == NULL) { return false; }

  for (unsigned i = 0; i < MAX_USERS; i++) {
    const struct users *u = socks5_args->users + i;
    if (u->name == NULL) { continue; }
    if (strcmp(u->name, user) == 0 && u->pass != NULL &&
        strcmp(u->pass, pass) == 0) {
      return true;
    }
  }
  return false;
}

static unsigned auth_read(struct selector_key *key) {
  struct socks5 *socks = key->data;
  bool error = false;
  const enum auth_state state =
    auth_consume(&socks->read_buffer, &socks->auth, &error);

  if (error) { return SOCKS5_STATE_ERROR; }
  if (!auth_is_done(state, NULL)) { return SOCKS5_STATE_AUTH_READ; }

  socks->auth_status = credentials_match(socks->auth.uname, socks->auth.passwd)
                         ? AUTH_STATUS_SUCCESS
                         : AUTH_STATUS_FAILURE;
  if (-1 == auth_marshall(&socks->write_buffer, socks->auth_status)) {
    return SOCKS5_STATE_ERROR;
  }
  return SOCKS5_STATE_AUTH_WRITE;
}

static unsigned auth_write(struct selector_key *key) {
  struct socks5 *socks = key->data;

  if (buffer_can_read(&socks->write_buffer)) { return SOCKS5_STATE_AUTH_WRITE; }
  return socks->auth_status == AUTH_STATUS_SUCCESS ? SOCKS5_STATE_REQUEST_READ
                                                   : SOCKS5_STATE_ERROR;
}

static unsigned request_read(struct selector_key *key) {
  struct socks5 *socks = key->data;
  buffer_reset(&socks->read_buffer);
  return SOCKS5_STATE_DONE;
}
