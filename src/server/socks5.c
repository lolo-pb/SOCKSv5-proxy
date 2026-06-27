#include "socks5.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static struct socks5args *socks5_args;

static void hello_read_init(const unsigned state, struct selector_key *key);
static unsigned hello_read(struct selector_key *key);
static unsigned hello_write(struct selector_key *key);
static void auth_read_init(const unsigned state, struct selector_key *key);
static unsigned auth_read(struct selector_key *key);
static unsigned auth_write(struct selector_key *key);
static void request_read_init(const unsigned state, struct selector_key *key);
static unsigned request_read(struct selector_key *key);
static unsigned request_write(struct selector_key *key);
static void origin_connect_write(struct selector_key *key);
static void origin_connect_close(struct selector_key *key);

// Selector callbacks for the upstream/origin fd while connect() is pending.
static const struct fd_handler origin_connect_handler = {
  .handle_read = NULL,
  .handle_write = origin_connect_write,
  .handle_block = NULL,
  .handle_close = origin_connect_close,
};

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
    .on_arrival = request_read_init,
    .on_read_ready = request_read,
  },
  {
    // Waiting for the upstream/origin nonblocking connect() to finish.
    .state = SOCKS5_STATE_CONNECTING,
  },
  {
    .state = SOCKS5_STATE_REQUEST_WRITE,
    .on_write_ready = request_write,
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
  socks->client_fd = -1;
  socks->origin_fd = -1;
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

// Frees the SOCKS state and closes any origin fd it still owns.
void socks5_destroy(struct socks5 *socks) {
  if (socks == NULL) { return; }
  if (socks->origin_fd >= 0) {
    close(socks->origin_fd);
    socks->origin_fd = -1;
  }
  free(socks);
}

// Stores the accepted client fd so origin callbacks can resume client writes.
void socks5_set_client_fd(struct socks5 *socks, const int client_fd) {
  socks->client_fd = client_fd;
}

// Unregisters a pending origin fd before the shared SOCKS state is freed.
void socks5_unregister_origin(struct socks5 *socks, fd_selector selector) {
  if (socks->origin_registered && socks->origin_fd >= 0) {
    selector_unregister_fd(selector, socks->origin_fd);
    socks->origin_registered = false;
  }
}

socks5_action
socks5_handle_read(struct socks5 *socks, struct selector_key *key) {
  // esto llama al read que corresponda segun el state, osea hello_read o auth_read etc idem lors otros stm_handler
  const unsigned state = stm_handler_read(&socks->stm, key);

  if (state == SOCKS5_STATE_ERROR || state == SOCKS5_STATE_DONE) {
    return SOCKS5_ACTION_CLOSE;
  }
  // Pause the client fd while the origin fd completes connect().
  if (state == SOCKS5_STATE_CONNECTING) { return SOCKS5_ACTION_NOOP; }
  return buffer_can_read(&socks->write_buffer) ? SOCKS5_ACTION_WRITE
                                               : SOCKS5_ACTION_READ;
}

socks5_action
socks5_handle_write(struct socks5 *socks, struct selector_key *key) {
  const unsigned state = stm_handler_write(&socks->stm, key);

  if (state == SOCKS5_STATE_ERROR || state == SOCKS5_STATE_DONE) {
    return SOCKS5_ACTION_CLOSE;
  }
  // Pause the client fd while the origin fd completes connect().
  if (state == SOCKS5_STATE_CONNECTING) { return SOCKS5_ACTION_NOOP; }
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

static void request_read_init(const unsigned state, struct selector_key *key) {
  struct socks5 *socks = key->data;

  socks->request_reply = SOCKS5_REPLY_GENERAL_FAILURE;
  request_parser_init(&socks->request);
}

// Converts origin connect results into SOCKS5 reply codes.
static uint8_t socks5_reply_from_errno(const int error) {
  switch (error) {
    case 0:
      return SOCKS5_REPLY_SUCCEEDED;
    case ENETUNREACH:
      return SOCKS5_REPLY_NETWORK_UNREACHABLE;
    case EHOSTUNREACH:
      return SOCKS5_REPLY_HOST_UNREACHABLE;
    case ECONNREFUSED:
      return SOCKS5_REPLY_CONNECTION_REFUSED;
    default:
      return SOCKS5_REPLY_GENERAL_FAILURE;
  }
}

// Opens a nonblocking origin socket and starts the TCP connect.
static int register_origin_connect(
  struct socks5 *socks, struct selector_key *key, const struct sockaddr *addr,
  const socklen_t addr_len
) {
  const int fd = socket(addr->sa_family, SOCK_STREAM, 0);
  if (fd < 0) { return errno; }
  if (selector_fd_set_nio(fd) == -1) {
    const int error = errno;
    close(fd);
    return error;
  }

  if (connect(fd, addr, addr_len) == 0) {
    socks->origin_fd = fd;
    socks->request_reply = SOCKS5_REPLY_SUCCEEDED;
    return 0;
  }
  if (errno != EINPROGRESS) {
    const int error = errno;
    close(fd);
    return error;
  }

  socks->origin_fd = fd;
  selector_status ss =
    selector_register(key->s, fd, &origin_connect_handler, OP_WRITE, socks);
  if (ss != SELECTOR_SUCCESS) {
    close(fd);
    socks->origin_fd = -1;
    return ECONNREFUSED;
  }
  socks->origin_registered = true;
  return EINPROGRESS;
}

// Builds an IPv4 sockaddr from the parsed SOCKS request.
static int start_ipv4_connect(struct socks5 *socks, struct selector_key *key) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr.s_addr, socks->request.address, 4);
  memcpy(&addr.sin_port, socks->request.port, 2);

  return register_origin_connect(
    socks, key, (const struct sockaddr *) &addr, sizeof(addr)
  );
}

// Builds an IPv6 sockaddr from the parsed SOCKS request.
static int start_ipv6_connect(struct socks5 *socks, struct selector_key *key) {
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  memcpy(&addr.sin6_addr.s6_addr, socks->request.address, 16);
  memcpy(&addr.sin6_port, socks->request.port, 2);

  return register_origin_connect(
    socks, key, (const struct sockaddr *) &addr, sizeof(addr)
  );
}

// Placeholder for future domain/DNS support.
static int start_domain_connect(struct socks5 *socks, struct selector_key *key) {
  return EHOSTUNREACH;
}

// Chooses the origin connect path for the request address type.
static int start_origin_connect(struct socks5 *socks, struct selector_key *key) {
  switch (socks->request.atyp) {
    case SOCKS5_ATYP_IPV4:
      return start_ipv4_connect(socks, key);
    case SOCKS5_ATYP_IPV6:
      return start_ipv6_connect(socks, key);
    case SOCKS5_ATYP_DOMAINNAME:
      return start_domain_connect(socks, key);
    default:
      return EAFNOSUPPORT;
  }
}

// Writes the SOCKS request reply into the client output buffer.
static unsigned marshall_request_reply(struct socks5 *socks) {
  if (-1 ==
      request_marshall_reply(&socks->write_buffer, socks->request_reply)) {
    return SOCKS5_STATE_ERROR;
  }
  return SOCKS5_STATE_REQUEST_WRITE;
}

// Parses CONNECT and starts the origin connection instead of failing directly.
static unsigned request_read(struct selector_key *key) {
  struct socks5 *socks = key->data;
  bool error = false;
  const enum request_state state =
    request_consume(&socks->read_buffer, &socks->request, &error);

  if (error) {
    socks->request_reply = SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED;
  } else if (!request_is_done(state, NULL)) {
    return SOCKS5_STATE_REQUEST_READ;
  } else if (socks->request.command != SOCKS5_CMD_CONNECT) {
    socks->request_reply = SOCKS5_REPLY_COMMAND_NOT_SUPPORTED;
  } else {
    const int connect_status = start_origin_connect(socks, key);
    if (connect_status == EINPROGRESS) { return SOCKS5_STATE_CONNECTING; }
    socks->request_reply = socks5_reply_from_errno(connect_status);
  }

  return marshall_request_reply(socks);
}

static unsigned request_write(struct selector_key *key) {
  struct socks5 *socks = key->data;

  if (buffer_can_read(&socks->write_buffer)) {
    return SOCKS5_STATE_REQUEST_WRITE;
  }
  return SOCKS5_STATE_DONE;
}

// Finishes a pending nonblocking connect and wakes the client to send the reply.
static void origin_connect_write(struct selector_key *key) {
  struct socks5 *socks = key->data;
  int error = 0;
  socklen_t len = sizeof(error);

  if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
    error = errno;
  }

  socks->origin_registered = false;
  selector_unregister_fd(key->s, key->fd);

  socks->request_reply = socks5_reply_from_errno(error);
  if (marshall_request_reply(socks) == SOCKS5_STATE_ERROR) {
    socks->stm.current = socks->stm.states + SOCKS5_STATE_ERROR;
    selector_set_interest(key->s, socks->client_fd, OP_READ);
    return;
  }

  socks->stm.current = socks->stm.states + SOCKS5_STATE_REQUEST_WRITE;
  selector_set_interest(key->s, socks->client_fd, OP_WRITE);
}

// Marks the origin fd as no longer registered in the selector.
static void origin_connect_close(struct selector_key *key) {
  struct socks5 *socks = key->data;
  if (socks->origin_fd == key->fd) { socks->origin_registered = false; }
}
