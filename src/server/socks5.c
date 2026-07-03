#include "socks5.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
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
static uint8_t socks5_reply_from_errno(const int error);
static int start_origin_connect(struct socks5 *socks, struct selector_key *key);
static unsigned marshall_request_reply(struct socks5 *socks);
static void origin_connect_write(struct selector_key *key);
static void origin_read(struct selector_key *key);
static void origin_write(struct selector_key *key);
static void origin_connect_close(struct selector_key *key);
static void client_unregister(struct socks5 *socks, fd_selector selector);
static void client_close(struct socks5 *socks, fd_selector selector);
static void origin_unregister(struct socks5 *socks, fd_selector selector);
static void origin_close(struct socks5 *socks, fd_selector selector);
static void socks5_free(struct socks5 *socks);

// struct to pass dns thread data to main thred
struct dns_job {
  struct socks5 *socks;
  fd_selector selector;
  int client_fd;
  char host[256];
  char service[6];
};

static void *dns_worker(void *data);
static void socks5_release_block_data(void *data);

// Selector callbacks for the upstream/origin fd during connect and relay.
static const struct fd_handler origin_connect_handler = {
  .handle_read = origin_read,
  .handle_write = origin_write,
  .handle_block_done = NULL,
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
    .state = SOCKS5_STATE_RELAY,
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
  atomic_init(&socks->references, 1);
  socks->client_fd = -1;
  socks->origin_fd = -1;
  pthread_mutex_init(&socks->dns_mutex, NULL);
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

void socks5_ref(struct socks5 *socks) {
  if (socks == NULL) { return; }
  atomic_fetch_add_explicit(&socks->references, 1, memory_order_relaxed);
}

// Releases one owner reference; the last release frees the SOCKS state.
void socks5_release(struct socks5 *socks) {
  if (socks == NULL) { return; }

  const unsigned refs =
    atomic_fetch_sub_explicit(&socks->references, 1, memory_order_acq_rel);
  if (refs == 1) {
    socks5_free(socks);
  } else if (refs == 0) {
    abort();
  }
}

static void socks5_release_block_data(void *data) { socks5_release(data); }

// Stores the accepted client fd so origin callbacks can resume client writes.
void socks5_set_client_fd(struct socks5 *socks, const int client_fd) {
  socks->client_fd = client_fd;
}

void socks5_cancel(struct socks5 *socks) {
  if (socks == NULL) { return; }

  pthread_mutex_lock(&socks->dns_mutex);
  socks->cancelled = true;
  pthread_mutex_unlock(&socks->dns_mutex);
}

bool socks5_is_relaying(struct socks5 *socks) { return socks->relay_started; }

static void
relay_shutdown_write_side(int fd, bool *shutdown_done, const char *side) {
  if (*shutdown_done || fd < 0) { return; }

  fprintf(stderr, "partial close: shutdown %s write side fd=%d\n", side, fd);
  shutdown(fd, SHUT_WR);
  *shutdown_done = true;
}

// Propagates EOF in one direction without closing the whole tunnel.
static bool relay_should_close(struct socks5 *socks) {
  const bool client_to_origin_drained = !buffer_can_read(&socks->read_buffer);
  const bool origin_to_client_drained = !buffer_can_read(&socks->write_buffer);

  if (socks->client_eof && client_to_origin_drained) {
    relay_shutdown_write_side(
      socks->origin_fd, &socks->origin_write_shutdown, "origin"
    );
  }
  if (socks->origin_eof && origin_to_client_drained) {
    relay_shutdown_write_side(
      socks->client_fd, &socks->client_write_shutdown, "client"
    );
  }

  return socks->client_eof && socks->origin_eof && client_to_origin_drained &&
         origin_to_client_drained;
}

// Recomputes read/write interests from relay buffer state.
static void relay_update_interests(struct socks5 *socks, fd_selector selector) {
  fd_interest client_interest = OP_NOOP;
  fd_interest origin_interest = OP_NOOP;

  if (!socks->client_eof && buffer_can_write(&socks->read_buffer)) {
    client_interest |= OP_READ;
  }
  if (buffer_can_read(&socks->write_buffer)) { client_interest |= OP_WRITE; }

  if (!socks->origin_eof && buffer_can_write(&socks->write_buffer)) {
    origin_interest |= OP_READ;
  }
  if (buffer_can_read(&socks->read_buffer)) { origin_interest |= OP_WRITE; }

  selector_set_interest(selector, socks->client_fd, client_interest);
  selector_set_interest(selector, socks->origin_fd, origin_interest);
}

// Switches from SOCKS negotiation to raw bidirectional relay.
static unsigned start_relay(struct socks5 *socks, fd_selector selector) {
  socks->relay_started = true;
  socks->client_eof = false;
  socks->origin_eof = false;
  socks->client_write_shutdown = false;
  socks->origin_write_shutdown = false;
  buffer_reset(&socks->read_buffer);
  buffer_reset(&socks->write_buffer);
  relay_update_interests(socks, selector);// good use of API ദ്ദി（• ˕ •)マ
  return SOCKS5_STATE_RELAY;
}

// Treats nonblocking would-block errors as normal selector flow.
static bool is_retryable_io_error(void) {
  return errno == EAGAIN || errno == EWOULDBLOCK;
}

// Reads client bytes into the client-to-origin relay buffer.
socks5_action
socks5_relay_client_read(struct socks5 *socks, struct selector_key *key) {
  size_t count;
  uint8_t *ptr = buffer_write_ptr(&socks->read_buffer, &count);
  const ssize_t bytes = read(key->fd, ptr, count);

  if (bytes > 0) {
    buffer_write_adv(&socks->read_buffer, bytes);
  } else if (bytes == 0) {
    socks->client_eof = true;
  } else if (!is_retryable_io_error()) {
    return SOCKS5_ACTION_CLOSE;
  }

  if (relay_should_close(socks)) { return SOCKS5_ACTION_CLOSE; }
  relay_update_interests(socks, key->s);
  return SOCKS5_ACTION_NONE;
}

// Writes origin bytes from the origin-to-client relay buffer.
socks5_action
socks5_relay_client_write(struct socks5 *socks, struct selector_key *key) {
  size_t count;
  uint8_t *ptr = buffer_read_ptr(&socks->write_buffer, &count);
  const ssize_t bytes = write(key->fd, ptr, count);

  if (bytes > 0) {
    buffer_read_adv(&socks->write_buffer, bytes);
  } else if (bytes < 0 && !is_retryable_io_error()) {
    return SOCKS5_ACTION_CLOSE;
  }

  if (relay_should_close(socks)) { return SOCKS5_ACTION_CLOSE; }
  relay_update_interests(socks, key->s);
  return SOCKS5_ACTION_NONE;
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
  if (state == SOCKS5_STATE_RELAY) { return SOCKS5_ACTION_NONE; }
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
  if (state == SOCKS5_STATE_RELAY) { return SOCKS5_ACTION_NONE; }
  return buffer_can_read(&socks->write_buffer) ? SOCKS5_ACTION_WRITE
                                               : SOCKS5_ACTION_READ;
}

socks5_action
socks5_handle_block_done(struct socks5 *socks, struct selector_key *key) {
  pthread_mutex_lock(&socks->dns_mutex);
  socks->dns_pending = false;
  pthread_mutex_unlock(&socks->dns_mutex);

  const int connect_status = start_origin_connect(socks, key);
  if (connect_status == EINPROGRESS) {
    socks->stm.current = socks->stm.states + SOCKS5_STATE_CONNECTING;
    return SOCKS5_ACTION_NOOP;
  }

  socks->request_reply = socks5_reply_from_errno(connect_status);
  if (marshall_request_reply(socks) == SOCKS5_STATE_ERROR) {
    socks->stm.current = socks->stm.states + SOCKS5_STATE_ERROR;
    return SOCKS5_ACTION_CLOSE;
  }
  socks->stm.current = socks->stm.states + SOCKS5_STATE_REQUEST_WRITE;
  return SOCKS5_ACTION_WRITE;
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
    if (
      strcmp(u->name, user) == 0 && u->pass != NULL &&
      strcmp(u->pass, pass) == 0
    ) {
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
    selector_status ss =
      selector_register(key->s, fd, &origin_connect_handler, OP_NOOP, socks);
    if (ss != SELECTOR_SUCCESS) {
      close(fd);
      socks->origin_fd = -1;
      return ECONNREFUSED;
    }
    socks->origin_registered = true;
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

static void *dns_worker(void *data) {
  struct dns_job *job = data;
  struct socks5 *socks = job->socks;
  struct addrinfo hints;
  struct addrinfo *result = NULL;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  const int error = getaddrinfo(job->host, job->service, &hints, &result);

  pthread_mutex_lock(&socks->dns_mutex);
  socks->dns_pending = false;
  if (!socks->cancelled) {
    socks->dns_error = error;
    socks->dns_result = result;
    socks->dns_next = result;
    result = NULL;

    selector_status ss = selector_notify_block_done(
      job->selector, job->client_fd, socks, socks5_release_block_data
    );
    pthread_mutex_unlock(&socks->dns_mutex);
    if (ss != SELECTOR_SUCCESS) { socks5_release(socks); }
  } else {
    pthread_mutex_unlock(&socks->dns_mutex);
    socks5_release(socks);
  }

  if (result != NULL) { freeaddrinfo(result); }
  free(job);
  return NULL;
}

// Tries resolved addresses from the current DNS cursor until a connect starts.
static int
start_resolved_connect(struct socks5 *socks, struct selector_key *key) {
  if (socks->dns_error != 0 || socks->dns_result == NULL) {
    return EHOSTUNREACH;
  }

  int last_error = EHOSTUNREACH;
  for (struct addrinfo *ai = socks->dns_next; ai != NULL; ai = ai->ai_next) {
    socks->dns_next = ai->ai_next;
    if (ai->ai_socktype != SOCK_STREAM) { continue; }

    const int status =
      register_origin_connect(socks, key, ai->ai_addr, ai->ai_addrlen);
    if (status == 0 || status == EINPROGRESS) { return status; }
    last_error = status;
  }
  return last_error;
}

static void
request_port_to_service(const struct socks5 *socks, char service[6]) {
  const unsigned port =
    ((unsigned) socks->request.port[0] << 8) | socks->request.port[1];
  snprintf(service, 6, "%u", port);
}

// Starts asynchronous DNS resolution for domain-name requests.
static int
start_domain_connect(struct socks5 *socks, struct selector_key *key) {
  struct dns_job *job = malloc(sizeof(*job));
  if (job == NULL) { return ENOMEM; }

  job->socks = socks;
  job->selector = key->s;
  job->client_fd = socks->client_fd;
  memcpy(job->host, socks->request.address, socks->request.address_len);
  job->host[socks->request.address_len] = '\0';
  request_port_to_service(socks, job->service);

  pthread_mutex_lock(&socks->dns_mutex);
  socks->dns_pending = true;
  socks->dns_error = 0;
  socks->dns_result = NULL;
  socks->dns_next = NULL;
  pthread_mutex_unlock(&socks->dns_mutex);

  socks5_ref(socks);
  pthread_t thread;
  const int status = pthread_create(&thread, NULL, dns_worker, job);
  if (status != 0) {
    socks5_release(socks);
    free(job);
    pthread_mutex_lock(&socks->dns_mutex);
    socks->dns_pending = false;
    pthread_mutex_unlock(&socks->dns_mutex);
    return status;
  }
  pthread_detach(thread);
  return EINPROGRESS;
}

// Chooses the origin connect path for the request address type.
static int
start_origin_connect(struct socks5 *socks, struct selector_key *key) {
  switch (socks->request.atyp) {
    case SOCKS5_ATYP_IPV4:
      return start_ipv4_connect(socks, key);
    case SOCKS5_ATYP_IPV6:
      return start_ipv6_connect(socks, key);
    case SOCKS5_ATYP_DOMAINNAME:
      if (socks->dns_pending) { return EINPROGRESS; }
      if (socks->dns_result != NULL || socks->dns_error != 0) {
        return start_resolved_connect(socks, key);
      }
      return start_domain_connect(socks, key);
    default:
      return EAFNOSUPPORT;
  }
}

// Writes the SOCKS request reply into the client output buffer.
static unsigned marshall_request_reply(struct socks5 *socks) {
  struct sockaddr_storage bind_addr;
  struct sockaddr *addr = NULL;
  socklen_t addr_len = sizeof(bind_addr);

  if (socks->request_reply == SOCKS5_REPLY_SUCCEEDED && socks->origin_fd >= 0 &&
      getsockname(socks->origin_fd, (struct sockaddr *) &bind_addr, &addr_len) ==
        0) {
    addr = (struct sockaddr *) &bind_addr;
  }

  if (-1 ==
      request_marshall_reply(
        &socks->write_buffer, socks->request_reply, addr, addr_len
      )) {
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
    socks->request_reply = state == request_error_unsupported_atyp
                             ? SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED
                             : SOCKS5_REPLY_GENERAL_FAILURE;
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

// Sends the SOCKS reply, then starts relay only on success.
static unsigned request_write(struct selector_key *key) {
  struct socks5 *socks = key->data;

  if (buffer_can_read(&socks->write_buffer)) {
    return SOCKS5_STATE_REQUEST_WRITE;
  }
  if (socks->request_reply != SOCKS5_REPLY_SUCCEEDED) {
    return SOCKS5_STATE_DONE;
  }
  return start_relay(socks, key->s);
}

// Finishes a pending nonblocking connect and wakes the client to send the reply.
static void origin_connect_write(struct selector_key *key) {
  struct socks5 *socks = key->data;
  int error = 0;
  socklen_t len = sizeof(error);

  if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
    error = errno;
  }

  socks->request_reply = socks5_reply_from_errno(error);
  if (error != 0) {
    origin_close(socks, key->s);

    if (socks->request.atyp == SOCKS5_ATYP_DOMAINNAME &&
        socks->dns_next != NULL) {
      error = start_resolved_connect(socks, key);
      if (error == EINPROGRESS) { return; }
      socks->request_reply = socks5_reply_from_errno(error);
    }
  } else {
    selector_set_interest(key->s, key->fd, OP_NOOP);
  }

  if (marshall_request_reply(socks) == SOCKS5_STATE_ERROR) {
    socks->stm.current = socks->stm.states + SOCKS5_STATE_ERROR;
    selector_set_interest(key->s, socks->client_fd, OP_READ);
    return;
  }

  socks->stm.current = socks->stm.states + SOCKS5_STATE_REQUEST_WRITE;
  selector_set_interest(key->s, socks->client_fd, OP_WRITE);
}

// Reads origin bytes into the origin-to-client relay buffer.
static void origin_read(struct selector_key *key) {
  struct socks5 *socks = key->data;
  size_t count;
  uint8_t *ptr = buffer_write_ptr(&socks->write_buffer, &count);
  const ssize_t bytes = read(key->fd, ptr, count);

  if (bytes > 0) {
    buffer_write_adv(&socks->write_buffer, bytes);
  } else if (bytes == 0) {
    socks->origin_eof = true;
  } else if (!is_retryable_io_error()) {
    socks5_connection_close(socks, key->s);
    return;
  }

  if (relay_should_close(socks)) {
    socks5_connection_close(socks, key->s);
    return;
  }
  relay_update_interests(socks, key->s);
}

// Writes client bytes from the client-to-origin relay buffer.
static void origin_write(struct selector_key *key) {
  struct socks5 *socks = key->data;

  if (!socks->relay_started) {
    origin_connect_write(key);
    return;
  }

  size_t count;
  uint8_t *ptr = buffer_read_ptr(&socks->read_buffer, &count);
  const ssize_t bytes = write(key->fd, ptr, count);

  if (bytes > 0) {
    buffer_read_adv(&socks->read_buffer, bytes);
  } else if (bytes < 0 && !is_retryable_io_error()) {
    socks5_connection_close(socks, key->s);
    return;
  }

  if (relay_should_close(socks)) {
    socks5_connection_close(socks, key->s);
    return;
  }
  relay_update_interests(socks, key->s);
}

// Marks the origin fd as no longer registered in the selector.
static void origin_connect_close(struct selector_key *key) {
  struct socks5 *socks = key->data;
  if (socks->origin_fd == key->fd) { socks->origin_registered = false; }
}

// Frees the SOCKS state once every owner has released its reference.
static void socks5_free(struct socks5 *socks) {
  if (socks->dns_result != NULL) {
    freeaddrinfo(socks->dns_result);
    socks->dns_result = NULL;
  }
  pthread_mutex_destroy(&socks->dns_mutex);
  free(socks);
}

static void client_unregister(struct socks5 *socks, fd_selector selector) {
  if (socks->client_registered && socks->client_fd >= 0) {
    const int fd = socks->client_fd;
    socks->client_registered = false;
    selector_unregister_fd(selector, fd);
  }
}

static void client_close(struct socks5 *socks, fd_selector selector) {
  const int fd = socks->client_fd;
  client_unregister(socks, selector);
  if (fd >= 0) {
    fprintf(stderr, "full close: close client fd=%d\n", fd);
    close(fd);
    if (socks->client_fd == fd) { socks->client_fd = -1; }
  }
}

static void origin_unregister(struct socks5 *socks, fd_selector selector) {
  if (socks->origin_registered && socks->origin_fd >= 0) {
    const int fd = socks->origin_fd;
    socks->origin_registered = false;
    selector_unregister_fd(selector, fd);
  }
}

static void origin_close(struct socks5 *socks, fd_selector selector) {
  const int fd = socks->origin_fd;
  origin_unregister(socks, selector);
  if (fd >= 0) {
    fprintf(stderr, "full close: close origin fd=%d\n", fd);
    close(fd);
    if (socks->origin_fd == fd) { socks->origin_fd = -1; }
  }
}

void socks5_connection_close(struct socks5 *socks, fd_selector selector) {
  if (socks == NULL || socks->closing) { return; }

  fprintf(
    stderr, "full close: connection client_fd=%d origin_fd=%d\n",
    socks->client_fd, socks->origin_fd
  );
  socks->closing = true;
  socks5_cancel(socks);
  client_close(socks, selector);
  origin_close(socks, selector);
  socks5_release(socks);
}
