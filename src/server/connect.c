#include "connect.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns_resolver.h"
#include "io_util.h"
#include "metrics.h"
#include "request.h"
#include "socks5.h"

static void origin_read(struct selector_key *key);
static void origin_write(struct selector_key *key);
static void origin_connect_close(struct selector_key *key);

static const struct fd_handler origin_handler = {
  .handle_read = origin_read,
  .handle_write = origin_write,
  .handle_block_done = NULL,
  .handle_close = origin_connect_close,
};

const struct fd_handler *connect_origin_handler(void) {
  return &origin_handler;
}

uint8_t connect_reply_from_errno(const int error) {
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

static int register_origin_connect(
  struct socks5 *socks, struct selector_key *key, const struct sockaddr *addr,
  socklen_t addr_len
) {
  const int fd = socket(addr->sa_family, SOCK_STREAM, 0);
  if (fd < 0) return errno;
  if (selector_fd_set_nio(fd) == -1) {
    const int error = errno;
    close(fd);
    return error;
  }

  if (connect(fd, addr, addr_len) == 0) {
    socks->origin_fd = fd;
    selector_status ss =
      selector_register(key->s, fd, &origin_handler, OP_NOOP, socks);
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
    selector_register(key->s, fd, &origin_handler, OP_WRITE, socks);
  if (ss != SELECTOR_SUCCESS) {
    close(fd);
    socks->origin_fd = -1;
    return ECONNREFUSED;
  }
  socks->origin_registered = true;
  return EINPROGRESS;
}

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

static int
start_resolved_connect(struct socks5 *socks, struct selector_key *key) {
  if (socks->dns_error != 0 || socks->dns_result == NULL) return EHOSTUNREACH;

  int last_error = EHOSTUNREACH;
  for (struct addrinfo *ai = socks->dns_next; ai != NULL; ai = ai->ai_next) {
    socks->dns_next = ai->ai_next;
    if (ai->ai_socktype != SOCK_STREAM) continue;

    const int status =
      register_origin_connect(socks, key, ai->ai_addr, ai->ai_addrlen);
    if (status == 0 || status == EINPROGRESS) return status;
    last_error = status;
  }
  return last_error;
}

int connect_to_origin(struct socks5 *socks, struct selector_key *key) {
  switch (socks->request.atyp) {
    case SOCKS5_ATYP_IPV4:
      return start_ipv4_connect(socks, key);
    case SOCKS5_ATYP_IPV6:
      return start_ipv6_connect(socks, key);
    case SOCKS5_ATYP_DOMAINNAME:
      if (socks->dns_pending) return EINPROGRESS;
      if (socks->dns_result != NULL || socks->dns_error != 0)
        return start_resolved_connect(socks, key);
      return dns_resolve_start(socks, key);
    default:
      return EAFNOSUPPORT;
  }
}

unsigned connect_marshall_reply(struct socks5 *socks) {
  struct sockaddr_storage bind_addr;
  struct sockaddr *addr = NULL;
  socklen_t addr_len = sizeof(bind_addr);

  if (
    socks->request_reply == SOCKS5_REPLY_SUCCEEDED && socks->origin_fd >= 0 &&
    getsockname(socks->origin_fd, (struct sockaddr *) &bind_addr, &addr_len) ==
      0
  ) {
    addr = (struct sockaddr *) &bind_addr;
  }

  if (
    -1 == request_marshall_reply(
            &socks->write_buffer, socks->request_reply, addr, addr_len
          )
  ) {
    return SOCKS5_STATE_ERROR;
  }
  return SOCKS5_STATE_REQUEST_WRITE;
}

// Called when origin fd completes a pending nonblocking connect.
static void
origin_connect_write_handler(struct socks5 *socks, struct selector_key *key) {
  int error = 0;
  socklen_t len = sizeof(error);

  if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1)
    error = errno;

  socks->request_reply = connect_reply_from_errno(error);
  if (error != 0) {
    // close failed origin fd and try next address if available
    if (socks->origin_registered && socks->origin_fd >= 0) {
      socks->origin_registered = false;
      selector_unregister_fd(key->s, key->fd);
    }
    if (socks->origin_fd >= 0) {
      close(socks->origin_fd);
      socks->origin_fd = -1;
    }

    if (
      socks->request.atyp == SOCKS5_ATYP_DOMAINNAME && socks->dns_next != NULL
    ) {
      error = start_resolved_connect(socks, key);
      if (error == EINPROGRESS) return;
      socks->request_reply = connect_reply_from_errno(error);
    }
  } else {
    selector_set_interest(key->s, key->fd, OP_NOOP);
  }

  if (connect_marshall_reply(socks) == SOCKS5_STATE_ERROR) {
    socks->stm.current = socks->stm.states + SOCKS5_STATE_ERROR;
    selector_set_interest(key->s, socks->client_fd, OP_READ);
    return;
  }

  socks->stm.current = socks->stm.states + SOCKS5_STATE_REQUEST_WRITE;
  selector_set_interest(key->s, socks->client_fd, OP_WRITE);
}

// Reads origin bytes into write_buffer (origin → client direction).
static void origin_read(struct selector_key *key) {
  struct socks5 *socks = key->data;
  size_t count;
  uint8_t *ptr = buffer_write_ptr(&socks->write_buffer, &count);
  const ssize_t bytes = read(key->fd, ptr, count);

  if (bytes > 0) {
    buffer_write_adv(&socks->write_buffer, bytes);
    if (!relay_flush(socks->client_fd, &socks->write_buffer)) {
      socks5_connection_close(socks, key->s);
      return;
    }
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

// Writes read_buffer to origin (client → origin direction).
static void origin_write(struct selector_key *key) {
  struct socks5 *socks = key->data;

  if (!socks->relay_started) {
    origin_connect_write_handler(socks, key);
    return;
  }

  if (!relay_flush(key->fd, &socks->read_buffer)) {
    socks5_connection_close(socks, key->s);
    return;
  }

  if (relay_should_close(socks)) {
    socks5_connection_close(socks, key->s);
    return;
  }

  relay_update_interests(socks, key->s);
}

static void origin_connect_close(struct selector_key *key) {
  struct socks5 *socks = key->data;
  if (socks->origin_fd == key->fd) socks->origin_registered = false;
}
