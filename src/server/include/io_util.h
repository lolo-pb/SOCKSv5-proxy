#ifndef IO_UTIL_H
#define IO_UTIL_H

#include <errno.h>
#include <stdbool.h>

// Returns true when the last I/O syscall failed with a would-block error,
// meaning the operation should be retried when the fd is ready.
static inline bool is_retryable_io_error(void) {
  return errno == EAGAIN || errno == EWOULDBLOCK;
}

#endif
