#ifndef REQUEST_H_4f1c2b9a
#define REQUEST_H_4f1c2b9a

#include <stdint.h>

#include "buffer.h"
#include "selector.h"

/**
 * request.h - STUB para la primera entrega.
 *
 * La fase REQUEST (RFC1928: CONNECT, resolución DNS, relay) se implementa en
 * la próxima entrega. Por ahora sólo definimos los tipos que la `union` de
 * `struct socks5` referencia, para que el código compile. Sus cuerpos son
 * mínimos y se completarán al implementar el proxy de datos.
 */

/** usado por REQUEST_READ / REQUEST_WRITE */
struct request_st {
  buffer *rb, *wb;
};

/** usado mientras se establece la conexión con el origen */
struct connecting {
  buffer *wb;
  int *client_fd;
  int *origin_fd;
};

/** usado durante el relay de datos cliente <-> origen */
struct copy {
  int *fd;
  buffer *rb, *wb;
  fd_interest duplex;
  struct copy *other;
};

#endif
