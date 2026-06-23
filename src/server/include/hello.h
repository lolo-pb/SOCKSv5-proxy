#ifndef HELLO_H_4f1c2b9a
#define HELLO_H_4f1c2b9a

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"

/**
 * hello.h - parser del mensaje de negociación de métodos de SOCKSv5 (RFC1928).
 *
 *   +----+----------+----------+
 *   |VER | NMETHODS | METHODS  |
 *   +----+----------+----------+
 *   | 1  |    1     | 1 to 255 |
 *   +----+----------+----------+
 */

/* métodos de autenticación (RFC1928 sección 3) */
#define SOCKS_HELLO_NOAUTHENTICATION_REQUIRED 0x00
#define SOCKS_HELLO_GSSAPI 0x01
#define SOCKS_HELLO_USERNAME_PASSWORD 0x02
#define SOCKS_HELLO_NO_ACCEPTABLE_METHODS 0xFF

/** estados del parser */
enum hello_state {
  hello_version,
  hello_nmethods,
  hello_methods,
  hello_done,
  /** versión de SOCKS no soportada */
  hello_error_unsupported_version,
};

struct hello_parser {
  /** invocado por cada método anunciado por el cliente */
  void (*on_authentication_method)(
    struct hello_parser *parser, const uint8_t method
  );
  /** dato del usuario (típicamente para almacenar el método seleccionado) */
  void *data;

  /** estado actual del parser */
  enum hello_state state;
  /** métodos que faltan leer */
  uint8_t remaining;
};

/** inicializa el parser */
void hello_parser_init(struct hello_parser *p);

/** entrega un byte al parser. retorna el nuevo estado */
enum hello_state hello_parser_feed(struct hello_parser *p, const uint8_t b);

/**
 * consume los bytes disponibles en el buffer y avanza el parser.
 * En caso de error deja `errored' en true (si no es NULL).
 */
enum hello_state
hello_consume(buffer *b, struct hello_parser *p, bool *errored);

/**
 * Retorna true si el parser terminó (con éxito o error).
 * Si `errored' no es NULL, indica si terminó por error.
 */
bool hello_is_done(const enum hello_state state, bool *errored);

/**
 * Escribe en el buffer la respuesta del hello (VER + METHOD).
 * retorna la cantidad de bytes escritos, o -1 si no hubo espacio.
 */
int hello_marshall(buffer *b, const uint8_t method);

#endif
