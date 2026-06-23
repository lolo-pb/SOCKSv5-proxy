#ifndef AUTH_H_4f1c2b9a
#define AUTH_H_4f1c2b9a

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"

/**
 * auth.h - parser de la sub-negociación usuario/contraseña de SOCKSv5
 *          (RFC1929).
 *
 *   +----+------+----------+------+----------+
 *   |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *   +----+------+----------+------+----------+
 *   | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 *   +----+------+----------+------+----------+
 *
 *   La respuesta es:  +----+--------+
 *                     |VER | STATUS |
 *                     +----+--------+
 *   con STATUS == 0x00 indicando éxito.
 */

/** estados del parser */
enum auth_state {
  auth_version,
  auth_ulen,
  auth_uname,
  auth_plen,
  auth_passwd,
  auth_done,
  /** versión de la sub-negociación no soportada */
  auth_error_unsupported_version,
};

struct auth_parser {
  enum auth_state state;
  uint8_t ulen, plen;
  /** índice de lectura dentro de uname/passwd */
  uint8_t i;
  /** terminados en NUL para poder compararlos con strcmp */
  char uname[256];
  char passwd[256];
};

/** inicializa el parser */
void auth_parser_init(struct auth_parser *p);

/** entrega un byte al parser. retorna el nuevo estado */
enum auth_state auth_parser_feed(struct auth_parser *p, const uint8_t b);

/**
 * consume los bytes disponibles en el buffer y avanza el parser.
 * En caso de error deja `errored' en true (si no es NULL).
 */
enum auth_state auth_consume(buffer *b, struct auth_parser *p, bool *errored);

/**
 * Retorna true si el parser terminó (con éxito o error).
 * Si `errored' no es NULL, indica si terminó por error.
 */
bool auth_is_done(const enum auth_state state, bool *errored);

/**
 * Escribe en el buffer la respuesta (VER + STATUS).
 * retorna la cantidad de bytes escritos, o -1 si no hubo espacio.
 */
int auth_marshall(buffer *b, const uint8_t status);

#endif
