#ifndef SOCKS5NIO_H_4f1c2b9a
#define SOCKS5NIO_H_4f1c2b9a

#include "args.h"
#include "selector.h"

/**
 * socks5nio.h - maneja el flujo de una conexión SOCKSv5 sobre sockets no
 *               bloqueantes, multiplexados con el selector.
 */

/**
 * Inicializa el módulo con la configuración parseada de línea de comandos.
 * Debe llamarse una vez antes de aceptar conexiones; deja una referencia a
 * `args` para validar credenciales (la estructura debe sobrevivir al proceso).
 */
void socksv5_init(struct socks5args *args);

/** Acepta una nueva conexión entrante sobre el socket pasivo. */
void socksv5_passive_accept(struct selector_key *key);

/** Libera el pool de estructuras reutilizadas. */
void socksv5_pool_destroy(void);

#endif
