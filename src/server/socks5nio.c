/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 *
 * Primera entrega: fase de negociación completa.
 *   HELLO_READ -> HELLO_WRITE -> AUTH_READ -> AUTH_WRITE -> DONE
 *
 * Se selecciona el método USERNAME/PASSWORD (RFC1929) y se validan las
 * credenciales contra los usuarios provistos por línea de comandos (-u).
 * La fase REQUEST/CONNECT y el relay de datos se implementan en la próxima
 * entrega (ver request.h).
 */
#include <assert.h>// assert
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>// malloc
#include <string.h>// memset
#include <unistd.h>// close

#include <arpa/inet.h>
#include <netdb.h>     // freeaddrinfo, struct addrinfo
#include <sys/socket.h>// accept, recv, send, sockaddr_storage

#include "buffer.h"
#include "hello.h"

#include "args.h"
#include "auth.h"
#include "netutils.h"
#include "request.h"
#include "socks5.h"
#include "socks5nio.h"
#include "stm.h"

#define N(x) (sizeof(x) / sizeof((x)[0]))

/** tamaño de los buffers de I/O de cada conexión */
#define BUFFER_SIZE 4096

/** configuración (usuarios) provista por línea de comandos */
static struct socks5args *socks5_args = NULL;

void socksv5_init(struct socks5args *args) { socks5_args = args; }

/** valida un par usuario/contraseña contra los usuarios configurados */
static bool socks5_credentials_match(const char *user, const char *pass) {
  if (socks5_args == NULL) { return false; }
  for (unsigned i = 0; i < MAX_USERS; i++) {
    const struct users *u = &socks5_args->users[i];
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

/** maquina de estados general */
enum socks_v5state {
  /**
   * recibe el mensaje `hello` del cliente, y lo procesa
   *
   * Intereses:   OP_READ sobre client_fd
   * Transiciones: HELLO_READ | HELLO_WRITE | ERROR
   */
  HELLO_READ,

  /**
   * envía la respuesta del `hello' al cliente.
   *
   * Intereses:   OP_WRITE sobre client_fd
   * Transiciones: HELLO_WRITE | AUTH_READ | ERROR
   */
  HELLO_WRITE,

  /**
   * recibe la sub-negociación usuario/contraseña (RFC1929).
   *
   * Intereses:   OP_READ sobre client_fd
   * Transiciones: AUTH_READ | AUTH_WRITE | ERROR
   */
  AUTH_READ,

  /**
   * envía la respuesta de la autenticación al cliente.
   *
   * Intereses:   OP_WRITE sobre client_fd
   * Transiciones: AUTH_WRITE | DONE (éxito) | ERROR (credenciales inválidas)
   */
  AUTH_WRITE,

  /**
   * [PRÓXIMA ENTREGA] recibe y procesa el REQUEST de SOCKSv5.
   * Placeholder: aún no se transiciona a este estado.
   */
  REQUEST_READ,

  // estados terminales
  DONE,
  ERROR,
};

////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
  buffer *rb, *wb;
  struct hello_parser parser;
  /** el método de autenticación seleccionado */
  uint8_t method;
};

/** usado por AUTH_READ, AUTH_WRITE */
struct auth_st {
  buffer *rb, *wb;
  struct auth_parser parser;
  /** estado de la validación (AUTH_STATUS_SUCCESS / AUTH_STATUS_FAILURE) */
  uint8_t status;
};

/*
 * Si bien cada estado tiene su propio struct que le da un alcance acotado,
 * disponemos de la siguiente estructura para hacer una única alocación cuando
 * recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {
  /** información del cliente */
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len;
  int client_fd;

  /** resolución y conexión al origen (próxima entrega) */
  int origin_fd;
  struct addrinfo *origin_resolution;

  /** maquina de estados */
  struct state_machine stm;

  /** estados para el client_fd */
  union {
    struct hello_st hello;
    struct auth_st auth;
    struct request_st request;
    struct copy copy;
  } client;
  /** estados para el origin_fd */
  union {
    struct connecting conn;
    struct copy copy;
  } orig;

  /** buffers de I/O y su almacenamiento */
  uint8_t raw_buff_read[BUFFER_SIZE];
  uint8_t raw_buff_write[BUFFER_SIZE];
  buffer read_buffer, write_buffer;

  /** contador de referencias y enlace para el pool */
  unsigned references;
  struct socks5 *next;
};

/**
 * Pool de `struct socks5' para evitar alocaciones/liberaciones constantes.
 */
static const unsigned max_pool = 50;
static unsigned pool_size = 0;
static struct socks5 *pool = NULL;

static const struct state_definition *socks5_describe_states(void);

/** crea un nuevo `struct socks5' */
static struct socks5 *socks5_new(int client_fd) {
  struct socks5 *ret;

  if (pool == NULL) {
    ret = malloc(sizeof(*ret));
  } else {
    ret = pool;
    pool = pool->next;
    pool_size--;
  }
  if (ret == NULL) { goto finally; }

  memset(ret, 0x00, sizeof(*ret));

  ret->origin_fd = -1;
  ret->client_fd = client_fd;
  ret->client_addr_len = sizeof(ret->client_addr);

  ret->stm.initial = HELLO_READ;
  ret->stm.max_state = ERROR;
  ret->stm.states = socks5_describe_states();
  stm_init(&ret->stm);

  buffer_init(&ret->read_buffer, N(ret->raw_buff_read), ret->raw_buff_read);
  buffer_init(&ret->write_buffer, N(ret->raw_buff_write), ret->raw_buff_write);

  ret->references = 1;
finally:
  return ret;
}

/** realmente destruye */
static void socks5_destroy_(struct socks5 *s) {
  if (s->origin_resolution != NULL) {
    freeaddrinfo(s->origin_resolution);
    s->origin_resolution = 0;
  }
  free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias y el pool de
 * objetos.
 */
static void socks5_destroy(struct socks5 *s) {
  if (s == NULL) {
    // nada para hacer
  } else if (s->references == 1) {
    if (pool_size < max_pool) {
      s->next = pool;
      pool = s;
      pool_size++;
    } else {
      socks5_destroy_(s);
    }
  } else {
    s->references -= 1;
  }
}

void socksv5_pool_destroy(void) {
  struct socks5 *next, *s;
  for (s = pool; s != NULL; s = next) {
    next = s->next;
    free(s);
  }
  pool = NULL;
  pool_size = 0;
}

/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ((struct socks5 *) (key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read(struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_block(struct selector_key *key);
static void socksv5_close(struct selector_key *key);
static const struct fd_handler socks5_handler = {
  .handle_read = socksv5_read,
  .handle_write = socksv5_write,
  .handle_close = socksv5_close,
  .handle_block = socksv5_block,
};

/** Intenta aceptar la nueva conexión entrante*/
void socksv5_passive_accept(struct selector_key *key) {
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  struct socks5 *state = NULL;

  const int client =
    accept(key->fd, (struct sockaddr *) &client_addr, &client_addr_len);
  if (client == -1) { goto fail; }
  if (selector_fd_set_nio(client) == -1) { goto fail; }
  state = socks5_new(client);
  if (state == NULL) {
    // sin un estado, nos es imposible manejarlo.
    // tal vez deberiamos apagar accept() hasta que detectemos
    // que se liberó alguna conexión.
    goto fail;
  }
  memcpy(&state->client_addr, &client_addr, client_addr_len);
  state->client_addr_len = client_addr_len;

  if (
    SELECTOR_SUCCESS !=
    selector_register(key->s, client, &socks5_handler, OP_READ, state)
  ) {
    goto fail;
  }
  return;
fail:
  if (client != -1) { close(client); }
  socks5_destroy(state);
}

////////////////////////////////////////////////////////////////////////////////
// HELLO
////////////////////////////////////////////////////////////////////////////////

/** callback del parser utilizado en `hello_read' */
static void on_hello_method(struct hello_parser *p, const uint8_t method) {
  uint8_t *selected = p->data;
  // exigimos autenticación: preferimos usuario/contraseña
  if (SOCKS_HELLO_USERNAME_PASSWORD == method) { *selected = method; }
}

/** inicializa las variables de los estados HELLO_… */
static void hello_read_init(const unsigned state, struct selector_key *key) {
  struct hello_st *d = &ATTACHMENT(key)->client.hello;

  d->rb = &ATTACHMENT(key)->read_buffer;
  d->wb = &ATTACHMENT(key)->write_buffer;
  d->method = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;
  d->parser.data = &d->method;
  d->parser.on_authentication_method = on_hello_method;
  hello_parser_init(&d->parser);
}

static unsigned hello_process(const struct hello_st *d);

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned hello_read(struct selector_key *key) {
  struct hello_st *d = &ATTACHMENT(key)->client.hello;
  unsigned ret = HELLO_READ;
  bool error = false;
  uint8_t *ptr;
  size_t count;
  ssize_t n;

  ptr = buffer_write_ptr(d->rb, &count);
  n = recv(key->fd, ptr, count, 0);
  if (n > 0) {
    buffer_write_adv(d->rb, n);
    const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
    if (hello_is_done(st, 0)) {
      if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
        ret = hello_process(d);
      } else {
        ret = ERROR;
      }
    }
  } else {
    ret = ERROR;
  }

  return error ? ERROR : ret;
}

/** procesamiento del mensaje `hello': prepara la respuesta */
static unsigned hello_process(const struct hello_st *d) {
  unsigned ret = HELLO_WRITE;
  if (-1 == hello_marshall(d->wb, d->method)) { ret = ERROR; }
  return ret;
}

/** envía la respuesta del `hello' al cliente */
static unsigned hello_write(struct selector_key *key) {
  struct hello_st *d = &ATTACHMENT(key)->client.hello;
  unsigned ret = HELLO_WRITE;
  uint8_t *ptr;
  size_t count;
  ssize_t n;

  ptr = buffer_read_ptr(d->wb, &count);
  n = send(key->fd, ptr, count, MSG_NOSIGNAL);
  if (n == -1) {
    ret = ERROR;
  } else {
    buffer_read_adv(d->wb, n);
    if (!buffer_can_read(d->wb)) {
      if (SOCKS_HELLO_NO_ACCEPTABLE_METHODS == d->method) {
        // ya le informamos 0xFF al cliente; cerramos
        ret = ERROR;
      } else if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
        ret = AUTH_READ;
      } else {
        ret = ERROR;
      }
    }
  }
  return ret;
}

////////////////////////////////////////////////////////////////////////////////
// AUTH  (RFC1929)
////////////////////////////////////////////////////////////////////////////////

/** inicializa las variables de los estados AUTH_… */
static void auth_read_init(const unsigned state, struct selector_key *key) {
  struct auth_st *d = &ATTACHMENT(key)->client.auth;

  d->rb = &ATTACHMENT(key)->read_buffer;
  d->wb = &ATTACHMENT(key)->write_buffer;
  d->status = AUTH_STATUS_FAILURE;
  auth_parser_init(&d->parser);
}

static unsigned auth_process(struct auth_st *d);

/** lee la sub-negociación usuario/contraseña */
static unsigned auth_read(struct selector_key *key) {
  struct auth_st *d = &ATTACHMENT(key)->client.auth;
  unsigned ret = AUTH_READ;
  bool error = false;
  uint8_t *ptr;
  size_t count;
  ssize_t n;

  ptr = buffer_write_ptr(d->rb, &count);
  n = recv(key->fd, ptr, count, 0);
  if (n > 0) {
    buffer_write_adv(d->rb, n);
    const enum auth_state st = auth_consume(d->rb, &d->parser, &error);
    if (auth_is_done(st, 0)) {
      if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
        ret = auth_process(d);
      } else {
        ret = ERROR;
      }
    }
  } else {
    ret = ERROR;
  }

  return error ? ERROR : ret;
}

/** valida las credenciales y prepara la respuesta */
static unsigned auth_process(struct auth_st *d) {
  const bool ok =
    socks5_credentials_match(d->parser.uname, d->parser.passwd);
  d->status = ok ? AUTH_STATUS_SUCCESS : AUTH_STATUS_FAILURE;
  if (-1 == auth_marshall(d->wb, d->status)) { return ERROR; }
  return AUTH_WRITE;
}

/** envía la respuesta de la autenticación al cliente */
static unsigned auth_write(struct selector_key *key) {
  struct auth_st *d = &ATTACHMENT(key)->client.auth;
  unsigned ret = AUTH_WRITE;
  uint8_t *ptr;
  size_t count;
  ssize_t n;

  ptr = buffer_read_ptr(d->wb, &count);
  n = send(key->fd, ptr, count, MSG_NOSIGNAL);
  if (n == -1) {
    ret = ERROR;
  } else {
    buffer_read_adv(d->wb, n);
    if (!buffer_can_read(d->wb)) {
      // [PRÓXIMA ENTREGA] si status == SUCCESS aquí se pasaría a REQUEST_READ.
      // En esta entrega cerramos la conexión al terminar la negociación.
      ret = (AUTH_STATUS_SUCCESS == d->status) ? DONE : ERROR;
    }
  }
  return ret;
}

////////////////////////////////////////////////////////////////////////////////
// Tabla de estados
////////////////////////////////////////////////////////////////////////////////

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
  {
    .state = HELLO_READ,
    .on_arrival = hello_read_init,
    .on_read_ready = hello_read,
  },
  {
    .state = HELLO_WRITE,
    .on_write_ready = hello_write,
  },
  {
    .state = AUTH_READ,
    .on_arrival = auth_read_init,
    .on_read_ready = auth_read,
  },
  {
    .state = AUTH_WRITE,
    .on_write_ready = auth_write,
  },
  {
    // placeholder para la próxima entrega; aún no se transiciona aquí
    .state = REQUEST_READ,
  },
  {
    .state = DONE,
  },
  {
    .state = ERROR,
  },
};

static const struct state_definition *socks5_describe_states(void) {
  return client_statbl;
}

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.
static void socksv5_done(struct selector_key *key);

static void socksv5_read(struct selector_key *key) {
  struct state_machine *stm = &ATTACHMENT(key)->stm;
  const enum socks_v5state st = stm_handler_read(stm, key);

  if (ERROR == st || DONE == st) { socksv5_done(key); }
}

static void socksv5_write(struct selector_key *key) {
  struct state_machine *stm = &ATTACHMENT(key)->stm;
  const enum socks_v5state st = stm_handler_write(stm, key);

  if (ERROR == st || DONE == st) { socksv5_done(key); }
}

static void socksv5_block(struct selector_key *key) {
  struct state_machine *stm = &ATTACHMENT(key)->stm;
  const enum socks_v5state st = stm_handler_block(stm, key);

  if (ERROR == st || DONE == st) { socksv5_done(key); }
}

static void socksv5_close(struct selector_key *key) {
  socks5_destroy(ATTACHMENT(key));
}

static void socksv5_done(struct selector_key *key) {
  const int fds[] = {
    ATTACHMENT(key)->client_fd,
    ATTACHMENT(key)->origin_fd,
  };
  for (unsigned i = 0; i < N(fds); i++) {
    if (fds[i] != -1) {
      if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
        abort();
      }
      close(fds[i]);
    }
  }
}
