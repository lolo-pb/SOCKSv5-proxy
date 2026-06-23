#ifndef SOCKS5_H_4f1c2b9a
#define SOCKS5_H_4f1c2b9a

/**
 * socks5.h - constantes del protocolo SOCKSv5 (RFC1928) y de la
 *            sub-negociación usuario/contraseña (RFC1929).
 *
 * Compartido por las distintas fases del proxy (hello, auth y -- en
 * próximas entregas -- request).
 */

/** versión del protocolo SOCKS soportada */
#define SOCKS5_VERSION 0x05

/* --- RFC1928: códigos de respuesta del REQUEST (para próximas entregas) --- */
#define SOCKS5_REPLY_SUCCEEDED 0x00
#define SOCKS5_REPLY_GENERAL_FAILURE 0x01
#define SOCKS5_REPLY_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS5_REPLY_CONNECTION_REFUSED 0x05
#define SOCKS5_REPLY_TTL_EXPIRED 0x06
#define SOCKS5_REPLY_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED 0x08

/* --- RFC1929: sub-negociación usuario/contraseña --- */
#define AUTH_VERSION 0x01
#define AUTH_STATUS_SUCCESS 0x00
#define AUTH_STATUS_FAILURE 0x01

#endif
