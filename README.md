# SOCKSv5 Proxy

Servidor proxy SOCKSv5 (RFC 1928) con autenticación usuario/contraseña (RFC 1929) y protocolo de monitoreo binario.

## Build

```
make
```

Produce `bin/server` y `bin/client`. Requiere gcc con soporte C11.

## Uso

### Server

```
./bin/server [opciones]
```

| Opción | Default | Descripción |
|--------|---------|-------------|
| `-l addr` | 0.0.0.0 | Dirección de escucha SOCKS |
| `-p port` | 1080 | Puerto SOCKS |
| `-L addr` | 127.0.0.1 | Dirección de escucha monitoreo |
| `-P port` | 8080 | Puerto monitoreo |
| `-u user:pass` | — | Agregar usuario (hasta 10 veces) |
| `-U file` | — | Cargar usuarios desde archivo (formato `user:pass` por línea) |
| `-N` | — | Deshabilitar disector POP3 |

### Client (monitoreo)

```
./bin/client -u admin:pass [opciones] <comando>
```

| Comando | Descripción |
|---------|-------------|
| `-m` | Ver métricas |
| `-U` | Listar usuarios |
| `-a user:pass` | Agregar usuario |
| `-d user` | Eliminar usuario |

## Estructura

```
src/server/    Servidor (SOCKS + monitoreo)
src/client/    Cliente CLI de monitoreo
src/shared/    Infraestructura compartida (buffer, selector, stm, parser)
tests/         Tests unitarios
doc/           Consigna y material de referencia
```
