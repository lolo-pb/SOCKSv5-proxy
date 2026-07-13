# SOCKSv5 Proxy

Servidor proxy SOCKSv5 (RFC 1928) con autenticación usuario/contraseña (RFC 1929) y protocolo de monitoreo binario.

## Materiales

| Material | Ubicación |
|----------|-----------|
| Informe | `doc/informe/` |
| Código fuente servidor | `src/server/` |
| Código fuente cliente | `src/client/` |
| Código compartido | `src/shared/` |
| Tests | `tests/` |

## Build

```
make
```

Requiere gcc con soporte C11, pthreads, y libncursesw. Produce los binarios en `bin/`.

| Artefacto | Ubicación |
|-----------|-----------|
| Servidor proxy | `bin/server` |
| Cliente monitoreo | `bin/client` |

Para limpiar: `make clean`

## Ejecución

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

### Client (monitoreo)

```
./bin/client -u user:pass [opciones] <comando>
```

| Opción/Comando | Descripción |
|----------------|-------------|
| `-l addr` | Dirección del servidor (default 127.0.0.1) |
| `-P port` | Puerto de monitoreo (default 8080) |
| `-u user:pass` | Credenciales de autenticación |
| `-m` | Ver métricas |
| `-U` | Listar usuarios |
| `-a user:pass` | Agregar usuario |
| `-d user` | Eliminar usuario |
