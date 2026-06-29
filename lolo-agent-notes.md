# SOCKSv5 Proxy Notes

Quick map of the project. Keep this short and update it when the structure changes.

## Project Shape

This is a C SOCKS v5 proxy project.

The server is event-driven. `main.c` owns the listening socket and the selector loop. Accepted client sockets are handled through selector callbacks in `socks5nio.c`, while protocol decisions live in the SOCKS5 protocol files.

Blocking work, like future DNS resolution with `getaddrinfo`, is expected to happen outside the main selector loop and notify the selector when ready.

## Folders

`src/server/`
Server code: server entrypoint, SOCKS5 socket glue, and SOCKS5 protocol parsers.

`src/server/include/`
Headers for the server modules.

`src/shared/`
Reusable infrastructure: args, selector, buffers, parser, state machine, and network helpers.

`src/shared/include/`
Headers for shared infrastructure.

`src/client/`
Client program entrypoint. It is separate from the server path.

`tests/`
Unit tests for shared pieces.

`doc/`
Assignment/reference material.

`bin/`
Build output, like `bin/server` and `bin/client`.

`obj/`
Compiled object files.

## Build And Run

`Makefile`
Builds all `src/server/*.c`, `src/client/*.c`, and `src/shared/*.c`.

Main commands:

```sh
make
make server
make client
make clean
```

`Makefile.inc`
Compiler settings. Currently uses `gcc`, C11, warnings, pedantic mode, and debug symbols.

Server defaults come from `src/shared/args.c`:

```text
SOCKS listen addr: 0.0.0.0
SOCKS listen port: 1080
management addr:   127.0.0.1
management port:   8080
max users:         10
```

Useful server args:

```sh
./bin/server -p 1080 -l 0.0.0.0 -u user:pass
```

## Code Preferences

Do not silence unused parameters with casts like `(void) key;`. If a parameter
is unused because it belongs to a future stub or callback signature, prefer
leaving it plainly unused.

## Main Runtime Flow

1. `src/server/main.c` parses CLI args into `struct socks5args`.
2. `main.c` passes those args into `socksv5_init()`.
3. `main.c` creates, binds, and listens on the passive TCP socket.
4. `main.c` initializes the selector and registers the passive socket for `OP_READ`.
5. The passive socket handler is `socksv5_passive_accept()`.
6. `socks5nio.c` accepts each client, sets it nonblocking, allocates `struct socks5`, and registers the client fd.
7. For each client event, `socks5nio.c` does socket I/O and stores bytes in shared `buffer` objects.
8. `socks5.c` consumes those buffers through the protocol state machine.
9. `socks5.c` returns a `socks5_action`: wait for read, wait for write, or close.
10. `socks5nio.c` applies that action to the selector/client fd.

Important object relationship:

```text
selector client fd data -> struct socks5
```

So client callbacks receive `key->data` as that client's SOCKS5 state.

## Server Files

`src/server/main.c`
Server bootstrap. It owns process-level setup: CLI args, listen address/port, passive socket, signals, selector creation, selector loop, and shutdown cleanup.

It does not implement SOCKS5 protocol behavior. Its key handoff is:

```c
.handle_read = socksv5_passive_accept
```

`src/server/socks5nio.c`
NIO/socket glue for SOCKS5 clients.

Responsibilities:

- Accept clients from the passive server fd.
- Set client sockets to nonblocking mode.
- Allocate/free one `struct socks5` per client.
- Register client fds in the selector.
- Read socket bytes into `state->read_buffer`.
- Write bytes from `state->write_buffer`.
- Ask `socks5.c` what selector interest should come next.
- Close client fds on EOF, error, or protocol completion.

`src/server/socks5.c`
Main SOCKS5 protocol state machine.

Responsibilities:

- Initialize `struct socks5`.
- Store global server args for credential checks.
- Drive states: hello read/write, auth read/write, request read, done, error.
- Choose the authentication method.
- Check username/password credentials from CLI users.
- Return read/write/close actions to `socks5nio.c`.

Current protocol support:

- SOCKS5 hello parsing.
- Username/password method selection (`0x02`).
- Username/password auth parsing and response.
- CONNECT request parsing.
- IPv4, IPv6, and domain-name origin connection attempts.
- Async DNS resolution for domain requests.
- Nonblocking origin connect.
- Bidirectional relay after successful CONNECT.

`src/server/hello.c`
Parser/marshaller for the SOCKS5 hello/auth-method negotiation message.

`src/server/auth.c`
Parser/marshaller for username/password subnegotiation.

`src/server/include/socks5.h`
Defines `struct socks5`, protocol states/actions, constants, and the protocol API used by `socks5nio.c`.

`src/server/include/socks5nio.h`
Public NIO API used by `main.c`: `socksv5_init()`, `socksv5_passive_accept()`, and `socksv5_pool_destroy()`.

## Shared Files

`src/shared/args.c`
CLI parser. Fills `struct socks5args` with listen addresses, ports, dissector setting, and up to 10 users.

`src/shared/selector.c`
Custom selector/event loop. Registers fds, tracks read/write interest, dispatches callbacks, and supports notifications from blocking jobs.

`src/shared/buffer.c`
Read/write buffer helper. Server connections now use this instead of raw read/write counters.

`src/shared/stm.c`
Small state-machine engine used by the SOCKS5 protocol.

`src/shared/parser.c`
Generic byte parser engine.

`src/shared/netutils.c`
Shared network helpers.

## Suggestions / Uncertainty

The note is outdated. The SOCKS5 core is no longer missing CONNECT entirely: it has hello, username/password auth, request parsing, IPv4/IPv6/domain connect, async DNS, nonblocking connect, and relay.

What’s still missing or weak in the SOCKS5 part:

1. FQDN multi-address fallback is incomplete  
   `socks5.c` tries resolved addresses only until one `connect()` starts. If that async connect later fails in `origin_connect_write`, it replies failure instead of trying the next resolved address. The TP explicitly asks for trying other IPs when an FQDN resolves to multiple addresses.

2. Half-close relay behavior is probably too aggressive  
   `relay_should_close` closes the whole tunnel when either side EOFs and its pending buffer drains. A more transparent proxy should `shutdown()` one direction and keep the other direction alive until both sides are done.

   PREENTREGA : ask whether this TP expects TCP half-close correctness in the SOCKS relay, or whether closing the tunnel after one side finishes sending is acceptable for the demos/tests.

     Current behavior:

     client <-> proxy <-> origin
   
     If either side reaches EOF, the proxy eventually closes the whole connection once
     pending buffered data is flushed.
   
     Example:
   
     client sends request
     client closes its write side
     origin still wants to send a response 

3. Cleanup/pool shutdown is unfinished  
   `socksv5_pool_destroy` is still TODO, and graceful shutdown in `main.c` stops the loop rather than stopping accepts and waiting for active connections.

Build status: `make` passes.

The name `socksv5` appears in the NIO code, while the protocol is usually written `socks5`. This is harmless but can be confusing when reading the split between socket glue and protocol code.
