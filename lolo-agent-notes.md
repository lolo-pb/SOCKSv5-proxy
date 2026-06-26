# SOCKSv5 Proxy Notes

These notes are a quick map of the project. Keep them short and update them when the structure changes.

## Project Shape

This is a C SOCKS v5 proxy project.

The server is event-driven: one main loop watches file descriptors with the custom selector. The listening socket accepts new clients, and each client is meant to be handled through callbacks and a state machine.

Blocking work, like DNS resolution with `getaddrinfo`, is expected to happen outside the main selector loop and notify the selector when ready.

## Folders

`src/server/`
Server-side code. This is where the SOCKS proxy behavior is being built.

`src/server/include/`
Server headers.

`src/client/`
Client program entrypoint. Currently separate from the server work.

`src/shared/`
Reusable infrastructure used by client/server: selector, buffers, parser, state machine, args, net helpers.

`src/shared/include/`
Headers for shared infrastructure.

`tests/`
Unit tests for shared pieces.

`doc/`
Assignment/reference material.

`bin/`
Build output, like `bin/server` and `bin/client`.

`obj/`
Compiled object files.

## Main Files

`Makefile`
Builds the project. Main commands:

```sh
make
make all
make server
make client
make clean
```

`Makefile.inc`
Compiler settings. Currently uses `gcc`, C11, warnings, pedantic mode, and debug symbols.

`src/server/main.c`
Server bootstrap. Parses an optional port argument, creates the passive TCP socket, binds/listens, initializes the selector, registers the listening socket, and runs the selector loop.

Default port is `1080`.

`main.c` does not implement the SOCKS5 protocol itself. Its main server-specific handoff is registering the passive server fd with this handler:

```c
.handle_read = socksv5_passive_accept
```

After that, new client sockets and protocol state are owned by the SOCKS5 NIO/protocol files.

`src/server/socks5nio.c`
Selector/socket glue for the SOCKS5 server. It is the layer between the generic selector and the SOCKS5 protocol engine.

Responsibilities:

- Accept new clients from the passive server fd.
- Put accepted client sockets in nonblocking mode.
- Allocate one `struct socks5` per client connection.
- Register each client fd in the selector with read/write callbacks.
- Read bytes from the socket into the connection's `struct socks5` read buffer.
- Ask `socks5.c` what the protocol wants to do next: read, write, or close.
- Write prepared response bytes back to the client.
- Unregister/close client fds and free the per-client state when done.

The important object relationship is:

```text
selector fd data -> struct socks5
```

So when the selector calls a client callback, `key->data` is the SOCKS5 state for that client.

`src/server/socks5.c`
SOCKS5 protocol-level code. This owns the per-connection protocol state machine and decides what response should be sent next.

Responsibilities:

- Initialize `struct socks5`.
- Track the SOCKS5 phase, currently hello/auth-method negotiation and request-read placeholder.
- Interpret bytes that `socks5nio.c` already read from the socket.
- Fill the response buffer when the protocol needs to answer.
- Return a `socks5_action` telling the NIO layer whether to wait for read, wait for write, or close.

Right now it supports the initial SOCKS5 hello enough to accept no-auth (`0x00`) or reject unsupported/invalid methods with `0xFF`. The actual CONNECT request handling is still only a placeholder.

`src/server/include/socks5.h`
SOCKS5 protocol constants, the `struct socks5` per-client state object, state/action enums, and protocol helper declarations.

`src/server/include/socks5nio.h`
Public server NIO API used by `main.c`.

`src/shared/selector.c`
Custom selector/event loop. Registers fds, tracks read/write interest, dispatches callbacks, and handles notifications from blocking jobs.

`src/shared/stm.c`
Small state-machine engine. This is likely useful for SOCKS5 connection phases.

`src/shared/buffer.c`
Read/write buffer helper for socket I/O.

`src/shared/parser.c`
Generic byte parser engine.

`src/shared/netutils.c`
Shared network helpers.

## Runtime Layers

`socksv5`
Connection/socket wrapper idea. This is the NIO side: accepted client fd, selector registration, socket reads/writes, close behavior.

`socks5`
Protocol engine. This owns the SOCKS5 state machine, current read bytes, prepared response bytes, and protocol decisions.

`selector_key`
Selector/fd event context. The selector passes this to callbacks so handlers know which selector and fd fired, plus the per-fd `data` pointer.

Current code keeps this simple: the selector `data` for a client points directly to `struct socks5`.

## Current SOCKS5 Work

Current server flow:

1. `main.c` listens on port `1080` by default.
2. The listening fd is registered with the selector for `OP_READ`.
3. When a client connects, `socksv5_passive_accept()` accepts it.
4. The client fd is set nonblocking.
5. A `struct socks5` is allocated for per-client protocol state.
6. The client fd is registered in the selector for `OP_READ`.
7. `socksv5_read()` reads socket bytes into the `struct socks5` read buffer.
8. `socks5.c` drives the SOCKS5 state machine and prepares protocol responses.
9. `socks5nio.c` applies the returned action by changing selector interest to read/write or closing the fd.

`socks5nio.c`
Selector/socket glue lives here.

`socks5.h` / `socks5.c`
SOCKS5 constants and protocol helpers live here. Request parsing and response building should be added here as the protocol implementation grows.

## Current Manual Test

Start the server:

```sh
./bin/server
```

Connect with netcat from another terminal:

```sh
nc localhost 1080
helo
```

Observed server output:

```text
Listening on TCP port 1080
new connection fd=3
Read smth from fd=3
closing ...^Csignal 2, cleaning up and exiting
closing: Interrupted system call
```

The `closing: Interrupted system call` line appears after pressing `Ctrl-C` while the selector is blocked. It is part of the current shutdown path, not the SOCKS5 protocol.

## Suggestions / Uncertainty

CONNECT request parsing and upstream connection handling are not implemented yet. `socks5.c` currently stops at the request-read state placeholder.

The name `socksv5` appears in code, while the protocol is usually written `socks5`. This is harmless but may become confusing if both spellings spread.


## todo

- si mandas eof muere y no cierra -_  - 
