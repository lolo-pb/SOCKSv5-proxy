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

`src/server/socks5nio.c`
NIO/socket glue for the SOCKS5 server. The listening socket callback accepts clients. Accepted clients are set nonblocking, get a small per-client state object, and are registered in the selector.

This is where the next SOCKS5 behavior is currently being added.

`src/server/socks5.c`
SOCKS5 protocol-level code. Currently has protocol constants through its header and a helper for supported auth methods.

`src/server/include/socks5.h`
SOCKS5 protocol constants, small protocol structs, and protocol helper declarations.

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

We started replacing the temporary accept-and-close behavior.

Current server flow:

Idea de divicion de lod socks: 
  socksv5     = connection/socket wrapper
  socks5      = protocol engine
  selector_key = selector/fd context


1. `main.c` listens on port `1080` by default.
2. The listening fd is registered with the selector for `OP_READ`.
3. When a client connects, `socksv5_passive_accept()` accepts it.
4. The client fd is set nonblocking.
5. A `struct socks5` is allocated for per-client protocol state.
6. The client fd is registered in the selector for `OP_READ`.
7. `socksv5_read()` reads socket bytes into the `struct socks5` read buffer.
8. `socks5.c` drives the SOCKS5 state machine and prepares protocol responses.

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

`socksv5_read()` currently unregisters and closes without actually reading bytes. That is fine as a placeholder, but the next change should introduce a real connection state machine and buffers.

The name `socksv5` appears in code, while the protocol is usually written `socks5`. This is harmless but may become confusing if both spellings spread.


## todo

- si mandas eof muere y no cierra -_  - 
