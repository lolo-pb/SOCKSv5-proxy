# SOCKSv5 Proxy Notes

Quick map of the project. Keep this short and update it when the structure changes.

## Project Shape

This is a C SOCKS v5 proxy project.

The server is event-driven. `main.c` owns the listening socket and the selector loop. Accepted client sockets are handled through selector callbacks in `socks5nio.c`, while protocol decisions live in the SOCKS5 protocol files.

Blocking work, like DNS resolution with `getaddrinfo`, happens outside the main selector loop and notifies the selector when ready.

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


Useful server args:

```sh
./bin/server -p 1080 -l 0.0.0.0 -u user:pass
./bin/server -U users.conf
./bin/server -N
```

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
- Drive states: hello read/write, auth read/write, request read/write, connecting, relay, done, error.
- Choose the authentication method.
- Check username/password credentials from CLI users.
- Start origin connections and handle origin fd callbacks.
- Relay data in both directions after CONNECT succeeds.
- Handle relay half-close with directional `shutdown(..., SHUT_WR)`.
- Return read/write/close actions to `socks5nio.c`.

Current protocol support:

- SOCKS5 hello parsing.
- Username/password method selection (`0x02`).
- Username/password auth parsing and response.
- CONNECT request parsing.
- IPv4, IPv6, and domain-name origin connection attempts.
- Async DNS resolution for domain requests.
- FQDN multi-address fallback using a `dns_next` cursor.
- Nonblocking origin connect.
- Bidirectional relay after successful CONNECT.
- Relay half-close handling after one side reaches EOF.

`src/server/hello.c`
Parser/marshaller for the SOCKS5 hello/auth-method negotiation message.

`src/server/auth.c`
Parser/marshaller for username/password subnegotiation.

`src/server/include/socks5.h`
Defines `struct socks5`, protocol states/actions, constants, and the protocol API used by `socks5nio.c`.

`src/server/include/socks5nio.h`
Public NIO API used by `main.c`: `socksv5_init()`, `socksv5_passive_accept()`, and `socksv5_pool_destroy()`.

## Monitoring / Management

The TP requires a separate monitoring/configuration protocol on a different
passive socket from SOCKS.

Current code has the monitoring pieces wired in a minimal way.

`src/server/mon_nio.c`
Management socket handlers. It accepts monitoring clients, parses binary
monitoring requests, checks auth, and writes binary responses.

Supported management commands in the handler:

- auth
- add user
- delete user
- list users
- get metrics
- get access log

`src/server/mon_parser.c`
Parses monitoring requests from bytes into a `mon_request`. It expects the same
request layout produced by `mon_request_encode()`:

```text
version, command, nargs, all arg lengths, then all arg bytes
```

`src/shared/mon_protocol.c`
Encodes monitoring requests/responses and decodes responses. This is shared by
the management client and server.

`src/server/user_table.c`
Separate user table used by the monitoring code.

Current server wiring:

```text
src/server/main.c opens the SOCKS listener
-> opens the management listener from args.mng_addr / args.mng_port
-> registers socksv5_passive_accept() for SOCKS
-> registers mon_passive_accept() for monitoring
-> both listeners share the same selector loop
```

On graceful shutdown, both passive sockets stop accepting new connections.

Management users are initialized from startup users:

```text
parse args / users file
-> SOCKS auth uses args.users
-> main also copies those users into user_table
-> monitoring auth checks user_table_lookup()
```

This keeps initial SOCKS users and initial management users aligned. Runtime
management add/delete currently changes `user_table`; check whether SOCKS auth
should also see those runtime changes before relying on it as final behavior.

## Client Program

`src/client/`
Management client program. It is not a SOCKS consumer. For using the proxy,
use a SOCKS-capable program like `curl --socks5`.

Current client modes:

```sh
./bin/client -u lolo:pass -m
./bin/client -u lolo:pass -U
./bin/client -u lolo:pass --access-log
```

These are one-shot management commands.

```sh
./bin/client
./bin/client -u lolo:pass
```

These open the ncurses UI path.

`src/client/client_args.c`
Parses CLI args. If no command is selected, the caller enters interactive UI
mode. One-shot commands still require `-u user:pass`.

`src/client/mng_client.c`
Selector-based one-shot management client. It connects, sends auth, sends one
command, formats the response to stdout, and exits.

`src/client/client_ui.c`
ncurses UI. Current flow:

```text
start client with no command
-> play src/client/ui/open_animation.txt
-> any key during animation skips it
-> if -u was given, try management auth immediately
-> otherwise show login form
-> login sends MON_CMD_AUTH to the management port
-> on success show a temporary "logged in" placeholder
```

The UI currently only authenticates. The post-login menu and actual management
actions are not wired into ncurses yet.

`src/client/ui/open_animation.txt`
ASCII/Unicode animation frames. Frames are separated by lines containing only:

```text
#
```

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

## Full Proxy Flow

```text
client connects to proxy
-> main server socket becomes readable
-> socksv5_passive_accept() accepts client fd
-> client fd is set nonblocking
-> struct socks5 is allocated for this client
-> client fd is registered in selector with OP_READ
```

```text
client sends SOCKS5 hello
-> selector calls socksv5_read()
-> bytes go into socks->read_buffer
-> socks5_handle_read() runs HELLO_READ state
-> hello parser reads version + auth methods
-> server chooses username/password auth
-> hello reply is written into socks->write_buffer
-> client fd interest becomes OP_WRITE
```

```text
proxy sends hello reply
-> selector calls socksv5_write()
-> bytes are written from socks->write_buffer to client fd
-> hello reply buffer becomes empty
-> socks5_handle_write() moves state to AUTH_READ
-> client fd interest becomes OP_READ
```

```text
client sends username/password auth
-> selector calls socksv5_read()
-> bytes go into socks->read_buffer
-> socks5_handle_read() runs AUTH_READ state
-> auth parser reads username + password
-> credentials are checked against configured users
-> auth response is written into socks->write_buffer
-> client fd interest becomes OP_WRITE
```

```text
proxy sends auth response
-> selector calls socksv5_write()
-> bytes are written from socks->write_buffer to client fd
-> auth response buffer becomes empty
-> if auth succeeded, state moves to REQUEST_READ
-> client fd interest becomes OP_READ
```

```text
client sends CONNECT request
-> selector calls socksv5_read()
-> bytes go into socks->read_buffer
-> socks5_handle_read() runs REQUEST_READ state
-> request parser reads command, address type, destination address, destination port
-> if command is CONNECT, proxy starts origin connection
```

For IPv4 / IPv6:

```text
request has raw IP address
-> build sockaddr from request address + port
-> create nonblocking origin socket
-> call connect()
```

For FQDN/domain:

```text
request has domain name
-> start_domain_connect() creates DNS job
-> DNS thread runs getaddrinfo()
-> client fd interest becomes OP_NOOP while DNS is pending
-> DNS finishes
-> selector wakes client fd with block_done
-> start_resolved_connect() loops resolved addresses
-> create nonblocking origin socket
-> call connect()
-> if async connect fails, dns_next is used to try the next resolved address
```

If origin connect starts asynchronously:

```text
connect() returns EINPROGRESS
-> origin fd is registered in selector with OP_WRITE
-> client fd interest becomes OP_NOOP
-> state becomes CONNECTING
```

When origin connect finishes:

```text
origin fd becomes writable
-> selector calls origin_write()
-> relay has not started yet
-> origin_write() calls origin_connect_write()
-> getsockopt(SO_ERROR) checks connect result
```

If origin connect succeeds:

```text
origin connect succeeds
-> set origin fd OP_NOOP
-> marshal SOCKS success reply into client write buffer
-> state becomes REQUEST_WRITE
-> client fd interest becomes OP_WRITE
```

```text
proxy sends SOCKS success reply
-> selector calls socksv5_write()
-> bytes are written from socks->write_buffer to client fd
-> SOCKS reply buffer becomes empty
-> request_write() sees success
-> start_relay() runs
-> read/write buffers are reset
-> relay_started = true
-> enable origin/client read/write interests
```

Now one forward trip, client to origin:

```text
client sends application data
-> client fd becomes readable
-> selector calls socksv5_read()
-> socks5_is_relaying() is true
-> socks5_relay_client_read() reads from client fd
-> bytes go into socks->read_buffer
-> relay_update_interests() enables OP_WRITE on origin fd
```

```text
proxy forwards data to origin
-> origin fd becomes writable
-> selector calls origin_write()
-> relay_started is true
-> bytes are written from socks->read_buffer to origin fd
-> sent bytes are removed from socks->read_buffer
-> relay_update_interests() updates client/origin interests
```

Now one backward trip, origin to client:

```text
origin sends application data
-> origin fd becomes readable
-> selector calls origin_read()
-> bytes are read from origin fd
-> bytes go into socks->write_buffer
-> relay_update_interests() enables OP_WRITE on client fd
```

```text
proxy forwards data back to client
-> client fd becomes writable
-> selector calls socksv5_write()
-> socks5_is_relaying() is true
-> socks5_relay_client_write() writes from socks->write_buffer to client fd
-> sent bytes are removed from socks->write_buffer
-> relay_update_interests() updates client/origin interests
```

Relay EOF / half-close behavior:

```text
one side reaches EOF
-> proxy stops reading from that side
-> pending data for the opposite side is flushed
-> proxy calls shutdown(other_fd, SHUT_WR)
-> tunnel stays open for the other direction
-> full close happens after both sides EOF and both relay buffers drain
```

So the shortest full version is:

```text
client connects
-> proxy accepts and registers client fd
-> client sends hello
-> proxy replies selected auth method
-> client sends username/password
-> proxy replies auth success
-> client sends CONNECT request
-> proxy resolves/builds destination address
-> proxy starts nonblocking connect to origin
-> origin connect succeeds
-> proxy sends SOCKS success reply
-> proxy starts relay
-> client data is read into read_buffer
-> read_buffer is written to origin
-> origin response is read into write_buffer
-> write_buffer is written to client
```

## Suggestions / Uncertainty

What’s still missing or weak in the SOCKS5 part:

1. Graceful shutdown has no timeout  
   First `SIGINT` / `SIGTERM` stops accepting and waits for active clients.
   A second signal force-closes active connections. If a timeout is wanted,
   it would belong around the draining loop in `main.c`.

## Code Preferences

Do not silence unused parameters with casts like `(void) key;`. If a parameter
is unused because it belongs to a future stub or callback signature, prefer
leaving it plainly unused.
