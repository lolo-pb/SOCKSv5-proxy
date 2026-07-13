#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import os
import random
import signal
import struct
import time
from dataclasses import dataclass


DEFAULT_USERS_FILE = "users.conf"


@dataclass
class Stats:
    attempts: int = 0
    connected: int = 0
    failed: int = 0
    closed: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    active_long: int = 0
    active_short: int = 0


class Counters:
    def __init__(self):
        self.stats = Stats()
        self.lock = asyncio.Lock()

    async def add(self, **changes):
        async with self.lock:
            for key, value in changes.items():
                setattr(self.stats, key, getattr(self.stats, key) + value)

    async def snapshot(self):
        async with self.lock:
            return Stats(**self.stats.__dict__)


class ActiveUserRateLimiter:
    def __init__(self, changes_per_second):
        self.interval = 1.0 / changes_per_second
        self.lock = asyncio.Lock()
        self.next_change = 0.0

    async def wait(self):
        async with self.lock:
            now = time.monotonic()
            if now < self.next_change:
                await asyncio.sleep(self.next_change - now)
                now = time.monotonic()
            self.next_change = now + self.interval


def load_users(path):
    users = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                raise ValueError(f"bad user line in {path!r}: {line!r}")
            user, password = line.split(":", 1)
            if user and password:
                users.append((user.encode(), password.encode()))
    if not users:
        raise ValueError(f"no users found in {path!r}")
    return users


def encode_socks_addr(host, port):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raw_host = host.encode("idna")
        if len(raw_host) > 255:
            raise ValueError("target hostname is too long for SOCKS5")
        return b"\x03" + bytes([len(raw_host)]) + raw_host + struct.pack("!H", port)

    if ip.version == 4:
        return b"\x01" + ip.packed + struct.pack("!H", port)
    return b"\x04" + ip.packed + struct.pack("!H", port)


async def read_socks_reply(reader):
    head = await reader.readexactly(4)
    if head[0] != 5:
        raise OSError(f"bad SOCKS version in reply: {head[0]}")
    if head[1] != 0:
        raise OSError(f"SOCKS CONNECT failed with reply code {head[1]}")

    atyp = head[3]
    if atyp == 1:
        await reader.readexactly(4)
    elif atyp == 3:
        n = (await reader.readexactly(1))[0]
        await reader.readexactly(n)
    elif atyp == 4:
        await reader.readexactly(16)
    else:
        raise OSError(f"bad SOCKS address type in reply: {atyp}")
    await reader.readexactly(2)


async def socks_connect(args, users):
    user, password = random.choice(users)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(args.socks_host, args.socks_port),
        timeout=args.connect_timeout,
    )

    writer.write(b"\x05\x01\x02")
    await writer.drain()
    method = await asyncio.wait_for(reader.readexactly(2), timeout=args.io_timeout)
    if method != b"\x05\x02":
        writer.close()
        await writer.wait_closed()
        raise OSError(f"proxy rejected username/password auth: {method!r}")

    if len(user) > 255 or len(password) > 255:
        raise ValueError("username/password too long for RFC1929 auth")
    writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
    await writer.drain()
    auth = await asyncio.wait_for(reader.readexactly(2), timeout=args.io_timeout)
    if auth != b"\x01\x00":
        writer.close()
        await writer.wait_closed()
        raise OSError(f"SOCKS auth failed for {user.decode(errors='replace')}")

    request = b"\x05\x01\x00" + encode_socks_addr(args.target_host, args.target_port)
    writer.write(request)
    await writer.drain()
    await asyncio.wait_for(read_socks_reply(reader), timeout=args.io_timeout)
    return reader, writer


async def close_writer(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass


async def echo_handler(reader, writer):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                return
            writer.write(data)
            await writer.drain()
    finally:
        await close_writer(writer)


async def run_local_echo_server(host, port):
    server = await asyncio.start_server(echo_handler, host, port)
    sockets = server.sockets or []
    actual_port = sockets[0].getsockname()[1]
    return server, actual_port


async def one_session(args, users, counters, stop_at, long_lived, worker_id, active_limiter):
    await counters.add(attempts=1)
    reader = writer = None
    active_key = "active_long" if long_lived else "active_short"
    active_added = False
    try:
        if active_limiter is not None:
            await active_limiter.wait()
        reader, writer = await socks_connect(args, users)
        await counters.add(connected=1, **{active_key: 1})
        active_added = True

        if long_lived:
            end = min(stop_at, time.monotonic() + random.uniform(args.long_min, args.long_max))
            seq = 0
            while time.monotonic() < end:
                payload = f"long {worker_id} {seq} {time.time()}\n".encode()
                writer.write(payload)
                await writer.drain()
                data = await asyncio.wait_for(reader.readexactly(len(payload)), args.io_timeout)
                if data != payload:
                    raise OSError("echo payload mismatch")
                await counters.add(bytes_sent=len(payload), bytes_recv=len(data))
                seq += 1
                await asyncio.sleep(random.uniform(args.ping_min, args.ping_max))
        else:
            payload_len = random.randint(args.short_min_bytes, args.short_max_bytes)
            payload = os.urandom(payload_len)
            writer.write(payload)
            await writer.drain()
            got = 0
            while got < payload_len:
                data = await asyncio.wait_for(
                    reader.read(min(4096, payload_len - got)), args.io_timeout
                )
                if not data:
                    raise OSError("short connection closed early")
                got += len(data)
            await counters.add(bytes_sent=payload_len, bytes_recv=got)
            await asyncio.sleep(random.uniform(args.short_hold_min, args.short_hold_max))

    except (asyncio.TimeoutError, OSError, ValueError) as e:
        await counters.add(failed=1)
        if args.verbose:
            print(f"[worker {worker_id}] {type(e).__name__}: {e}")
    finally:
        if writer is not None:
            if active_added and active_limiter is not None:
                await active_limiter.wait()
            await close_writer(writer)
            changes = {"closed": 1}
            if active_added:
                changes[active_key] = -1
            await counters.add(**changes)


async def long_worker(args, users, counters, stop_event, worker_id, active_limiter):
    while not stop_event.is_set():
        stop_at = time.monotonic() + args.duration
        await one_session(args, users, counters, stop_at, True, worker_id, active_limiter)
        await asyncio.sleep(random.uniform(args.reconnect_min, args.reconnect_max))


async def short_worker(args, users, counters, stop_event, worker_id, active_limiter):
    while not stop_event.is_set():
        stop_at = time.monotonic() + args.duration
        await one_session(args, users, counters, stop_at, False, worker_id, active_limiter)
        await asyncio.sleep(random.uniform(args.churn_min, args.churn_max))


async def reporter(counters, stop_event, interval):
    started = time.monotonic()
    while not stop_event.is_set():
        await asyncio.sleep(interval)
        s = await counters.snapshot()
        elapsed = time.monotonic() - started
        print(
            f"{elapsed:7.1f}s "
            f"attempts={s.attempts} connected={s.connected} failed={s.failed} "
            f"active_long={s.active_long} active_short={s.active_short} "
            f"closed={s.closed} sent={s.bytes_sent} recv={s.bytes_recv}",
            flush=True,
        )


async def run(args):
    users = load_users(args.users)
    echo_server = None

    if args.local_echo:
        echo_server, actual_port = await run_local_echo_server(args.echo_host, args.echo_port)
        args.target_host = args.echo_host
        args.target_port = actual_port
        print(f"local echo target listening on {args.target_host}:{args.target_port}")

    counters = Counters()
    active_limiter = (
        ActiveUserRateLimiter(args.user_change_rate) if args.steady_users else None
    )
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    workers = []
    for i in range(args.long_connections):
        workers.append(
            asyncio.create_task(
                long_worker(args, users, counters, stop_event, i, active_limiter)
            )
        )
    for i in range(args.connections - args.long_connections):
        workers.append(
            asyncio.create_task(
                short_worker(args, users, counters, stop_event, i, active_limiter)
            )
        )
    workers.append(asyncio.create_task(reporter(counters, stop_event, args.report_every)))

    try:
        await asyncio.wait_for(stop_event.wait(), timeout=args.duration)
    except asyncio.TimeoutError:
        stop_event.set()

    await asyncio.gather(*workers, return_exceptions=True)
    if echo_server is not None:
        echo_server.close()
        await echo_server.wait_closed()

    s = await counters.snapshot()
    print(
        "final: "
        f"attempts={s.attempts} connected={s.connected} failed={s.failed} "
        f"closed={s.closed} sent={s.bytes_sent} recv={s.bytes_recv}"
    )


def parse_args():
    p = argparse.ArgumentParser(
        description="Stress a SOCKS5 proxy with authenticated short and long-lived sessions."
    )
    p.add_argument("--socks-host", default="127.0.0.1")
    p.add_argument("--socks-port", type=int, default=1080)
    p.add_argument("--users", default=DEFAULT_USERS_FILE)
    p.add_argument("--connections", type=int, default=200)
    p.add_argument("--long-connections", type=int, default=50)
    p.add_argument("--duration", type=float, default=300.0)
    p.add_argument("--report-every", type=float, default=5.0)
    p.add_argument("--connect-timeout", type=float, default=5.0)
    p.add_argument("--io-timeout", type=float, default=10.0)
    p.add_argument("--verbose", action="store_true")
    p.add_argument(
        "--steady-users",
        action="store_true",
        help="rate-limit active connection opens/closes so current users changes slowly",
    )
    p.add_argument(
        "--user-change-rate",
        type=float,
        default=1.0,
        help="max active user changes per second when --steady-users is enabled",
    )

    p.add_argument("--local-echo", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--echo-host", default="127.0.0.1")
    p.add_argument("--echo-port", type=int, default=0)
    p.add_argument("--target-host", default="127.0.0.1")
    p.add_argument("--target-port", type=int, default=0)

    p.add_argument("--long-min", type=float, default=20.0)
    p.add_argument("--long-max", type=float, default=90.0)
    p.add_argument("--ping-min", type=float, default=1.0)
    p.add_argument("--ping-max", type=float, default=5.0)
    p.add_argument("--reconnect-min", type=float, default=0.2)
    p.add_argument("--reconnect-max", type=float, default=3.0)

    p.add_argument("--churn-min", type=float, default=0.05)
    p.add_argument("--churn-max", type=float, default=1.0)
    p.add_argument("--short-hold-min", type=float, default=0.0)
    p.add_argument("--short-hold-max", type=float, default=2.0)
    p.add_argument("--short-min-bytes", type=int, default=64)
    p.add_argument("--short-max-bytes", type=int, default=16384)

    args = p.parse_args()
    if args.connections < 1:
        p.error("--connections must be positive")
    if args.long_connections < 0 or args.long_connections > args.connections:
        p.error("--long-connections must be between 0 and --connections")
    if args.user_change_rate <= 0:
        p.error("--user-change-rate must be positive")
    if not args.local_echo and args.target_port <= 0:
        p.error("--target-port is required with --no-local-echo")
    return args


if __name__ == "__main__":
    asyncio.run(run(parse_args()))
