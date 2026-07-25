"""Control channel between the privileged daemon and the user interface.

The tunnel needs root but a user interface must not run as root, so the two are
separate processes speaking newline-delimited JSON over a unix socket.
"""

from __future__ import annotations

import json
import socket
import threading

SOCKET_PATH = "/var/run/sstp.sock"

# A control message is a few kilobytes at most; anything larger is a client
# gone wrong, and the daemon runs as root, so the buffer is capped.
MAX_MESSAGE = 1 << 20


class ProtocolError(Exception):
    pass


class Channel:
    """Framing for one connection.

    Command replies and broadcast events are written by different threads, so
    sends are serialised to keep two messages from interleaving on the wire.
    """

    def __init__(self, sock: socket.socket):
        self.socket = sock
        self._buffer = bytearray()
        self._send_lock = threading.Lock()

    def send(self, message: dict) -> None:
        payload = json.dumps(message).encode() + b"\n"
        with self._send_lock:
            self.socket.sendall(payload)

    def receive(self) -> dict | None:
        """Return the next message, or None once the peer closes."""
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                if not line.strip():
                    continue
                try:
                    return json.loads(line)
                except ValueError as exc:
                    raise ProtocolError(f"malformed message: {exc}") from exc
            if len(self._buffer) > MAX_MESSAGE:
                raise ProtocolError("message too long")
            chunk = self.socket.recv(65536)
            if not chunk:
                return None
            self._buffer += chunk

    def close(self) -> None:
        try:
            self.socket.close()
        except OSError:
            pass


def connect(path: str = SOCKET_PATH) -> Channel:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    return Channel(sock)


def is_running(path: str = SOCKET_PATH) -> bool:
    try:
        connect(path).close()
    except OSError:
        return False
    return True
