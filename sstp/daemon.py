"""Privileged daemon that owns the tunnel and serves control clients.

The user interface runs unprivileged and drives this over a unix socket. The
card is re-read on every connect rather than cached, because the token may have
been swapped for a different one between attempts.
"""

from __future__ import annotations

import grp
import os
import socket
import threading
import time

from . import ipc, log, net
from .session import Config, Session
from .token import Token, TokenError

logger = log.get("daemon")

# Only administrators may control the tunnel; the socket is the whole security
# boundary, since anyone who can talk to it can reroute all traffic.
CONTROL_GROUP = "admin"
SOCKET_MODE = 0o660


class DaemonError(Exception):
    pass


def _describe(entry) -> dict:
    return {
        "ckaid": entry.ckaid.hex(),
        "label": entry.label,
        "subject": entry.subject,
        "issuer": entry.issuer,
        "upn": entry.principal_name(),
        "expires": entry.certificate.not_valid_after_utc.isoformat(),
        "expired": entry.is_expired,
        "self_signed": entry.is_self_signed,
        "can_authenticate": entry.can_authenticate,
        "suitable": entry.is_suitable,
    }


class Daemon:
    def __init__(self, socket_path: str = ipc.SOCKET_PATH):
        self.socket_path = socket_path
        self._lock = threading.Lock()
        self._state: dict = {"state": "idle", "since": time.time()}
        self._session: Session | None = None
        self._worker: threading.Thread | None = None
        self._subscribers: list[ipc.Channel] = []
        self._server: socket.socket | None = None
        self._running = False

    # ------------------------------------------------------------------ state

    def _set_state(self, state: str, **fields) -> None:
        with self._lock:
            self._state = {"state": state, "since": time.time(), **fields}
            payload = dict(self._state)
        logger.info("state: %s%s", state, f" ({fields})" if fields else "")
        self._broadcast({"event": "state", **payload})

    def _broadcast(self, message: dict) -> None:
        with self._lock:
            targets = list(self._subscribers)
        for channel in targets:
            try:
                channel.send(message)
            except OSError:
                with self._lock:
                    if channel in self._subscribers:
                        self._subscribers.remove(channel)

    def _status(self) -> dict:
        with self._lock:
            status = dict(self._state)
            session = self._session
        if session is not None and session.utun is not None:
            status["rx_bytes"] = session.utun.rx_bytes
            status["tx_bytes"] = session.utun.tx_bytes
        return status

    # --------------------------------------------------------------- commands

    def _command_ping(self, request: dict) -> dict:
        return {"ok": True, "pong": True}

    def _command_status(self, request: dict) -> dict:
        return {"ok": True, "status": self._status()}

    def _command_tokens(self, request: dict) -> dict:
        try:
            token = Token(request.get("module"))
        except TokenError as exc:
            return {"ok": False, "error": str(exc)}
        tokens = []
        try:
            for info in token.slots():
                token.open(slot=info.slot)
                tokens.append(
                    {
                        "slot": info.slot,
                        "label": info.label,
                        "serial": info.serial,
                        "pin_locked": info.pin_locked,
                        "pin_final_try": info.pin_final_try,
                        "pin_count_low": info.pin_count_low,
                        "certificates": [_describe(c) for c in token.certificates()],
                    }
                )
                token.close()
        except TokenError as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            token.close()
        return {"ok": True, "module": token.module_path, "tokens": tokens}

    def _command_connect(self, request: dict) -> dict:
        with self._lock:
            if self._state["state"] in ("connecting", "connected"):
                return {"ok": False, "error": "a tunnel is already active"}

        server = request.get("server")
        if not server:
            return {"ok": False, "error": "no server was given"}
        pin = request.get("pin")
        if not pin:
            return {"ok": False, "error": "no PIN was given"}

        self._set_state("connecting", server=server)
        try:
            token, identity = self._prepare_token(request, pin)
        except TokenError as exc:
            self._set_state("failed", error=str(exc))
            return {"ok": False, "error": str(exc)}
        finally:
            # The PIN is used once for C_Login and never stored or logged.
            del pin
            request.pop("pin", None)

        config = Config(
            server=server,
            port=request.get("port", 443),
            username=request.get("username", ""),
            ca_file=request.get("ca_file"),
            verify_outer=request.get("verify_outer", True),
            verify_inner=request.get("verify_inner", True),
            inner_ca_file=request.get("inner_ca_file"),
            mtu=request.get("mtu", 1400),
            default_route=request.get("default_route", True),
            set_dns=request.get("set_dns", True),
            extra_routes=request.get("routes", []),
            dns_domains=request.get("dns_domains") or [],
        )
        session = Session(config, token, identity, on_event=self._on_session_event)
        with self._lock:
            self._session = session
            self._worker = threading.Thread(
                target=self._run_session,
                args=(session, token, identity),
                name="tunnel",
                daemon=True,
            )
            self._worker.start()
        return {"ok": True, "certificate": identity.subject}

    def _prepare_token(self, request: dict, pin: str):
        """Read the card from scratch and log in; never reuse a cached view."""
        token = Token(request.get("module"))
        try:
            token.open(slot=request.get("slot"))
            wanted = (request.get("ckaid") or "").lower()
            certificates = token.certificates()
            chosen = next(
                (entry for entry in certificates if entry.ckaid.hex() == wanted), None
            )
            if chosen is None:
                raise TokenError("the chosen certificate is not on this token")
            if not chosen.can_authenticate:
                raise TokenError(
                    f"{chosen.subject} is not marked for client authentication"
                )
            if chosen.is_expired:
                raise TokenError(f"{chosen.subject} has expired")
            token.login(pin)
            return token, token.identity_for(chosen)
        except Exception:
            token.close()
            raise

    def _command_disconnect(self, request: dict) -> dict:
        with self._lock:
            session = self._session
        if session is None:
            return {"ok": False, "error": "no tunnel is active"}
        session.stop()
        return {"ok": True}

    def _command_subscribe(self, request: dict, channel: ipc.Channel) -> dict:
        with self._lock:
            self._subscribers.append(channel)
        return {"ok": True, "status": self._status()}

    # ---------------------------------------------------------------- session

    def _on_session_event(self, name: str, **fields) -> None:
        if name == "connected":
            with self._lock:
                server = self._state.get("server")
            self._set_state("connected", server=server, **fields)

    def _run_session(self, session: Session, token, identity) -> None:
        try:
            session.connect()
            session.run()
            self._set_state("disconnected")
        except Exception as exc:
            logger.error("tunnel failed: %s", exc)
            self._set_state("failed", error=str(exc))
        finally:
            session.shutdown()
            token.close()
            with self._lock:
                self._session = None

    # ------------------------------------------------------------------ serve

    def _listen(self) -> socket.socket:
        if os.path.exists(self.socket_path):
            if ipc.is_running(self.socket_path):
                raise DaemonError(
                    f"another daemon is already listening on {self.socket_path}"
                )
            logger.warning("removing a stale socket at %s", self.socket_path)
            os.unlink(self.socket_path)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        os.chmod(self.socket_path, SOCKET_MODE)
        try:
            os.chown(self.socket_path, 0, grp.getgrnam(CONTROL_GROUP).gr_gid)
        except (KeyError, PermissionError) as exc:
            logger.warning("cannot restrict %s to the admin group: %s",
                           self.socket_path, exc)
        server.listen(8)
        logger.info("listening on %s", self.socket_path)
        return server

    def serve(self) -> None:
        self._server = self._listen()
        net.recover_leftovers()
        self._running = True
        try:
            while self._running:
                try:
                    client, _ = self._server.accept()
                except OSError:
                    break
                threading.Thread(
                    target=self._serve_client, args=(client,), daemon=True
                ).start()
        finally:
            self.stop()

    def _serve_client(self, sock: socket.socket) -> None:
        channel = ipc.Channel(sock)
        handlers = {
            "ping": self._command_ping,
            "status": self._command_status,
            "tokens": self._command_tokens,
            "connect": self._command_connect,
            "disconnect": self._command_disconnect,
        }
        try:
            while True:
                request = channel.receive()
                if request is None:
                    break
                command = request.get("command")
                logger.debug("command %s", command)
                if command == "subscribe":
                    reply = self._command_subscribe(request, channel)
                elif command in handlers:
                    try:
                        reply = handlers[command](request)
                    except Exception as exc:
                        logger.exception("command %s failed", command)
                        reply = {"ok": False, "error": str(exc)}
                else:
                    reply = {"ok": False, "error": f"unknown command {command!r}"}
                channel.send(reply)
        except (OSError, ipc.ProtocolError) as exc:
            logger.debug("client gone: %s", exc)
        finally:
            with self._lock:
                if channel in self._subscribers:
                    self._subscribers.remove(channel)
            channel.close()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        with self._lock:
            session = self._session
        if session is not None:
            session.stop()
            worker = self._worker
            if worker is not None:
                worker.join(timeout=10)
        if self._server is not None:
            self._server.close()
            self._server = None
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass
        net.clear_state()
        logger.info("daemon stopped")
