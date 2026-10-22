"""
Slack Socket Mode: approval buttons without a public endpoint.

The HTTP route (`/api/slack/interactive`) needs Slack to reach the deployment,
which means a public URL in front of a security tool that holds containment
rights. Socket Mode turns the direction around: Kronagent opens an outbound
WebSocket to Slack with an app-level token (`xapp-…`), and Slack delivers each
button click down it. The deployment then needs no inbound port at all.

Authenticity comes from the connection itself — only Slack, holding the app's
token, can hand out the socket URL — so there is no signing secret to check on
this path. What a click may do is decided by the same handler the HTTP route
uses (`web.handle_slack_action`): operator mapping, registry permissions,
tenant scope, the kill switch and the audit trail are identical.

Protocol, per Slack's Socket Mode docs:
  1. POST apps.connections.open with the app token → a single-use wss:// URL.
  2. Slack sends {"type": "hello"}, then envelopes:
     {"envelope_id": …, "type": "interactive", "payload": {…}}.
  3. Each envelope is acknowledged with {"envelope_id": …} within 3 seconds,
     so the ack goes first and the decision (which may run containment) runs
     after it, replying through the payload's response_url.
  4. {"type": "disconnect"} means reconnect: Slack rotates sockets routinely.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio
import json
import logging
import random
import urllib.request
from typing import Any, Awaitable, Callable, Optional

from .chatops import respond

_log = logging.getLogger(__name__)

OPEN_URL = "https://slack.com/api/apps.connections.open"
MIN_BACKOFF = 1.0
MAX_BACKOFF = 60.0
STOP_POLL = 1.0       # how often an idle socket checks for shutdown

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class SocketModeError(RuntimeError):
    """Slack refused to open a socket (bad token, Socket Mode off, …)."""


def open_connection_url(app_token: str) -> str:
    """Exchange the app-level token for a single-use WebSocket URL."""
    req = urllib.request.Request(
        OPEN_URL, data=b"", method="POST",
        headers={"Authorization": f"Bearer {app_token}",
                 "Content-Type": "application/x-www-form-urlencoded"})
    # noqa justified: OPEN_URL is a hardcoded https://slack.com/api literal
    with urllib.request.urlopen(req, timeout=10) as response:  # noqa: S310
        body = json.loads(response.read().decode("utf-8"))
    if not body.get("ok") or not body.get("url"):
        raise SocketModeError(f"apps.connections.open failed: {body.get('error', 'no url')}")
    return body["url"]


def _default_connect(url: str):
    try:
        from websockets.asyncio.client import connect
    except ImportError as exc:
        raise SocketModeError('Socket Mode needs websockets: pip install "kronagent[slack]"') from exc
    return connect(url, open_timeout=10, ping_interval=20, ping_timeout=20)


class SlackSocketMode:
    """Keeps one Socket Mode connection open and feeds button clicks to
    `handler`. Runs until `stop` is set; every failure short of that is
    logged and retried with backoff, because a dropped socket must never
    take the agent loop down with it."""

    def __init__(self, app_token: str, handler: Handler, *,
                 open_url: Callable[[str], str] = open_connection_url,
                 connect: Callable[[str], Any] = _default_connect,
                 reply: Callable[[str, dict[str, Any]], bool] = respond) -> None:
        if not app_token.startswith("xapp-"):
            raise SocketModeError("KRONAGENT_SLACK_APP_TOKEN must be an app-level token (xapp-…)")
        self._token = app_token
        self._handler = handler
        self._open_url = open_url
        self._connect = connect
        self._reply = reply
        self._inflight: set[asyncio.Task] = set()
        self.connections = 0          # sockets opened; for tests and logs

    async def run(self, stop: asyncio.Event) -> None:
        backoff = MIN_BACKOFF
        while not stop.is_set():
            try:
                url = await asyncio.to_thread(self._open_url, self._token)
                async with self._connect(url) as ws:
                    self.connections += 1
                    backoff = MIN_BACKOFF
                    await self._serve(ws, stop)
            except asyncio.CancelledError:
                raise
            except SocketModeError as exc:
                _log.error("slack socket mode: %s", exc)
            except Exception as exc:  # noqa: BLE001 - reconnect on anything
                _log.warning("slack socket mode: connection lost (%s: %s)", type(exc).__name__, exc)
            if stop.is_set():
                break
            delay = backoff + random.uniform(0, backoff * 0.25)
            backoff = min(backoff * 2, MAX_BACKOFF)
            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
        if self._inflight:
            await asyncio.gather(*self._inflight, return_exceptions=True)

    async def _serve(self, ws, stop: asyncio.Event) -> None:
        """One socket's lifetime. Returns when Slack asks for a reconnect, the
        socket closes, or `stop` is set."""
        while not stop.is_set():
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=STOP_POLL)
            except asyncio.TimeoutError:
                continue
            try:
                message = json.loads(raw)
            except (TypeError, json.JSONDecodeError):
                continue
            kind = message.get("type")
            if kind == "hello":
                _log.info("slack socket mode: connected")
                continue
            if kind == "disconnect":
                _log.info("slack socket mode: reconnect requested (%s)", message.get("reason", ""))
                return
            envelope_id = message.get("envelope_id")
            if envelope_id:
                # Ack first: Slack retries an envelope it hasn't heard back on
                # within 3 seconds, and containment can take longer than that.
                await ws.send(json.dumps({"envelope_id": envelope_id}))
            payload = message.get("payload") or {}
            if kind == "interactive" and payload.get("type") == "block_actions":
                task = asyncio.create_task(self._decide(payload))
                self._inflight.add(task)
                task.add_done_callback(self._inflight.discard)

    async def _decide(self, payload: dict[str, Any]) -> None:
        try:
            result = await self._handler(payload)
        except Exception as exc:  # noqa: BLE001 - tell the clicker, keep the socket
            _log.error("slack socket mode: handling a click failed (%s: %s)", type(exc).__name__, exc)
            result = {"response_type": "ephemeral", "replace_original": False,
                      "text": "❌ Kronagent hit an error processing that click. Check the "
                              "approval queue for the request's real state, and the logs."}
        response_url: Optional[str] = payload.get("response_url")
        if response_url:
            await asyncio.to_thread(self._reply, response_url, result)
