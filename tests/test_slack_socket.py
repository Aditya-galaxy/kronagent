"""
Slack Socket Mode against a stand-in socket: acks, routing, reconnects, and
the same authorization as the HTTP route.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from kronagent import slack_socket
from kronagent.slack_socket import SlackSocketMode, SocketModeError


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(slack_socket, "STOP_POLL", 0.02)
    monkeypatch.setattr(slack_socket, "MIN_BACKOFF", 0.01)


class FakeSocket:
    """Serves scripted messages, then idles until closed by the client."""

    def __init__(self, messages: list[dict]) -> None:
        self.inbox: asyncio.Queue = asyncio.Queue()
        for m in messages:
            self.inbox.put_nowait(json.dumps(m))
        self.sent: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def recv(self) -> str:
        return await self.inbox.get()

    async def send(self, raw: str) -> None:
        self.sent.append(json.loads(raw))


def click(envelope_id: str = "env-1", action: str = "approve_action", value: str = "req-1") -> dict:
    return {"envelope_id": envelope_id, "type": "interactive",
            "payload": {"type": "block_actions", "user": {"id": "U1", "username": "alice"},
                        "actions": [{"action_id": action, "value": value}],
                        "response_url": "https://hooks.slack.com/actions/T1/1/abc"}}


def make(sockets: list[FakeSocket], handler=None, replies: list | None = None, opens: list | None = None):
    async def default_handler(payload):
        return {"replace_original": True, "text": f"handled {payload['actions'][0]['value']}"}

    queue = list(sockets)

    def open_url(token: str) -> str:
        if opens is not None:
            opens.append(token)
        return "wss://example.invalid/socket"

    def connect(url: str):
        return queue.pop(0) if queue else FakeSocket([])

    def reply(url: str, body: dict) -> bool:
        if replies is not None:
            replies.append((url, body))
        return True

    return SlackSocketMode("xapp-1-test", handler or default_handler,
                           open_url=open_url, connect=connect, reply=reply)


async def run_until(client: SlackSocketMode, done, timeout: float = 3.0) -> None:
    stop = asyncio.Event()
    task = asyncio.create_task(client.run(stop))
    deadline = asyncio.get_running_loop().time() + timeout
    while not done():
        if asyncio.get_running_loop().time() > deadline:
            stop.set()
            await task
            pytest.fail("condition never met")
        await asyncio.sleep(0.01)
    stop.set()
    await task


def test_a_bot_token_is_refused() -> None:
    with pytest.raises(SocketModeError, match="xapp-"):
        SlackSocketMode("xoxb-not-an-app-token", lambda p: None)


async def test_a_click_is_acked_then_decided_and_the_card_updated() -> None:
    sock = FakeSocket([{"type": "hello"}, click()])
    replies: list = []
    client = make([sock], replies=replies)
    await run_until(client, lambda: replies)
    assert sock.sent == [{"envelope_id": "env-1"}]
    url, body = replies[0]
    assert url == "https://hooks.slack.com/actions/T1/1/abc"
    assert body["text"] == "handled req-1"


async def test_the_ack_does_not_wait_for_a_slow_decision() -> None:
    """Slack re-delivers an envelope not acked within 3 seconds; containment
    can take longer, so the ack must go out before the decision finishes."""
    gate = asyncio.Event()

    async def slow(payload):
        await gate.wait()
        return {"text": "done"}

    sock = FakeSocket([click()])
    replies: list = []
    client = make([sock], handler=slow, replies=replies)
    stop = asyncio.Event()
    task = asyncio.create_task(client.run(stop))
    for _ in range(100):
        if sock.sent:
            break
        await asyncio.sleep(0.01)
    assert sock.sent == [{"envelope_id": "env-1"}] and not replies
    gate.set()
    stop.set()
    await task                     # waits for the in-flight decision
    assert replies and replies[0][1]["text"] == "done"


async def test_other_envelopes_are_acked_but_not_acted_on() -> None:
    calls: list = []

    async def handler(payload):
        calls.append(payload)
        return {}

    sock = FakeSocket([
        {"envelope_id": "e1", "type": "events_api", "payload": {"type": "event_callback"}},
        {"envelope_id": "e2", "type": "interactive", "payload": {"type": "view_submission"}},
        {"envelope_id": "e3", "type": "slash_commands", "payload": {"command": "/x"}},
    ])
    client = make([sock], handler=handler)
    await run_until(client, lambda: len(sock.sent) == 3)
    assert [m["envelope_id"] for m in sock.sent] == ["e1", "e2", "e3"]
    assert calls == []


async def test_a_disconnect_request_opens_a_fresh_socket() -> None:
    first = FakeSocket([{"type": "disconnect", "reason": "refresh_requested"}])
    second = FakeSocket([click(envelope_id="env-2")])
    opens: list = []
    client = make([first, second], opens=opens)
    await run_until(client, lambda: second.sent)
    assert client.connections == 2 and len(opens) == 2
    assert second.sent == [{"envelope_id": "env-2"}]


async def test_a_failed_open_is_retried() -> None:
    attempts: list = []
    sock = FakeSocket([click()])

    def flaky_open(token: str) -> str:
        attempts.append(token)
        if len(attempts) < 3:
            raise SocketModeError("apps.connections.open failed: ratelimited")
        return "wss://example.invalid/socket"

    replies: list = []
    async def handler(payload):
        return {"text": "ok"}

    client = SlackSocketMode("xapp-1-test", handler, open_url=flaky_open,
                             connect=lambda url: sock, reply=lambda u, b: replies.append(b) or True)
    await run_until(client, lambda: replies)
    assert len(attempts) == 3


async def test_a_handler_error_tells_the_clicker_and_keeps_the_socket() -> None:
    async def broken(payload):
        raise RuntimeError("store unavailable")

    sock = FakeSocket([click(envelope_id="a"), click(envelope_id="b", value="req-2")])
    replies: list = []
    client = make([sock], handler=broken, replies=replies)
    await run_until(client, lambda: len(replies) == 2)
    assert all("error" in body["text"] for _, body in replies)
    assert client.connections == 1


async def test_socket_clicks_go_through_the_routes_authorization(test_env_socket) -> None:
    """Socket Mode skips the signing secret, not the authorization: an
    operator outside the registry is refused, a mapped one approves."""
    from kronagent import web
    store, request_id = test_env_socket

    stranger = click(value=request_id)["payload"] | {"user": {"id": "U-unknown", "username": "mallory"}}
    refused = await web.handle_slack_action(stranger)
    assert "not found in operator registry" in refused["text"]
    assert store.get(request_id).status == "pending"

    approved = await web.handle_slack_action(click(value=request_id)["payload"]
                                             | {"user": {"id": "U12345", "username": "alice"}})
    assert approved["replace_original"] is True
    assert store.get(request_id).decided_by == "alice"


@pytest.fixture
def test_env_socket(tmp_path):
    from kronagent import web
    from kronagent.allowlist import AllowlistStore
    from kronagent.approvals import ApprovalRequest, ApprovalStore
    from kronagent.audit import AuditLog
    from kronagent.config import Settings
    from kronagent.identity import hash_token
    from kronagent.schemas import ActionClass

    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"alice": {"display_name": "Alice", "roles": ["admin"],
                                              "token_sha256": hash_token("s"), "active": True}}))
    settings = Settings(dry_run=True, approval_store_path=str(tmp_path / "approvals.json"),
                        allowlist_store_path=str(tmp_path / "allow.json"),
                        audit_log_path=str(tmp_path / "audit.jsonl"),
                        operator_registry_path=str(registry),
                        slack_app_token="xapp-1-test", slack_user_mapping={"U12345": "alice"})
    saved = (web.settings, web.approval_store, web.allowlist_store, web.audit_log)
    web.settings = settings
    web.approval_store = ApprovalStore(settings.approval_store_path)
    web.allowlist_store = AllowlistStore(settings.allowlist_store_path)
    web.audit_log = AuditLog(settings.audit_log_path)
    req = ApprovalRequest(finding_id="f-1", finding_type="aws:iam_abuse", severity=8.2,
                          action_class=ActionClass.DISABLE_ACCESS_KEY, target="AKIA123",
                          rationale="r", policy_reason="p", reversible=True, blast_radius="single_resource")
    web.approval_store.add(req)
    try:
        yield web.approval_store, req.request_id
    finally:
        web.settings, web.approval_store, web.allowlist_store, web.audit_log = saved
