"""
ChatOps Integration Utility for Kronagent.

Handles Slack Block Kit formatting, sending webhook or bot notifications,
updating interactive message cards, and verifying Slack signature headers.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import hmac
import hashlib
import json
import time
import urllib.parse
import urllib.request
from typing import Any, Optional

from .config import Settings
from .approvals import ApprovalRequest


SIGNATURE_MAX_AGE_SECONDS = 300   # Slack's guidance: reject requests older than five minutes


def verify_slack_signature(
    signing_secret: str,
    request_body: bytes,
    timestamp: str,
    signature: str,
    *,
    now: Optional[float] = None,
) -> bool:
    """
    Verify the HMAC-SHA256 signature of incoming Slack interactive payloads
    to prevent spoofing, and refuse a timestamp outside the five-minute window
    so a captured request can't be replayed later.
    """
    if not signing_secret or not signature or not timestamp:
        return False
    try:
        current = time.time() if now is None else now
        if abs(current - int(timestamp)) > SIGNATURE_MAX_AGE_SECONDS:
            return False
        # Slack protocol: v0:timestamp:body
        sig_basestring = b"v0:" + timestamp.encode("utf-8") + b":" + request_body
        computed = "v0=" + hmac.new(
            signing_secret.encode("utf-8"),
            sig_basestring,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(computed, signature)
    except Exception:
        return False


class ChatOpsNotifier:
    @staticmethod
    def _get_severity_emoji(sev: float) -> str:
        if sev >= 9.0:
            return "🔴 CRITICAL"
        if sev >= 7.0:
            return "🟠 HIGH"
        if sev >= 4.0:
            return "🟡 MEDIUM"
        return "🔵 LOW"

    @classmethod
    def build_slack_blocks(cls, req: ApprovalRequest, status_text: Optional[str] = None) -> list[dict[str, Any]]:
        """
        Build Slack Block Kit layout for the approval request.
        If status_text is provided, replace interactive buttons with the decision verdict.
        """
        emoji = cls._get_severity_emoji(req.severity)
        
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"🛡️ *Kronagent Incident Containment Approval Request* [ID: `{req.request_id}`]"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {emoji} ({req.severity})"},
                    {"type": "mrkdwn", "text": f"*Action Class:* `{req.action_class.value}`"},
                    {"type": "mrkdwn", "text": f"*Finding ID:* `{req.finding_id}`"},
                    {"type": "mrkdwn", "text": f"*Target:* `{req.target}`"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Rationale:* _{req.rationale}_\n*Policy Gate Reason:* {req.policy_reason}"
                }
            }
        ]

        # Add planned operations list
        if req.planned_api_calls:
            api_calls = "\n".join(f"• `{c}`" for c in req.planned_api_calls)
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Planned Operations:*\n{api_calls}"
                }
            })

        # Add buttons or decision verdict status
        if status_text:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"👉 *Verdict:* {status_text}"
                }
            })
        else:
            blocks.append({
                "type": "actions",
                "block_id": f"actions_{req.request_id}",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve ✅"},
                        "style": "primary",
                        "value": req.request_id,
                        "action_id": "approve_action"
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Reject / Deny ❌"},
                        "style": "danger",
                        "value": req.request_id,
                        "action_id": "deny_action"
                    }
                ]
            })

        return blocks

    # --- Allowlist expiry warnings -------------------------------------- #
    #
    # Deliberately NOT interactive. An approval card gets Approve/Deny buttons
    # because the decision is yes-or-no on a specific action. Renewing autonomy
    # is not: it requires a fresh, audited reason for why the class still
    # deserves it, and a one-click "renew" button is precisely how that
    # requirement would get hollowed out. So the card carries the command to
    # run, and the operator types the reason.

    @staticmethod
    def _mention(settings: Settings, owner: str) -> str:
        """`<@U123>` if the owner maps to a Slack user, else their plain id.
        settings.slack_user_mapping is slack_id -> operator_id, so invert it."""
        for slack_id, operator_id in settings.slack_user_mapping.items():
            if operator_id == owner:
                return f"<@{slack_id}>"
        return f"`{owner}`"

    @classmethod
    def build_expiry_warning_blocks(
        cls, settings: Settings, entry: Any, *, remaining: str,
    ) -> list[dict[str, Any]]:
        """Slack Block Kit for "this grant of autonomy is about to run out"."""
        fired = (f"{entry.fire_count}× (last {entry.last_fired_at})"
                 if entry.last_fired_at else "*never* — it has authorized nothing")
        return [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (f"⏳ *Kronagent autonomy expiring* — `{entry.action_class}` "
                             f"lapses in *{remaining}*"),
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Owner:* {cls._mention(settings, entry.owner)}"},
                    {"type": "mrkdwn", "text": f"*Expires:* `{entry.expires_at}`"},
                    {"type": "mrkdwn", "text": f"*Promoted by:* `{entry.promoted_by}`"},
                    {"type": "mrkdwn", "text": f"*Has fired:* {fired}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Promoted because:* _{entry.reason}_",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "*If it still applies*, renew it with a current reason:\n"
                        f"```python3 promote.py add {entry.action_class} --by <you> "
                        f"--reason \"<why it still applies>\" --expires-in 90d```\n"
                        "*If it doesn't*, do nothing — it lapses on its own and the class "
                        "goes back to requiring human approval. Silence is the safe answer here."
                    ),
                },
            },
        ]

    @classmethod
    def send_expiry_warning(cls, settings: Settings, entry: Any, *, remaining: str) -> bool:
        """Post one expiry warning. False when Slack isn't configured or the
        post fails — the caller records the attempt either way, and the entry
        lapses regardless, so a False here is a missed courtesy, not a missed
        control."""
        if not settings.slack_bot_token or not settings.slack_channel_id:
            return False

        url = "https://slack.com/api/chat.postMessage"
        payload = {
            "channel": settings.slack_channel_id,
            "text": (f"Kronagent: auto-execute allowlist entry {entry.action_class} "
                     f"expires in {remaining} (owner {entry.owner})"),
            "blocks": cls.build_expiry_warning_blocks(settings, entry, remaining=remaining),
        }
        req_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {settings.slack_bot_token}",
        }
        try:
            http_req = urllib.request.Request(url, data=req_bytes, headers=headers, method="POST")
            # noqa justified: url is a hardcoded https://slack.com/api literal
            with urllib.request.urlopen(http_req, timeout=10) as response:  # noqa: S310
                res_body = json.loads(response.read().decode("utf-8"))
                if res_body.get("ok"):
                    return True
                print(f"[-] Slack API error: {res_body.get('error')}")
        except Exception as e:
            print(f"[-] Failed to send Slack expiry warning: {e}")
        return False

    @classmethod
    def send_approval_notification(cls, settings: Settings, req: ApprovalRequest) -> Optional[str]:
        """
        Send the interactive Slack message. Returns the message timestamp (ts) if successful.
        """
        if not settings.slack_bot_token or not settings.slack_channel_id:
            return None

        url = "https://slack.com/api/chat.postMessage"
        payload = {
            "channel": settings.slack_channel_id,
            "text": f"Kronagent Approval Request for {req.action_class.value} on {req.target}",
            "blocks": cls.build_slack_blocks(req)
        }

        req_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {settings.slack_bot_token}"
        }

        try:
            http_req = urllib.request.Request(url, data=req_bytes, headers=headers, method="POST")
            # noqa justified: url is a hardcoded https://slack.com/api literal
            with urllib.request.urlopen(http_req, timeout=10) as response:  # noqa: S310
                res_body = json.loads(response.read().decode("utf-8"))
                if res_body.get("ok"):
                    return res_body.get("ts")
                else:
                    print(f"[-] Slack API error: {res_body.get('error')}")
        except Exception as e:
            print(f"[-] Failed to send Slack notification: {e}")
        return None

    @classmethod
    def update_approval_notification(
        cls,
        settings: Settings,
        ts: str,
        req: ApprovalRequest,
        status_text: str
    ) -> bool:
        """
        Update the existing Slack approval card to remove interactive buttons.
        """
        if not settings.slack_bot_token or not settings.slack_channel_id or not ts:
            return False

        url = "https://slack.com/api/chat.update"
        payload = {
            "channel": settings.slack_channel_id,
            "ts": ts,
            "text": f"Kronagent Approval Update for {req.action_class.value} on {req.target}",
            "blocks": cls.build_slack_blocks(req, status_text)
        }

        req_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {settings.slack_bot_token}"
        }

        try:
            http_req = urllib.request.Request(url, data=req_bytes, headers=headers, method="POST")
            # noqa justified: url is a hardcoded https://slack.com/api literal
            with urllib.request.urlopen(http_req, timeout=10) as response:  # noqa: S310
                res_body = json.loads(response.read().decode("utf-8"))
                return bool(res_body.get("ok"))
        except Exception as e:
            print(f"[-] Failed to update Slack notification: {e}")
        return False


def respond(response_url: str, body: dict[str, Any]) -> bool:
    """Deliver a reply to an interaction through its `response_url`.

    Slack ignores what an interactivity endpoint returns for a button click,
    and Socket Mode's acknowledgement carries nothing back to the message
    either, so this is how a click updates the card it came from. The URL comes
    from the payload, so it is held to Slack's own hook host: an interaction
    must never make Kronagent POST somewhere else.
    """
    parsed = urllib.parse.urlparse(response_url or "")
    if parsed.scheme != "https" or parsed.hostname != "hooks.slack.com":
        return False
    try:
        # noqa justified: scheme and host are checked above
        req = urllib.request.Request(  # noqa: S310
            response_url, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as response:  # noqa: S310
            return 200 <= response.status < 300
    except Exception as e:  # noqa: BLE001 - a lost reply must not fail the decision
        print(f"[-] Failed to deliver Slack reply: {e}")
        return False
