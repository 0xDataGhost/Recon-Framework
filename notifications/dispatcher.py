"""
notifications/dispatcher.py — fire-and-forget alert dispatch.

Supports Telegram and Discord webhooks. If neither is configured in
config["notifications"], dispatch() is a no-op so the scan still works.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any

from core.exceptions import NotificationError

logger = logging.getLogger(__name__)


@dataclass
class NotificationEvent:
    """A structured alert emitted by the scan pipeline."""
    event_type: str        # e.g. "SCAN_COMPLETE", "NEW_SUBDOMAIN"
    severity: str          # "INFO", "WARNING", "CRITICAL"
    target: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)


class NotificationDispatcher:
    """
    Dispatch scan events to configured notification channels.

    Reads config["notifications"] for channel configuration:
        telegram:
            bot_token: str
            chat_id:   str
        discord:
            webhook_url: str

    If no channels are configured, dispatch() is a silent no-op.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg: dict[str, Any] = config.get("notifications", {})

    # ── Public API ─────────────────────────────────────────────────────────────

    def dispatch(self, event: NotificationEvent) -> None:
        """Send *event* to all configured channels. Never raises."""
        channels_tried = 0

        tg_cfg = self._cfg.get("telegram", {})
        if tg_cfg.get("bot_token") and tg_cfg.get("chat_id"):
            channels_tried += 1
            try:
                self._send_telegram(event, tg_cfg["bot_token"], tg_cfg["chat_id"])
            except NotificationError as exc:
                logger.warning("telegram_dispatch_failed", extra=exc.to_dict())

        dc_cfg = self._cfg.get("discord", {})
        if dc_cfg.get("webhook_url"):
            channels_tried += 1
            try:
                self._send_discord(event, dc_cfg["webhook_url"])
            except NotificationError as exc:
                logger.warning("discord_dispatch_failed", extra=exc.to_dict())

        if channels_tried == 0:
            logger.debug(
                "notification_skipped",
                extra={"reason": "no channels configured", "event_type": event.event_type},
            )

    # ── Private helpers ────────────────────────────────────────────────────────

    def _send_telegram(self, event: NotificationEvent, bot_token: str, chat_id: str) -> None:
        text = f"*[{event.severity}] {event.event_type}*\nTarget: `{event.target}`\n{event.message}"
        payload = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}).encode()
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        self._post(url, payload, channel="telegram")

    def _send_discord(self, event: NotificationEvent, webhook_url: str) -> None:
        content = f"**[{event.severity}] {event.event_type}** | `{event.target}`\n{event.message}"
        payload = json.dumps({"content": content}).encode()
        self._post(webhook_url, payload, channel="discord")

    @staticmethod
    def _post(url: str, payload: bytes, channel: str) -> None:
        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "recon-framework/0.1"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
        except urllib.error.HTTPError as exc:
            raise NotificationError(
                f"HTTP {exc.code} posting to {channel}",
                context={"channel": channel, "http_status": exc.code},
            ) from exc
        except urllib.error.URLError as exc:
            raise NotificationError(
                f"Network error posting to {channel}: {exc.reason}",
                context={"channel": channel},
            ) from exc
