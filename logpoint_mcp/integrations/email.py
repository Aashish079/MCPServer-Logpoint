"""SOC email notifications over SMTP.

Recipients are restricted to an allowlist: the content the LLM reads (log data,
incident text) is attacker-influenced, so it must not be able to email anyone it likes.
"""
from __future__ import annotations

import asyncio
import logging
import re
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from ..config import SMTPSettings
from ..errors import IntegrationError

audit = logging.getLogger("logpoint_mcp.audit")

_ADDRESS = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")


class EmailSender:
    def __init__(self, settings: SMTPSettings) -> None:
        self._settings = settings
        self._allowed = [entry.lower() for entry in settings.allowed_recipients]

    async def aclose(self) -> None:
        return None

    def is_allowed(self, address: str) -> bool:
        address = address.lower()
        return any(address == entry or (entry.startswith("@") and address.endswith(entry)) for entry in self._allowed)

    async def send(self, *, subject: str, body: str, to: list[str] | None = None) -> dict[str, Any]:
        recipients = [address.strip() for address in (to or self._settings.default_recipients) if address.strip()]
        if not recipients:
            raise ValueError("No recipients given and SMTP_DEFAULT_RECIPIENTS is not set.")
        invalid = [address for address in recipients if not _ADDRESS.match(address)]
        if invalid:
            raise ValueError(f"Invalid email address(es): {invalid}")
        blocked = [address for address in recipients if not self.is_allowed(address)]
        if blocked:
            raise ValueError(f"Recipient(s) {blocked} are not in SMTP_ALLOWED_RECIPIENTS.")

        message = EmailMessage()
        message["From"] = self._settings.from_address
        message["To"] = ", ".join(recipients)
        message["Subject"] = " ".join(subject.split())  # no CR/LF: prevents header injection
        message.set_content(body)

        try:
            await asyncio.to_thread(self._deliver, message)
        except (smtplib.SMTPException, OSError) as exc:
            raise IntegrationError(f"SMTP delivery failed: {type(exc).__name__}: {exc}") from None
        audit.info("Sent email %r to %s", message["Subject"], recipients)
        return {"sent": True, "recipients": recipients}

    def _deliver(self, message: EmailMessage) -> None:
        s = self._settings
        context = ssl.create_default_context()
        if s.use_ssl:
            server: smtplib.SMTP = smtplib.SMTP_SSL(s.host, s.port, timeout=s.timeout_seconds, context=context)
        else:
            server = smtplib.SMTP(s.host, s.port, timeout=s.timeout_seconds)
        with server:
            if s.starttls and not s.use_ssl:
                server.starttls(context=context)
            if s.username and s.password:
                server.login(s.username, s.password.get_secret_value())
            server.send_message(message)
