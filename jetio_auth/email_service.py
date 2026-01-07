# ---------------------------------------------------------------------------
# Jetio Auth Plugin
# Copyright (c) 2025 Stephen Burabari Tete. All Rights Reserved.
# Licensed under the BSD 3-Clause license.
#
# LinkedIn: https://www.linkedin.com/in/tete-stephen/
# ---------------------------------------------------------------------------

"""
Transactional email service for jetio-auth (SMTP + Console).

This implementation uses **aiosmtplib** for SMTP delivery to avoid tight coupling
to higher-level mail wrappers that may have stricter Python version constraints.

Configuration
-------------
Reads from `jetio.config.settings`:

- MAIL_MODE: "console" or "smtp"
- MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM, MAIL_PORT, MAIL_SERVER
- MAIL_STARTTLS, MAIL_SSL_TLS
- MAIL_USE_CREDENTIALS
- MAIL_VALIDATE_CERTS

Templates
---------
jetio-auth ships default templates under:
    jetio_auth/templates/emails/

Developers can override by providing a `template_folder` path when constructing
the service, or by placing templates with the same names in a custom folder.

Default template names:
- activation.html
- password_reset.html

API
---
- send_activation_email(to_email, activation_link, company_name="Jetio App")
- send_password_reset_email(to_email, reset_link)
- send_custom_email(to_email, subject, template_name, context, subtype="html")

Notes
-----
- When MAIL_MODE="console", no SMTP connection is attempted; emails are printed.
- When MAIL_MODE="smtp", this sends real emails via SMTP.
"""

from __future__ import annotations

import logging
import re
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Optional

import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

from jetio.config import settings

log = logging.getLogger(__name__)


_TAG_RE = re.compile(r"<[^>]+>")


def _html_to_text(html: str) -> str:
    """Best-effort HTML -> plaintext fallback (dependency-free)."""
    text = _TAG_RE.sub("", html or "")
    text = re.sub(r"\s+\n", "\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


@dataclass(frozen=True)
class _SmtpConfig:
    server: str
    port: int
    from_email: str
    username: str
    password: str
    starttls: bool
    ssl_tls: bool
    use_credentials: bool
    validate_certs: bool


class JetioAuthEmailService:
    """
    Built-in transactional email service for jetio-auth.

    - Console mode prints emails (safe for tests/dev).
    - SMTP mode sends emails using aiosmtplib.
    """

    def __init__(self, template_folder: Optional[Path] = None):
        # Default packaged templates folder
        self.template_folder = template_folder or (Path(__file__).resolve().parent / "templates" / "emails")
        self.template_folder.mkdir(parents=True, exist_ok=True)

        self._jinja = Environment(
            loader=FileSystemLoader(str(self.template_folder)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------

    def _smtp_config(self) -> _SmtpConfig:
        return _SmtpConfig(
            server=settings.MAIL_SERVER,
            port=int(settings.MAIL_PORT),
            from_email=settings.MAIL_FROM,
            username=settings.MAIL_USERNAME,
            password=settings.MAIL_PASSWORD,
            starttls=bool(settings.MAIL_STARTTLS),
            ssl_tls=bool(settings.MAIL_SSL_TLS),
            use_credentials=bool(settings.MAIL_USE_CREDENTIALS),
            validate_certs=bool(settings.MAIL_VALIDATE_CERTS),
        )

    def _render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        tmpl = self._jinja.get_template(template_name)
        return tmpl.render(**context)

    def _print_console_email(self, to_email: str, subject: str, template: str, context: Dict[str, Any]) -> None:
        print("=" * 60)
        print("SIMULATED EMAIL (MAIL_MODE=console)")
        print(f"To: {to_email}")
        print(f"From: {settings.MAIL_FROM}")
        print(f"Subject: {subject}")
        print(f"Template: {template}")
        print("Context:")
        for k, v in context.items():
            print(f"  - {k}: {v}")
        print("=" * 60)

    async def _send_smtp_message(self, msg: EmailMessage) -> None:
        cfg = self._smtp_config()

        # TLS context
        if cfg.validate_certs:
            tls_context = ssl.create_default_context()
        else:
            tls_context = ssl._create_unverified_context()  # noqa: SLF001

        smtp = aiosmtplib.SMTP(
            hostname=cfg.server,
            port=cfg.port,
            use_tls=cfg.ssl_tls,
            tls_context=tls_context,
            timeout=30,
        )

        try:
            await smtp.connect()

            # If STARTTLS is requested (and not already using implicit TLS), upgrade connection
            if cfg.starttls and not cfg.ssl_tls:
                await smtp.starttls(tls_context=tls_context)

            if cfg.use_credentials:
                await smtp.login(cfg.username, cfg.password)

            await smtp.send_message(msg)
        finally:
            try:
                await smtp.quit()
            except Exception:
                pass

    def _build_email_message(
        self,
        *,
        to_email: str,
        subject: str,
        html_body: str,
        from_email: Optional[str] = None,
        reply_to: Optional[str] = None,
    ) -> EmailMessage:
        cfg = self._smtp_config()
        from_addr = from_email or cfg.from_email

        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to_email
        msg["Subject"] = subject
        if reply_to:
            msg["Reply-To"] = reply_to

        msg.set_content(_html_to_text(html_body) or "Please view this email in an HTML-capable client.")
        msg.add_alternative(html_body, subtype="html")
        return msg

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    async def send_activation_email(
        self,
        to_email: str,
        *,
        activation_link: str,
        company_name: str = "Jetio App",
    ) -> None:
        subject = "Activate Your Account"
        template_name = "activation.html"
        context = {"activation_link": activation_link, "company_name": company_name}

        if settings.MAIL_MODE == "console":
            self._print_console_email(to_email, subject, template_name, context)
            return

        html = self._render_template(template_name, context)
        msg = self._build_email_message(to_email=to_email, subject=subject, html_body=html)
        log.info("Sending activation email via SMTP to %s", to_email)
        await self._send_smtp_message(msg)

    async def send_password_reset_email(self, to_email: str, reset_link: str) -> None:
        subject = "Reset Your Password"
        template_name = "password_reset.html"
        context = {"reset_link": reset_link}

        if settings.MAIL_MODE == "console":
            self._print_console_email(to_email, subject, template_name, context)
            return

        html = self._render_template(template_name, context)
        msg = self._build_email_message(to_email=to_email, subject=subject, html_body=html)
        log.info("Sending password reset email via SMTP to %s", to_email)
        await self._send_smtp_message(msg)

    async def send_custom_email(
        self,
        to_email: str,
        *,
        subject: str,
        template_name: str,
        context: Dict[str, Any],
        subtype: str = "html",
    ) -> None:
        """
        Extension point: send any transactional email using the same engine.

        Parameters
        ----------
        to_email:
            Recipient email address.
        subject:
            Email subject line.
        template_name:
            Template file name within `template_folder`.
        context:
            Template context dict.
        subtype:
            Currently only "html" is supported for templates.
        """
        if subtype.lower() != "html":
            raise ValueError("Only HTML templates are supported by send_custom_email().")

        if settings.MAIL_MODE == "console":
            self._print_console_email(to_email, subject, template_name, context)
            return

        html = self._render_template(template_name, context)
        msg = self._build_email_message(to_email=to_email, subject=subject, html_body=html)
        log.info("Sending custom email via SMTP to %s (template=%s)", to_email, template_name)
        await self._send_smtp_message(msg)
