"""
Service for sending employee invitation emails with secret pairing codes.
Supports standard SMTP with TLS/SSL and graceful offline mock fallback.
"""
import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any

logger = logging.getLogger("hopzero.email_sender")

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", os.getenv("DEFAULT_FROM_EMAIL", "soc-admin@hopzero.local"))
def get_portal_base_url() -> str:
    return (
        os.getenv("PUBLIC_URL")
        or os.getenv("PORTAL_BASE_URL")
        or "http://localhost:5173"
    ).rstrip("/")


def send_employee_invitation(
    *,
    employee_email: str,
    employee_name: Optional[str],
    secret_code: str,
    organization_name: str = "HopZero Security",
    portal_base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Sends an onboarding invitation email with the employee's secret code and portal link.
    If SMTP is not configured, logs the email content and returns simulated success.
    """
    base_url = (portal_base_url or get_portal_base_url()).rstrip("/")
    portal_link = f"{base_url}/portal?code={secret_code}"
    display_name = employee_name or employee_email.split("@")[0]

    subject = f"🔐 Your Email Threat Scanner Access Code - {organization_name}"

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; }}
        .card {{ max-width: 560px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; border: 1px solid #334155; }}
        .badge {{ display: inline-block; background: #3b82f6; color: white; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; }}
        .code-box {{ background: #0f172a; border: 2px dashed #3b82f6; border-radius: 8px; padding: 18px; text-align: center; margin: 24px 0; }}
        .code {{ font-family: monospace; font-size: 28px; font-weight: 800; letter-spacing: 4px; color: #60a5fa; }}
        .btn {{ display: inline-block; background: #2563eb; color: #ffffff !important; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; margin-top: 10px; }}
        .footer {{ font-size: 12px; color: #94a3b8; margin-top: 24px; border-top: 1px solid #334155; padding-top: 16px; }}
      </style>
    </head>
    <body>
      <div class="card">
        <span class="badge">{organization_name} SOC</span>
        <h2 style="color: #f8fafc; margin-top: 12px;">Email Threat Scanner Invitation</h2>
        <p>Hello <strong>{display_name}</strong>,</p>
        <p>Your Security Operations Center (SOC) administrator has provisioned access to the <strong>HopZero Email Threat Scanner</strong>.</p>
        <p>Whenever you receive a suspicious email, you can scan it instantly for phishing, spoofing, and malicious links with zero password setup.</p>
        
        <div class="code-box">
          <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase; margin-bottom: 6px;">Your Secret Access Code</div>
          <div class="code">{secret_code}</div>
        </div>

        <div style="text-align: center;">
          <a href="{portal_link}" class="btn" target="_blank">Open Employee Security Portal</a>
        </div>

        <p style="margin-top: 20px; font-size: 14px; color: #cbd5e1;">
          <strong>How to use:</strong><br>
          1. Click the button above or visit <a href="{base_url}/portal" style="color:#60a5fa;">{base_url}/portal</a>.<br>
          2. Enter your secret code: <code>{secret_code}</code>.<br>
          3. Upload or paste any suspicious email to receive an instant safety verdict and report it directly to your SOC team.
        </p>

        <div class="footer">
          This security link and code are uniquely assigned to <strong>{employee_email}</strong>. Do not share your code.
        </div>
      </div>
    </body>
    </html>
    """

    plain_content = f"""
Hello {display_name},

Your SOC administrator has provisioned access to the HopZero Email Threat Scanner for {organization_name}.

Your Secret Access Code: {secret_code}
Direct Portal Link: {portal_link}

Whenever you receive a suspicious email, visit the link above and paste or upload the email. You can instantly report threats to your security team.

Best regards,
{organization_name} SOC Team
    """.strip()

    if not SMTP_HOST:
        logger.info(
            "SMTP not configured (SMTP_HOST empty). Logging invitation for %s: Code=%s, Link=%s",
            employee_email,
            secret_code,
            portal_link,
        )
        return {
            "delivered": True,
            "status": "mock_logged",
            "recipient": employee_email,
            "code": secret_code,
            "portal_link": portal_link,
            "notice": "Simulated delivery (SMTP_HOST not set). Code is active and link is valid.",
        }

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = employee_email

        msg.attach(MIMEText(plain_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10.0) as server:
            server.ehlo()
            if server.has_extn("STARTTLS"):
                server.starttls()
                server.ehlo()
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        logger.info("Successfully sent invitation email to %s via %s", employee_email, SMTP_HOST)
        return {
            "delivered": True,
            "status": "sent",
            "recipient": employee_email,
            "code": secret_code,
            "portal_link": portal_link,
        }
    except Exception as exc:
        logger.error("Failed to send SMTP email to %s: %s", employee_email, exc)
        return {
            "delivered": False,
            "status": "error",
            "error": str(exc),
            "recipient": employee_email,
            "code": secret_code,
            "portal_link": portal_link,
        }
