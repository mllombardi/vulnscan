"""
Vulnerable example: Sensitive Data Exposure + Security Misconfiguration
OWASP: A02 Cryptographic Failures, A05 Security Misconfiguration
"""

import hashlib
import logging
import requests
import ssl

log = logging.getLogger(__name__)

# VULN: Hardcoded API keys and secrets — will be committed to version control
# NOTE: These are intentionally fake placeholder values for security testing demos.
STRIPE_SECRET_KEY = "sk_live_FAKE_EXAMPLE_NOT_A_REAL_KEY"
SENDGRID_API_KEY = "SG.FAKE_EXAMPLE_KEY.NOT_REAL_DO_NOT_USE"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"        # standard AWS docs example key
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # standard AWS docs example
INTERNAL_WEBHOOK_SECRET = "webhook_secret_do_not_share"


def charge_card(amount: int, card_number: str, cvv: str) -> dict:
    """Process a card payment."""
    # VULN: Logging raw card data — PCI DSS violation
    log.info("Processing charge: amount=%d card=%s cvv=%s", amount, card_number, cvv)

    response = requests.post(
        "https://api.stripe.com/v1/charges",
        auth=(STRIPE_SECRET_KEY, ""),
        data={"amount": amount, "currency": "usd"},
        # VULN: SSL verification disabled — vulnerable to MITM attacks
        verify=False,
    )
    return response.json()


def send_email(to: str, subject: str, body: str) -> bool:
    """Send an email via SendGrid."""
    # VULN: Logging email body — may contain PII/PHI
    log.debug("Sending email to=%s subject=%s body=%s", to, subject, body)

    response = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={"Authorization": f"Bearer {SENDGRID_API_KEY}"},
        json={"personalizations": [{"to": [{"email": to}]}], "subject": subject},
        # VULN: TLS verification disabled
        verify=False,
    )
    return response.status_code == 202


def hash_token(token: str) -> str:
    # VULN: SHA1 is considered weak for security-sensitive hashing
    return hashlib.sha1(token.encode()).hexdigest()


def create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    # VULN: Disabling hostname and certificate verification
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def store_password(password: str) -> str:
    # VULN: Storing password with reversible encryption (XOR) instead of a proper KDF
    key = 0x5A
    return bytes([b ^ key for b in password.encode()]).hex()
