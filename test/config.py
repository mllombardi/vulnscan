"""
Vulnerable example: Security Misconfiguration + Template Injection
OWASP: A05 Security Misconfiguration, A03 Injection
"""

import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

# VULN: Debug mode enabled — activates Werkzeug's interactive debugger in production
app.config["DEBUG"] = True

# VULN: TESTING flag left on — disables security features like CSRF protection
app.config["TESTING"] = True

# VULN: Hardcoded default secret key — well-known default, trivially guessable
app.config["SECRET_KEY"] = "dev"

# VULN: Hardcoded database URI with credentials
app.config["DATABASE_URI"] = "postgresql://root:password@localhost/prod_db"

# VULN: Broad CORS — allows any origin to make credentialed requests
CORS_ALLOWED_ORIGINS = "*"


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")

    # VULN: Server-Side Template Injection — user input rendered as Jinja2 template
    # Attacker can submit: {{ config }} or {{ ''.__class__.__mro__[1].__subclasses__() }}
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


@app.route("/render")
def render():
    template = request.args.get("template", "")

    # VULN: Direct template rendering from user input — full SSTI
    return render_template_string(template)


@app.route("/env")
def show_env():
    # VULN: Exposing all environment variables — leaks secrets, config, API keys
    return dict(os.environ)


@app.route("/health")
def health():
    import platform
    import sys

    # VULN: Verbose system info exposed publicly — aids fingerprinting/attacks
    return {
        "status": "ok",
        "python": sys.version,
        "platform": platform.platform(),
        "cwd": os.getcwd(),
        "user": os.getenv("USER"),
        "path": os.getenv("PATH"),
    }
