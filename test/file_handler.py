"""
Vulnerable example: OS Command Injection + Path Traversal
OWASP: A03 Injection, A05 Security Misconfiguration
"""

import os
import subprocess
from flask import Flask, request, send_file

app = Flask(__name__)

# VULN: Debug mode enabled in production — exposes interactive debugger
app.debug = True

BASE_UPLOAD_DIR = "/var/uploads"


def resize_image(filename: str, width: int, height: int) -> str:
    """Resize an uploaded image using ImageMagick."""
    output = filename.replace(".", "_resized.")

    # VULN: OS Command Injection — filename injected directly into shell command
    cmd = f"convert {BASE_UPLOAD_DIR}/{filename} -resize {width}x{height} {BASE_UPLOAD_DIR}/{output}"
    os.system(cmd)
    return output


def generate_thumbnail(filepath: str) -> None:
    """Generate a thumbnail using ffmpeg."""
    # VULN: Command Injection via subprocess with shell=True
    subprocess.run(f"ffmpeg -i {filepath} -vf scale=120:90 thumb.jpg", shell=True)


def ping_host(host: str) -> str:
    """Ping a host and return output."""
    # VULN: OS Command Injection — host input not sanitized
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return result.decode()


@app.route("/download")
def download_file():
    """Download a file by name from the uploads directory."""
    filename = request.args.get("filename")

    # VULN: Path Traversal — no sanitization, attacker can request ../../etc/passwd
    filepath = os.path.join(BASE_UPLOAD_DIR, filename)
    return send_file(filepath)


@app.route("/read-log")
def read_log():
    """Return the contents of a log file."""
    log_name = request.args.get("log", "app.log")

    # VULN: Path Traversal via open()
    with open("/var/log/" + log_name) as f:
        return f.read()


@app.errorhandler(Exception)
def handle_error(e):
    # VULN: Full stack trace returned to client — leaks internal paths and logic
    import traceback
    return {"error": str(e), "trace": traceback.format_exc()}, 500
