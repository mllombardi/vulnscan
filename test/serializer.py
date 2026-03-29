"""
Vulnerable example: Insecure Deserialization
OWASP: A08 Software and Data Integrity Failures
"""

import pickle
import yaml
import marshal
import base64
from flask import Flask, request

app = Flask(__name__)


def load_user_session(session_data: bytes) -> dict:
    """Restore a user session from serialized bytes."""
    # VULN: pickle.loads on untrusted data allows arbitrary code execution
    # Attacker can craft a payload that runs any Python code on the server
    return pickle.loads(session_data)


def save_user_session(session: dict) -> bytes:
    return pickle.dumps(session)


@app.route("/restore-session", methods=["POST"])
def restore_session():
    """Restore session from a base64-encoded cookie value."""
    raw = request.cookies.get("session_data", "")

    # VULN: Deserializing attacker-controlled cookie with pickle
    session = pickle.loads(base64.b64decode(raw))
    return {"user": session.get("username")}


def load_config(config_str: str) -> dict:
    """Load application config from a YAML string."""
    # VULN: yaml.load without Loader allows arbitrary Python object instantiation
    # Use yaml.safe_load instead
    return yaml.load(config_str)


@app.route("/import-workflow", methods=["POST"])
def import_workflow():
    """Import a workflow definition from the request body."""
    raw = request.get_data()

    # VULN: marshal.loads on untrusted data — can execute arbitrary bytecode
    workflow = marshal.loads(raw)
    return {"imported": True, "steps": len(workflow.get("steps", []))}


def load_plugin(plugin_bytes: bytes):
    """Load a compiled plugin from bytes."""
    # VULN: eval/exec on user-supplied bytecode via compile
    code = marshal.loads(plugin_bytes)
    exec(compile(code, "<plugin>", "exec"))  # VULN: exec on untrusted code
