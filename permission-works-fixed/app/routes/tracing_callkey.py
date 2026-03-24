# routes/tracing_callkey.py (or inside tracing.py)
from flask import Blueprint, jsonify, session, abort
import secrets, time

callkey_bp = Blueprint("callkey", __name__)

# in-memory store; move to redis if you want multi-worker
CALL_KEYS = {}  # call_key -> {username, exp}

@callkey_bp.route("/api/call_key", methods=["POST"])
def issue_call_key():
    username = (session.get("user") or {}).get("username")
    if not username:
        abort(401)

    call_key = secrets.token_urlsafe(24)
    exp = int(time.time()) + 300  # 5 minutes
    CALL_KEYS[call_key] = {"username": username, "exp": exp}
    return jsonify({"username": username, "call_key": call_key, "expires_at": exp})
