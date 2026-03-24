from flask import Blueprint, render_template, jsonify, request, redirect, url_for, session, abort, current_app as app
from ..auth import login_required
from ..state import trace_log, ai_summary, is_tracing, lobby_pages, quick_reports, workflows, reports
from ..services.classifier import classify_projections_with_ai
from ..utils.parsers import (
    extract_projection_and_method,
    maybe_capture_lobby_from_url,
    maybe_capture_quick_report_from_url,
    maybe_capture_workflow_from_url,
    maybe_capture_report_from_request,
    STATUS_COMMANDS,
)
from ..settings import list_envs_full
import time, secrets, hmac, hashlib
from urllib.parse import urlparse

tracing_bp = Blueprint("tracing", __name__)

# ---- Short-lived call-key storage (swap for Redis in prod) ----
# Structure: call_key -> {"username": str, "exp": int}
CALL_KEYS = {}

def _default_base_root() -> str:
    data = list_envs_full() or {}
    envs = data.get("environments") or {}
    default_name = (data.get("default_env") or "").strip()
    base = (envs.get(default_name) or {}).get("base_root") \
        or (envs.get(default_name) or {}).get("cfg_base_root") \
        or ""
    base = (base or "").strip()
    if base.endswith("/"):
        base = base[:-1]
    return base

def revoke_keys_for_user(username: str):
    """Revoke all outstanding call keys for a given user (use in your logout route)."""
    if not username:
        return
    to_del = [k for k, v in CALL_KEYS.items() if v.get("username") == username]
    for k in to_del:
        CALL_KEYS.pop(k, None)

@tracing_bp.route("/api/call_key", methods=["POST"])
@login_required
def issue_call_key():
    """Mint a short-lived, single-use call key bound to the logged-in web user."""
    user = session.get("user") or {}
    username = (user.get("username") or user.get("email") or session.get("username") or "").strip()
    if not username:
        abort(401)  # not logged in or no username available

    call_key = secrets.token_urlsafe(24)
    exp = int(time.time()) + 60  # 60 seconds validity (short TTL)
    CALL_KEYS[call_key] = {"username": username, "exp": exp}
    return jsonify({"username": username, "call_key": call_key, "expires_at": exp})

def _validate_call_key_and_signature():
    """
    Validate:
      - X-Call-Key exists and is unexpired (multi-use within TTL)
      - X-PW-User matches the key's username (if provided)
      - If HMAC headers present, verify ts|METHOD|PATH|sha256(body)
    Returns web username if valid; abort(403) otherwise.
    """
    call_key = request.headers.get("X-Call-Key")
    devtools_user = request.headers.get("X-PW-User")
    ts_hdr = request.headers.get("X-Timestamp")
    sig_hdr = request.headers.get("X-Signature")

    if not call_key:
        app.logger.info("trace 403: missing X-Call-Key")
        abort(403)

    meta = CALL_KEYS.get(call_key)
    now = int(time.time())

    if (not meta) or (meta.get("exp", 0) < now):
        app.logger.info("trace 403: invalid/expired key")
        abort(403)

    web_user = meta.get("username", "")

    if devtools_user and devtools_user != web_user:
        app.logger.info("trace 403: user mismatch %s != %s", devtools_user, web_user)
        abort(403)

    # HMAC optional but verified if provided
    if ts_hdr and sig_hdr:
        try:
            ts = int(ts_hdr)
        except Exception:
            app.logger.info("trace 403: bad timestamp header")
            abort(403)

        if abs(now - ts) > 120:
            app.logger.info("trace 403: timestamp skew")
            abort(403)

        method = request.method.upper()
        path = request.path  # must match what the client signs ("/api/trace")
        body_bytes = request.get_data() or b""
        body_sha256 = hashlib.sha256(body_bytes).hexdigest()
        msg = f"{ts}|{method}|{path}|{body_sha256}".encode("utf-8")

        expected_sig = hmac.new(
            key=call_key.encode("utf-8"),
            msg=msg,
            digestmod=hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig.lower(), sig_hdr.lower()):
            app.logger.info("trace 403: bad signature")
            abort(403)

    return web_user

# ---------- Default environment URL guard (NEW) ----------

def _normalize_base_root(s: str | None) -> str:
    if not s:
        return ""
    s = s.strip()
    if s.endswith("/"):
        s = s[:-1]
    return s

def get_default_base_root() -> str:
    """
    Reads current default environment and returns its Base Root
    (supports both generic and cfg_* keys). Empty string if not set.
    """
    data = list_envs_full() or {}
    default_name = (data.get("default_env") or "").strip()
    envs = data.get("environments") or {}
    env = envs.get(default_name) or {}
    base = env.get("base_root") or env.get("cfg_base_root") or ""
    return _normalize_base_root(base)

def url_under_base(url: str, base_root: str) -> bool:
    """
    True if 'url' is under 'base_root' (same scheme/host and path prefix).
    Handles tenant roots like https://tenant.example.com or
    deeper roots like https://tenant.example.com/some/base.
    """
    if not url or not base_root:
        return False
    u = urlparse(url)
    b = urlparse(base_root)
    # Must match scheme and netloc (host[:port])
    if (u.scheme or "").lower() != (b.scheme or "").lower():
        return False
    if (u.netloc or "").lower() != (b.netloc or "").lower():
        return False
    # Path prefix check (base may include a subpath)
    base_path = b.path or ""
    target_path = u.path or ""
    if not base_path or base_path == "/":
        return True  # host match is enough if base path is root
    # Normalize with trailing slashes for prefix match
    if not base_path.endswith("/"):
        base_path = base_path + "/"
    if not target_path.endswith("/"):
        target_path_check = target_path + "/"
    else:
        target_path_check = target_path
    return target_path_check.startswith(base_path)

# ---------- Views ----------

@tracing_bp.route("/traces")
@login_required
def view_traces():
    """
    Start/Stop UI. If the user came from 'Update existing', we have
    session['update_role'] set by the menu flow; pass it to the template
    so it can show the 'You are going to update...' banner.
    """
    from .. import state
    return render_template(
        "traces.html",
        traces=trace_log,
        is_tracing=state.is_tracing,
        update_role=session.get("update_role"),
        default_base=_default_base_root(),            # <-- call local helper directly
        autolaunch=bool(request.args.get("autolaunch"))
    )


@tracing_bp.route("/start_trace")
@login_required
def start_trace():
    """
    Begin recording a new trace. We reset trace-related state but
    intentionally DO NOT clear session['update_role']; that flag is used
    to decide how we redirect after Stop (create vs update).
    """
    from .. import state
    state.is_tracing = True
    state.trace_log.clear()
    state.ai_summary.clear()
    state.lobby_pages.clear()
    state.quick_reports.clear()
    state.workflows.clear()
    state.reports.clear()
    return redirect(url_for("tracing.view_traces"))

@tracing_bp.route("/stop_trace")
@login_required
def stop_trace():
    from .. import state
    state.is_tracing = False
    state.ai_summary[:] = classify_projections_with_ai(state.trace_log)

    # If an update role is set, carry it to the summary. Otherwise go clean.
    update_role = (session.get("update_role") or "").strip()
    if update_role:
        return redirect(url_for("permissions.create_permission_ui", role=update_role))
    return redirect(url_for("permissions.create_permission_ui"))

@tracing_bp.route("/delete_trace", methods=["POST"])
@login_required
def delete_trace():
    index = int(request.form.get('index', -1))
    if 0 <= index < len(trace_log):
        del trace_log[index]
    return redirect(url_for("tracing.view_traces"))

@tracing_bp.route("/reset_trace", methods=["POST"])
@login_required
def reset_trace():
    from .. import state
    state.trace_log.clear()
    state.lobby_pages.clear()
    state.quick_reports.clear()
    state.workflows.clear()
    state.reports.clear()
    state.is_tracing = False
    return redirect(url_for("tracing.view_traces"))

@tracing_bp.route("/api/trace", methods=["POST"])
def receive_trace():
    from .. import state

    # Validate call key, user match, and signature (multi-use within TTL)
    web_user = _validate_call_key_and_signature()

    if not state.is_tracing:
        return jsonify({"status": "not_tracing"})

    data = request.get_json(force=True)
    url = data.get('url', '')

    # ---- NEW: Enforce default environment Base Root guard ----
    default_base = get_default_base_root()
    if default_base and not url_under_base(url, default_base):
        # Soft skip so the panel doesn't treat it as an error
        return jsonify({"status": "skipped_non_default_origin"}), 200

    # Avoid tracing the trace UI itself
    if url.endswith('/traces') or '/traces?' in url:
        return jsonify({"status": "skipped"})

    # Capture extras from UI URLs
    maybe_capture_lobby_from_url(url)
    maybe_capture_quick_report_from_url(url)
    maybe_capture_workflow_from_url(url)

    method = data.get('method', 'POST')
    headers = data.get('headers', {}) or {}
    override_method = headers.get('X-HTTP-Method') or headers.get('X-HTTP-Method-Override')
    if override_method:
        method = override_method.upper()

    body = data.get('body', '') if method == 'POST' else ''
    projection, method_name = extract_projection_and_method(url, body)

    # reports
    maybe_capture_report_from_request(url, body)

    is_status_change = bool(method_name) and (method_name in STATUS_COMMANDS)

    data['projection'] = projection
    data['methodName'] = method_name
    data['method'] = method
    data['body'] = body
    data['isStatusChange'] = is_status_change
    data['webUser'] = web_user  # who sent it (from validated key)

    state.trace_log.append(data)
    return jsonify({"status": "ok"})
