# app/auth.py
from __future__ import annotations

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from functools import wraps
from jinja2 import TemplateNotFound
from werkzeug.security import check_password_hash

# Supabase client factory (prefers service-role key if set)
from .supabase_client import supabase

auth_bp = Blueprint("auth", __name__)

# ---- roles & permissions (from DB user_type -> role mapping) ----
ROLES = ("standard", "admin", "superadmin")
ROLE_PERMISSIONS = {
    "standard": {"support", "create", "update"},
    "admin": {"support", "create", "update", "deliveries", "history", "templates"},
    "superadmin": {"*"},  # keep for future if you ever tag someone as superadmin in DB
}
ROLE_ORDER = {"standard": 0, "admin": 1, "superadmin": 2}


# -------------------- helpers for Jinja / guards --------------------
def current_role() -> str:
    r = session.get("role") or "standard"
    return r if r in ROLES else "standard"


def has_role(*roles) -> bool:
    r = current_role()
    return r == "superadmin" or r in roles


def can(permission: str) -> bool:
    r = current_role()
    perms = ROLE_PERMISSIONS.get(r, set())
    return "*" in perms or permission in perms


def role_is_at_least(min_role: str) -> bool:
    r = current_role()
    if r == "superadmin":
        return True
    if min_role not in ROLE_ORDER or r not in ROLE_ORDER:
        return False
    return ROLE_ORDER[r] >= ROLE_ORDER[min_role]


def _render_403():
    try:
        return render_template("403.html"), 403
    except TemplateNotFound:
        return "Forbidden", 403


@auth_bp.app_context_processor
def _inject_auth_helpers():
    return {
        "current_role": current_role,
        "has_role": has_role,
        "can": can,
        "role_is_at_least": role_is_at_least,
    }


# -------------------- decorators --------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "auth_required"}), 401
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def require_roles(*roles):
    def deco(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("logged_in"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "auth_required"}), 401
                return redirect(url_for("auth.login", next=request.path))
            if not has_role(*roles):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "forbidden", "need_role": roles}), 403
                return _render_403()
            return view(*args, **kwargs)

        return wrapped

    return deco


def roles_at_least(min_role: str):
    def deco(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("logged_in"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "auth_required"}), 401
                return redirect(url_for("auth.login", next=request.path))
            if not role_is_at_least(min_role):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "forbidden", "need_min_role": min_role}), 403
                return _render_403()
            return view(*args, **kwargs)

        return wrapped

    return deco


def require_permissions(*permissions):
    def deco(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("logged_in"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "auth_required"}), 401
                return redirect(url_for("auth.login", next=request.path))
            ok = any(can(p) for p in permissions)
            if not ok:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "forbidden", "need_permission": permissions}), 403
                return _render_403()
            return view(*args, **kwargs)

        return wrapped

    return deco


# -------------------- Supabase small helpers --------------------
def _password_matches(stored_hash: str | None, candidate: str) -> bool:
    """
    Check Werkzeug hash; as a dev fallback, accept plaintext match if the
    stored value doesn't look like a hash.
    """
    stored = (stored_hash or "").strip()
    if stored:
        try:
            if check_password_hash(stored, candidate):
                return True
        except Exception:
            pass
        if "$" not in stored and len(stored) < 120 and stored == candidate:
            return True
    return False


def _fetch_user_by_login(login: str):
    """
    Try username first; if not found, try email.
    Returns (row|None, error|None).
    """
    try:
        sb = supabase()
        # username
        resp = sb.table("app_users").select("*").eq("username", login).limit(1).execute()
        data = getattr(resp, "data", None) or (resp.get("data") if isinstance(resp, dict) else None)
        if isinstance(data, list) and data:
            return data[0], None
        # email
        resp = sb.table("app_users").select("*").eq("email", login).limit(1).execute()
        data = getattr(resp, "data", None) or (resp.get("data") if isinstance(resp, dict) else None)
        if isinstance(data, list) and data:
            return data[0], None
        return None, None
    except Exception as e:
        return None, str(e)


# -------------------- routes --------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    DB-only login with single-session enforcement:
      - If password OK -> atomically set is_online=true ONLY if currently false.
      - If that conditional update affects 0 rows -> someone else is logged in.
    """
    error = None

    if request.method == "POST":
        login_id = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")

        # Lookup user (username or email)
        user_row, db_err = _fetch_user_by_login(login_id)
        if db_err:
            error = "Invalid username or password"
        elif not user_row:
            error = "Invalid username or password"
        elif not _password_matches(user_row.get("password_hash"), password):
            error = "Invalid username or password"
        else:
            # Enforce single session with an atomic flip:
            # UPDATE app_users SET is_online = true WHERE id = ? AND is_online = false
            try:
                sb = supabase()
                upd = (
                    sb.table("app_users")
                    .update({"is_online": True})
                    .eq("id", user_row["id"])
                    .eq("is_online", False)
                    .execute()
                )
                updated = getattr(upd, "data", None) or (upd.get("data") if isinstance(upd, dict) else None)
                # Some client versions can return None unless "returning" is representation.
                # If updated is falsy, assume 0 rows affected.
                if not updated:
                    error = "This account is already signed in elsewhere."
                else:
                    # success: set session
                    utype = (user_row.get("user_type") or "").strip().lower()
                    role = "admin" if utype == "admin" else ("superadmin" if utype == "superadmin" else "standard")

                    session.clear()
                    session["logged_in"] = True
                    session["user_id"] = user_row.get("id")
                    session["username"] = user_row.get("username") or login_id
                    session["email"] = user_row.get("email")
                    session["name"] = user_row.get("name")
                    session["role"] = role

                    return redirect(request.args.get("next") or url_for("dashboard.dashboard_home"))
            except Exception:
                # Fall back to a conservative error (don’t leak DB details)
                error = "Login failed. Please try again."

    return render_template("login.html", error=error)


@auth_bp.route("/logout", methods=["POST", "GET"])
@login_required
def logout():
    # Best-effort: mark is_online=false for this user
    try:
        user_id = session.get("user_id")
        if user_id:
            sb = supabase()
            sb.table("app_users").update({"is_online": False}).eq("id", user_id).execute()
    except Exception:
        pass  # don't block logout UI

    # Revoke any devtools call-keys if that module exists
    try:
        from .routes.tracing import revoke_keys_for_user
        username = session.get("username") or (session.get("user") or {}).get("username")
        if username:
            revoke_keys_for_user(username)
    except Exception:
        pass

    session.clear()
    return redirect(url_for("auth.login"))


# ---------- init hook (required by your app factory) ----------
def init_auth(app):
    """
    Attach auth helpers/decorators to the Flask app so other modules
    can import them from 'app' (e.g., app.login_required).
    """
    app.login_required = login_required
    app.require_roles = require_roles
    app.require_permissions = require_permissions
    app.roles_at_least = roles_at_least
    return app
