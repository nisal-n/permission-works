from __future__ import annotations

from datetime import datetime, timezone
from flask import current_app, session

from ..settings import list_envs_full
from ..supabase_client import supabase


_AUDIT_EXTRA_FIELDS = {"created_env", "action_type"}


def _who() -> str | None:
    return session.get("username") or session.get("email")


def _current_env() -> str:
    try:
        meta = list_envs_full() or {}
        name = (
            meta.get("active_env")
            or meta.get("default_env")
            or meta.get("active_export_env")
            or "DEV"
        )
        return str(name or "DEV").strip() or "DEV"
    except Exception:
        return "DEV"


def _normalize_action(action_type: str | None) -> str:
    s = str(action_type or "New").strip().lower()
    if s in {"update", "updated", "modify", "modified", "edit", "edited"}:
        return "Updated"
    return "New"


def _safe_insert(table_name: str, payload: dict):
    sb = supabase()
    try:
        return sb.table(table_name).insert(payload).execute()
    except Exception as ex:
        # Graceful fallback for databases that have not yet applied the new columns.
        msg = str(ex).lower()
        if any(token in msg for token in ("schema cache", "column", "does not exist", "could not find")):
            slim = {k: v for k, v in payload.items() if k not in _AUDIT_EXTRA_FIELDS}
            return sb.table(table_name).insert(slim).execute()
        raise


def _select_latest(permission_set_name: str) -> dict | None:
    sb = supabase()
    queries = [
        "id,permission_set_name,created_at,created_env,action_type",
        "id,permission_set_name,created_at",
    ]
    for sel in queries:
        try:
            resp = (
                sb.table("ifs_permission_sets")
                  .select(sel)
                  .eq("permission_set_name", permission_set_name)
                  .order("created_at", desc=True)
                  .limit(1)
                  .execute()
            )
            data = getattr(resp, "data", None) or (resp.get("data") if isinstance(resp, dict) else None)
            if isinstance(data, list) and data:
                row = data[0] or {}
                row.setdefault("created_env", None)
                row.setdefault("action_type", None)
                return row
            return None
        except Exception:
            continue
    return None


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def log_permission_set_event(
    permission_set_name: str,
    *,
    action_type: str = "New",
    created_env: str | None = None,
) -> str | None:
    """
    Best-effort insert. Returns inserted header id, or None.
    Must NOT raise (never break existing logic).
    """
    try:
        sb = supabase()
        payload = {
            "permission_set_name": permission_set_name,
            "created_by": _who(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_env": (created_env or _current_env()),
            "action_type": _normalize_action(action_type),
        }
        resp = _safe_insert("ifs_permission_sets", payload)
        data = getattr(resp, "data", None) or (resp.get("data") if isinstance(resp, dict) else None)
        if isinstance(data, list) and data and "id" in data[0]:
            return data[0]["id"]
        return None
    except Exception:
        current_app.logger.exception("Supabase audit failed: log_permission_set_event")
        return None


def log_permission_set_created(permission_set_name: str) -> str | None:
    return log_permission_set_event(permission_set_name, action_type="New")


def log_permission_set_updated(permission_set_name: str) -> str | None:
    return log_permission_set_event(permission_set_name, action_type="Updated")


def get_latest_permission_set_id(permission_set_name: str) -> str | None:
    """
    For separate requests (grant users/structures), attach to the latest header.
    Best-effort; returns None on failure.
    """
    try:
        latest = _select_latest(permission_set_name)
        if latest and latest.get("id"):
            return latest["id"]
        return None
    except Exception:
        current_app.logger.exception("Supabase audit failed: get_latest_permission_set_id")
        return None


def resolve_permission_set_audit(
    permission_set_name: str,
    *,
    default_action: str = "Updated",
    max_age_seconds: int = 900,
) -> tuple[str | None, str]:
    """
    Reuse a very recent header for follow-up operations (for example, assign users right
    after create). Otherwise create a fresh Updated header so modifications always appear
    in the logs.
    """
    try:
        latest = _select_latest(permission_set_name)
        env_name = _current_env()
        now = datetime.now(timezone.utc)
        if latest and latest.get("id"):
            latest_dt = _parse_dt(latest.get("created_at"))
            latest_env = (latest.get("created_env") or env_name or "").strip().upper()
            if latest_dt is not None:
                age = (now - latest_dt).total_seconds()
                if age <= max_age_seconds and latest_env == env_name.strip().upper():
                    return latest.get("id"), _normalize_action(latest.get("action_type") or default_action)
        new_id = log_permission_set_event(permission_set_name, action_type=default_action, created_env=env_name)
        return new_id, _normalize_action(default_action)
    except Exception:
        current_app.logger.exception("Supabase audit failed: resolve_permission_set_audit")
        return None, _normalize_action(default_action)


def log_grant(
    permission_set_id: str,
    grant_type: str,
    target: str,
    access_level: str | None = None,
    *,
    action_type: str | None = None,
    created_env: str | None = None,
) -> None:
    """
    Best-effort insert. Must NOT raise.
    """
    try:
        payload = {
            "permission_set_id": permission_set_id,
            "grant_type": grant_type,
            "target": target,
            "access_level": access_level,
            "granted_by": _who(),
            "granted_at": datetime.now(timezone.utc).isoformat(),
            "created_env": (created_env or _current_env()),
            "action_type": _normalize_action(action_type),
        }
        _safe_insert("ifs_permission_set_grants", payload)
    except Exception:
        current_app.logger.exception("Supabase audit failed: log_grant")
        return
