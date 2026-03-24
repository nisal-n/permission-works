# app/routes/permissions.py

from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
)

import requests
from ..services.audit import (
    log_permission_set_created,
    log_permission_set_updated,
    get_latest_permission_set_id,
    resolve_permission_set_audit,
    log_grant,
)

from flask import current_app

from werkzeug.routing import BuildError
from ..auth import login_required
from ..state import ai_summary, lobby_pages, quick_reports, workflows, reports
from ..services.ifs import (
    get_access_token,
    fetch_permission_sets,
    fetch_users_page,
    fetch_user_groups_page,
    grant_projection,
    grant_read_only,
    grant_lobby_page,
    grant_groups,
    grant_users,
    grant_bpas,
    fetch_lobby_title_via_psh,
    fetch_lobby_title_via_lobbyconfig,
    grant_projection_command,
    get_permission_set_service_base,
    get_permission_set_url,
    get_permission_ssl_verify,
    export_roles_to_zip
)
from werkzeug.routing import BuildError
import json
import os
import zipfile
import xml.etree.ElementTree as ET
from functools import lru_cache
import time
from flask import request, redirect, url_for, render_template, flash


# Optional helper (if available). If not, command grants become no-ops.
try:
    # (role, projection, commands:list[str], client='web') -> (ok: bool, err: str|None)
    from ..services.ifs import grant_projection_commands as svc_grant_projection_commands
except Exception:  # pragma: no cover
    svc_grant_projection_commands = None

permissions_bp = Blueprint("permissions", __name__)
_virtual_cache = {}


def _finish_context_all() -> dict:
    data = session.get("permission_finish_context") or {}
    return data if isinstance(data, dict) else {}


def _finish_context_get(role: str) -> dict:
    role = (role or "").strip()
    if not role:
        return {}
    return dict(_finish_context_all().get(role) or {})


def _finish_context_put(role: str, ctx: dict) -> None:
    role = (role or "").strip()
    if not role:
        return
    all_ctx = _finish_context_all()
    all_ctx[role] = ctx
    session["permission_finish_context"] = all_ctx
    session.modified = True


def _finish_context_update(role: str, *, projections=None, lobbies=None, workflows=None, structures=None, users=None, groups=None, role_type=None) -> dict:
    ctx = _finish_context_get(role)
    ctx.setdefault("role", role)
    ctx.setdefault("projections", [])
    ctx.setdefault("lobbies", [])
    ctx.setdefault("workflows", [])
    ctx.setdefault("structures", [])
    ctx.setdefault("users", [])
    ctx.setdefault("groups", [])

    def _merge(key, values):
        if values is None:
            return
        merged = {str(v).strip() for v in (ctx.get(key) or []) if str(v).strip()}
        merged.update(str(v).strip() for v in (values or []) if str(v).strip())
        ctx[key] = sorted(merged)

    _merge("projections", projections)
    _merge("lobbies", lobbies)
    _merge("workflows", workflows)
    _merge("structures", structures)
    _merge("users", users)
    _merge("groups", groups)
    if role_type:
        ctx["role_type"] = role_type
    _finish_context_put(role, ctx)
    return ctx


def _finish_context_arm(role: str, entity: str = "users") -> dict:
    ctx = _finish_context_get(role)
    ctx.setdefault("role", role)
    ctx["entity"] = (entity or "users").strip().lower()
    ctx["started_at"] = time.time()
    _finish_context_put(role, ctx)
    return ctx


def _deliveries_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "deliveries"))


def _parse_exported_role_snapshot(role: str) -> tuple[dict | None, dict | None]:
    version_id, err = export_roles_to_zip([role], include_user_grants=True, include_group_grants=True)
    if err or not version_id:
        return None, err or {"error": "export_failed"}

    zip_path = os.path.join(_deliveries_dir(), f"{version_id}.zip")
    if not os.path.exists(zip_path):
        return None, {"error": "export_zip_missing", "details": zip_path}

    snapshot = {
        "role": role,
        "projections": set(),
        "structures": set(),
        "lobbies": set(),
        "workflows": set(),
        "users": set(),
        "groups": set(),
    }

    def _txt(root, path):
        out = set()
        for el in root.findall(path):
            val = (el.text or "").strip()
            if val:
                out.add(val)
        return out

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            xml_names = [n for n in zf.namelist() if n.lower().endswith('.xml')]
            target_name = f"{role}.xml".lower()
            chosen = None
            for name in xml_names:
                if os.path.basename(name).lower() == target_name:
                    chosen = name
                    break
            if not chosen and xml_names:
                chosen = xml_names[0]
            if not chosen:
                return None, {"error": "export_xml_missing", "details": zip_path}
            data = zf.read(chosen)
        root = ET.fromstring(data)
    except Exception as ex:
        return None, {"error": "export_parse_failed", "details": str(ex)}

    snapshot["projections"].update(_txt(root, ".//PROJECTION_GRANTS_ROW/PROJECTION"))
    snapshot["structures"].update(_txt(root, ".//ROLE_GRANT_ROW/GRANTED_ROLE"))
    snapshot["lobbies"].update(_txt(root, ".//LOBBY_PAGE_GRANTS_ROW/PO_ID"))
    snapshot["workflows"].update(_txt(root, ".//WORKFLOW_GRANT_ROW/BPA_KEY"))
    snapshot["users"].update(_txt(root, ".//USER_GRANT_ROW/IDENTITY"))

    group_paths = [
        ".//GROUP_GRANT_ROW/GROUP_IDENTITY",
        ".//GROUP_GRANT_ROW/USER_GROUP_IDENTITY",
        ".//USER_GROUP_GRANT_ROW/GROUP_IDENTITY",
        ".//USER_GROUP_GRANT_ROW/USER_GROUP_IDENTITY",
        ".//USER_GROUP_GRANT_ROW/IDENTITY",
    ]
    for gp in group_paths:
        snapshot["groups"].update(_txt(root, gp))

    for k, v in list(snapshot.items()):
        if isinstance(v, set):
            snapshot[k] = sorted(v)
    snapshot["zip_path"] = zip_path
    return snapshot, None


def _compute_finish_validation(role: str) -> tuple[dict, int]:
    ctx = _finish_context_get(role)
    snapshot, err = _parse_exported_role_snapshot(role)
    if err or snapshot is None:
        return ({
            "role": role,
            "status": "running",
            "message": "Sync is still running in IFS…",
            "details": [str((err or {}).get("details") or (err or {}).get("error") or "Validation export still warming up.")],
            "pending": {},
            "expected_total": 0,
            "validated_total": 0,
        }, 200)

    pending = {}
    expected_total = 0
    validated_total = 0
    for key in ("projections", "lobbies", "workflows", "structures", "users", "groups"):
        expected = sorted({str(v).strip() for v in (ctx.get(key) or []) if str(v).strip()})
        actual = {str(v).strip() for v in (snapshot.get(key) or []) if str(v).strip()}
        if expected:
            expected_total += len(expected)
            matched = [v for v in expected if v in actual]
            validated_total += len(matched)
            missing = [v for v in expected if v not in actual]
            if missing:
                pending[key] = missing

    started_at = float(ctx.get("started_at") or time.time())
    elapsed = max(0.0, time.time() - started_at)
    if pending and elapsed < 45:
        status = "running"
        message = "Do not close — validating permission set and waiting for sync to complete…"
    elif pending:
        status = "warning"
        message = "Overridden or delayed permissions found. Please review the pending items below."
    else:
        status = "success"
        message = "Sync completed successfully. Permission set is now validated in IFS."

    return ({
        "role": role,
        "status": status,
        "message": message,
        "pending": pending,
        "details": [],
        "expected_total": expected_total,
        "validated_total": validated_total,
        "elapsed_seconds": int(elapsed),
    }, 200)

# ----------------------- helpers -----------------------
def _psh_headers(token: str):
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json;odata.metadata=full;IEEE754Compatible=true",
        "Content-Type": "application/json;IEEE754Compatible=true",
    }

def _get_or_create_virtual(token: str, role: str, projection: str):
    """
    Ensure a ManageGrantsByCommandAssistantVirtual exists and return (objkey, etag).
    Accepts 200/201 on create. If ETag missing, re-reads the instance.
    Caches for 10 minutes.
    """
    import time, requests
    base = _psh_base().rstrip("/")
    headers = _psh_headers(token)
    now = time.time()
    k = (role, projection)
    cached = _virtual_cache.get(k)
    if cached and now - cached.get("ts", 0) < 600 and cached.get("objkey") and cached.get("etag"):
        return cached["objkey"], cached["etag"]

    # create (idempotent for our purposes)
    r = requests.post(
        f"{base}/ManageGrantsByCommandAssistantVirtuals",
        headers=headers,
        json={"Role": role, "ProjectionName": projection},
        timeout=30,
        verify=_permission_verify(),
    )
    if r.status_code not in (200, 201):  # 201 Created is normal here
        raise RuntimeError(f"Virtual create failed: HTTP {r.status_code} {r.text[:200]}")

    data = r.json() if r.content else {}
    objkey = (data or {}).get("Objkey")
    etag = (data or {}).get("@odata.etag") or r.headers.get("ETag") or r.headers.get("Etag")

    # If ETag missing, read instance to get it
    if objkey and not etag:
        r2 = requests.get(
            f"{base}/ManageGrantsByCommandAssistantVirtuals(Objkey='{objkey}')",
            headers=headers,
            timeout=30,
            verify=_permission_verify(),
        )
        if r2.status_code != 200:
            raise RuntimeError(f"Virtual GET failed: HTTP {r2.status_code} {r2.text[:200]}")
        etag = r2.headers.get("ETag") or r2.headers.get("Etag")
        if not etag:
            # try body as well
            d2 = r2.json() if r2.content else {}
            etag = (d2 or {}).get("@odata.etag")

    if not objkey or not etag:
        raise RuntimeError("Virtual created but Objkey/ETag not available")

    _virtual_cache[k] = {"objkey": objkey, "etag": etag, "ts": now}
    return objkey, etag

def _ensure_virtual(token: str, role: str, projection: str):
    """Create or reuse a ManageGrantsByCommandAssistantVirtual Objkey for (role, projection)."""
    import requests, time, urllib.parse as ul

    key = (role, projection)
    base = _psh_base()
    now = time.time()
    entry = _virtual_cache.get(key)
    if entry and now - entry[1] < 600:  # 10 min ttl
        return entry[0]

    r = requests.post(
        f"{base}/ManageGrantsByCommandAssistantVirtuals",
        headers=_psh_headers(token),
        json={"Role": role, "ProjectionName": projection},
        timeout=30,
        verify=_permission_verify(),
    )

    # Accept 200 OK or 201 Created
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Virtual create failed: HTTP {r.status_code} {r.text[:200]}")

    objkey = None
    try:
        data = r.json() if r.content else {}
        objkey = (data or {}).get("Objkey")
    except Exception:
        objkey = None

    # Fallbacks: Location header or @odata.id (Objkey appears between parentheses)
    if not objkey:
        loc = r.headers.get("Location") or ""
        if loc:
            # ex: .../ManageGrantsByCommandAssistantVirtuals(Objkey='xyz...')
            try:
                tail = loc.split("ManageGrantsByCommandAssistantVirtuals(", 1)[1]
                objkey = tail.split("Objkey='", 1)[1].split("'", 1)[0]
            except Exception:
                pass
        if not objkey and isinstance(data, dict):
            oid = data.get("@odata.id") or ""
            if oid:
                try:
                    tail = oid.split("ManageGrantsByCommandAssistantVirtuals(", 1)[1]
                    objkey = tail.split("Objkey='", 1)[1].split("'", 1)[0]
                except Exception:
                    pass

    if not objkey:
        raise RuntimeError("Virtual created but Objkey not found in response")

    _virtual_cache[key] = (objkey, now)
    return objkey



def _resolve_lobby_titles():
    unresolved = [lid for lid, meta in lobby_pages.items() if not meta.get("title")]
    if not unresolved:
        return

    token = get_access_token()
    if not token:
        return

    for lid in unresolved:
        title = (
            fetch_lobby_title_via_psh(lid, token)
            or fetch_lobby_title_via_lobbyconfig(lid, token)
        )
        if title:
            lobby_pages[lid]["title"] = title

def _build_rows_for_ui():
    rows = list(ai_summary)

    # Normalize quick_reports to a list of IDs
    try:
        if isinstance(quick_reports, dict):
            qr_ids = sorted(quick_reports.keys())
        else:
            qr_ids = sorted(quick_reports or [])
    except NameError:
        qr_ids = []

    for qr_id in qr_ids:
        rows.append({
            "projection": f"Quick report - {qr_id}",
            "access": "full",
            "qr_projection": qr_id,
        })

    for lobby_id, meta in lobby_pages.items():
        title = meta.get("title") or lobby_id
        rows.append({"projection": f"Lobby - {title}", "access": "full", "lobby_id": lobby_id})

    for key in sorted(workflows):
        rows.append({"projection": f"Workflow - {key}", "access": "full", "bpas_id": key})

    for rid, proj_name in sorted(reports.items()):
        rows.append({
            "projection": f"Report - {rid}",
            "access": "full",
            "report_id": rid,
            "report_projection": proj_name,
        })

    return rows


def _psh_base():
    """Base URL for PermissionSetHandling.svc resolved from the default IFS connection."""
    from flask import current_app
    dynamic_base = (get_permission_set_service_base() or "").rstrip("/")
    if dynamic_base:
        return dynamic_base
    return current_app.config.get(
        "PERMISSION_SET_BASE",
        "https://pyse8ne-dev1.build.ifs.cloud/main/ifsapplications/projection/v1/PermissionSetHandling.svc",
    )

def _odata_headers(token: str):
    """Headers that match the HAR/OpenAPI (important for action imports)."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json;odata.metadata=full;IEEE754Compatible=true",
        "Content-Type": "application/json;IEEE754Compatible=true",
    }

def _permission_verify() -> bool:
    return bool(get_permission_ssl_verify())

# ----------------------- UI: summary -----------------------

@permissions_bp.route("/create_permission_ui", methods=["GET"], endpoint="create_permission_ui")
@login_required
def create_permission_ui():
    """
    Renders the Create/Update Permission Set UI.
    - If ?role=<ROLE> is present, the page opens in Update mode (update_role set).
    - If ?lock=1 is present OR session['from_create_trace'] matches this role,
      the form auto-fills/locks and hides the Create button (Create-flow behavior).
    """
    from flask import request, session, render_template, url_for
    from werkzeug.routing import BuildError

    update_role = (request.args.get("role") or "").strip() or None

    # explicit query params first
    lock = (request.args.get("lock") or "").strip() == "1"
    prefill_role_type = (request.args.get("role_type") or "EndUserRole").strip()

    # ---- Session fallback for the return path from /traces ----
    # If no lock flag came back but we previously marked "from_create_trace"
    # and the role matches, lock the UI and prefill the role type.
    if not lock:
        try:
            marker = session.get("from_create_trace") or {}
            if marker and update_role and marker.get("role") == update_role:
                lock = True
                prefill_role_type = marker.get("role_type") or prefill_role_type
                # Optional: clear the marker so future visits behave normally
                # session.pop("from_create_trace", None)
        except Exception:
            pass

    # ---- Build the rows shown in the summary table (existing helpers) ----
    try:
        _resolve_lobby_titles()
    except Exception:
        pass  # non-fatal

    try:
        rows_for_ui = _build_rows_for_ui()
    except Exception:
        rows_for_ui = []

    # ---- Fetch roles (best-effort) ----
    roles = []
    try:
        token = get_access_token()
        if token:
            roles = fetch_permission_sets(token, top=200) or []
    except Exception:
        roles = []

    # ---- Build the form action (avoid BuildError if url_prefix varies) ----
    try:
        create_permission_set_url = url_for("permissions.create_permission_set")
    except BuildError:
        create_permission_set_url = f"{permissions_bp.url_prefix or ''}/create_permission_set"

    return render_template(
        "create_permission_ui.html",
        rows_for_ui=rows_for_ui,
        rows=rows_for_ui,
        roles=roles,
        update_role=update_role,                      # None => Create mode
        is_update=bool(update_role),                  # convenience for template `{% if is_update %}`
        create_permission_set_url=create_permission_set_url,
        # lock-mode context for the template JS
        lock=lock,
        prefill_role_type=prefill_role_type,
    )



# ----------------------- UI actions -----------------------

@permissions_bp.route("/delete_ai_trace", methods=["POST"], endpoint="delete_ai_trace")
@login_required
def delete_ai_trace():
    proj = request.form.get("projection")
    global ai_summary
    ai_summary[:] = [x for x in ai_summary if x.get("projection") != proj]
    return redirect(url_for("permissions.create_permission_ui"))

# ----------------------- APIs used by UI -----------------------

@permissions_bp.route("/api/ifs/permission_sets", methods=["GET"], endpoint="api_permission_sets")
@login_required
def api_permission_sets():
    q = (request.args.get("q") or "").strip()
    token = get_access_token()
    if not token:
        return jsonify({"error": "token_failed"}), 500
    roles = fetch_permission_sets(token, top=200, q=q if q else None)
    return jsonify({"roles": roles})

@permissions_bp.route("/api/ifs/action_commands", methods=["GET"], endpoint="api_action_commands")
@login_required
def api_action_commands():
    import re
    import requests
    from flask import jsonify, request

    # --- inputs ---
    projection = (request.args.get("projection") or "").strip()
    if not projection:
        return jsonify({"error": "missing_projection"}), 400

    # Basic allowlist for OData filter (avoid injection in $filter)
    if not re.fullmatch(r"[A-Za-z0-9_]+", projection):
        return jsonify({"error": "invalid_projection"}), 400

    token = get_access_token()
    if not token:
        return jsonify({"error": "token_failed"}), 500

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }

    base = _psh_base()

    # Ask for Label & Client too (so UI can show name but keep code for selection)
    # Note: we sort client,command for stable output. We also page if nextLink is present.
    url = (
        f"{base}/Reference_ActionCommand"
        f"?$select=ProjectionName,Client,Command,Label"
        f"&$filter=ProjectionName eq '{projection}'"
        f"&$orderby=Client,Command"
        f"&$top=500"
    )

    try:
        items = []
        next_url = url
        while next_url:
            r = requests.get(next_url, headers=headers, timeout=30, verify=_permission_verify())
            if r.status_code != 200:
                return jsonify({
                    "error": "ifs_action_commands_failed",
                    "status": r.status_code,
                    "details": r.text[:500],
                }), 502

            data = r.json() if r.content else {}
            batch = (data.get("value") or []) if isinstance(data, dict) else []
            items.extend(batch)
            next_url = data.get("@odata.nextLink")

        # Normalize & de-dup by command code
        by_code = {}
        for it in items:
            cmd = (it.get("Command") or it.get("COMMAND") or "").strip()
            if not cmd:
                continue
            label = (it.get("Label") or it.get("LABEL") or "").strip()
            client = (it.get("Client") or it.get("CLIENT") or "").strip()

            if cmd not in by_code:
                by_code[cmd] = {
                    "command": cmd,              # machine-usable
                    "label": label or cmd,       # human-friendly; fallback to code
                    "client": client or None,    # handy for selection strings
                    "projection": projection,
                }
            else:
                # Prefer a non-empty label if we didn't have one yet
                if not by_code[cmd]["label"] and label:
                    by_code[cmd]["label"] = label
                # Prefer a client if missing
                if not by_code[cmd]["client"] and client:
                    by_code[cmd]["client"] = client

        commands = list(by_code.values())
        # Sort by label (then code) for nice UI ordering
        commands.sort(key=lambda x: ((x.get("label") or "").lower(), x["command"].lower()))

        # Optional backwards-compat mode (?legacy=1) to return an array of strings like before
        legacy = (request.args.get("legacy") or "").strip() in ("1", "true", "yes")
        if legacy:
            # unique, sorted by command code
            codes = sorted({c["command"] for c in commands})
            return jsonify({"projection": projection, "commands": codes})

        return jsonify({
            "projection": projection,
            "commands": commands,  # [{command, label, client, projection}]
        })

    except Exception as e:
        return jsonify({"error": "exception", "details": str(e)}), 500


# ----------------------- Create / Update & Grant -----------------------

@permissions_bp.route('/create_permission_set', methods=['POST'], endpoint="create_permission_set")
@login_required
def create_permission_set():
    import json, requests
    from flask import current_app
    audit_id = None
    # --- detect AJAX + create_only flags ---
    is_ajax = (request.args.get("ajax") == "1") or ((request.headers.get("Accept") or "").startswith("application/json"))
    create_only = request.args.get("create_only") == "1"

    # --- input fields ---
    mode = (request.form.get('mode') or 'create').lower()
    input_role_name = (request.form.get('role_name') or '').strip()
    existing_role = (request.form.get('existing_role') or '').strip()

    # normalize role type
    role_type_raw = (request.form.get('role_type') or 'EndUserRole').strip().lower()
    role_type = 'FunctionalRole' if 'functional' in role_type_raw else 'EndUserRole'

    # ----------------------- Create or Update -----------------------
    if mode == 'update':
        role_name = existing_role
        if not role_name:
            return jsonify({"error": "Please choose an existing permission set (role)."}), 400
        
        audit_action = "Updated"
        # --- AUDIT: create a fresh update header so modifications appear in logs ---
        try:
            audit_id = log_permission_set_updated(role_name)
        except Exception:
            audit_id = None


        access_token = get_access_token()
        if not access_token:
            return jsonify({"error": "Failed to get access token"}), 500

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "OData-MaxVersion": "4.0",
            "OData-Version": "4.0",
        }

        # nothing else to create; proceed to grants

    else:  # create new permission set
        audit_action = "New"
        role_name = input_role_name
        if not role_name:
            return jsonify({"error": "Permission set name is required."}), 400

        access_token = get_access_token()
        if not access_token:
            return jsonify({"error": "Failed to get access token"}), 500

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "OData-MaxVersion": "4.0",
            "OData-Version": "4.0",
        }

        # ✅ Correct field: Role (not RoleName)
        payload = {
            "Role": role_name,
            "Description": "Created via classified traces",
            "FndRoleType": role_type,   # "EndUserRole" or "FunctionalRole"
            "LimitedTaskUser": False,
            "AdditionalTaskUser": "",
            "LastModified": "2019-10-01T01:01:01Z",
            "DiagramRootTop": "It is a Text",
        }

        # --- POST to create role ---
        try:
            r = requests.post(
                get_permission_set_url() or current_app.config["PERMISSION_SET_URL"],
                json=payload,
                headers=headers,
                timeout=30,
                verify=_permission_verify(),
            )
            txt = (r.text or "").strip()
            try:
                j = r.json()
            except Exception:
                j = None
        except requests.exceptions.RequestException as ex:
            current_app.logger.exception("Create role request failed")
            return jsonify({
                "error": "Failed to create permission set",
                "details": f"Upstream request error: {type(ex).__name__}: {ex}",
            }), 502

        # accept normal success / idempotent statuses
        if r.status_code in (200, 201, 204):
            pass
        elif r.status_code == 409:
            current_app.logger.info("Role already exists (409) – continuing")
        else:
            exists_markers = (
                "already exists",
                "fnd role already exists",
                "db_object_exist",
                "fnd_record_exist",
                "unique constraint",
                "duplicate",
            )
            body_lower = txt.lower()
            j_str = (str(j) if j is not None else "").lower()
            if any(m in body_lower for m in exists_markers) or any(m in j_str for m in exists_markers):
                current_app.logger.info("Role exists message detected – continuing")
            else:
                current_app.logger.warning("Create role failed: %s %s", r.status_code, txt[:500])
                return jsonify({
                    "error": "Failed to create permission set",
                    "status": r.status_code,
                    "details": (j.get("message") if isinstance(j, dict) and "message" in j else txt)[:1000],
                }), 502

        # --- AJAX create-only path ---
        if is_ajax and create_only:
            return jsonify({"ok": True, "role": role_name})
        
        # --- AUDIT: create header row (best-effort; never breaks flow) ---
        try:
            audit_id = log_permission_set_created(role_name)
        except Exception:
            audit_id = None



    audit_action = locals().get("audit_action", "New")

    # >>> EARLY EXIT for Trace UI (prevents any pre-granting) <<<
    next_dest = (request.args.get("next") or request.form.get("next") or "").lower()
    if next_dest in ("trace", "startstop", "capture"):
        return redirect(url_for(
            "dashboard.dash_permission_update_trace",
            role=role_name,
            origin="create",
            role_type=role_type
        ))

    # ================== GRANTS ==================
    # ---- Parse UI extras (minimal; doesn't affect your later command-grants parsing) ----
    try:
        _payload_raw = request.form.get("command_grants_json") or "{}"
        _payload = json.loads(_payload_raw)
    except Exception:
        _payload = {}

    try:
        deleted_raw = request.form.get("deleted_projections_json") or "[]"
        deleted_projections = set(json.loads(deleted_raw))
    except Exception:
        deleted_projections = set()

    access_by_proj = {}
    for it in (_payload.get("items") or []):
        proj = (it.get("projection") or "").strip()
        acc = (it.get("access") or "").strip()
        if proj and acc:
            access_by_proj[proj] = acc  # expected: "ReadOnly" or "FullAccess"

    def _skip(proj: str) -> bool:
        return proj in deleted_projections

    # --- core AI traces ---
    for trace in ai_summary:
        proj = trace.get('projection')
        if not proj or _skip(proj):
            continue

        acc = access_by_proj.get(proj)
        if acc == "ReadOnly":
            try:
                grant_read_only(proj, role_name, headers)
            except Exception:
                grant_projection(proj, role_name, headers, access="ReadOnly")
        else:
            grant_projection(proj, role_name, headers)
                # --- AUDIT: projection grant (best-effort) ---
        if audit_id:
            log_grant(
                audit_id,
                "projection",
                proj,
                access_level=("ReadOnly" if acc == "ReadOnly" else "FullAccess"),
                action_type=audit_action,
            )

    # --- Quick reports ---
    try:
        # Support both dict {qr_id: meta} and iterable of IDs ['QuickReport412216', ...]
        if isinstance(quick_reports, dict):
            items = list(quick_reports.keys())
        else:
            items = list(quick_reports or [])
    except NameError:
        items = []

    for qr_id in items:
        pretty = f"Quick report - {qr_id}"
        if _skip(pretty):
            continue
        # IMPORTANT: pass the raw Quick Report ID (e.g., "QuickReport412216")
        grant_projection(qr_id, role_name, headers)
        
        if audit_id:
            log_grant(audit_id, "projection", qr_id, access_level="FullAccess", action_type=audit_action)



            
    token = get_access_token()

    # --- Lobby pages ---
    for lobby_id, meta in lobby_pages.items():
        title = meta.get("title") or lobby_id
        proj = f"Lobby - {title}"
        if _skip(proj):
            continue
        # Use the dedicated API for lobby pages
        grant_lobby_page(lobby_id, role_name, token)
        
        if audit_id:
            log_grant(audit_id, "projection", f"Lobby:{lobby_id}", access_level="FullAccess", action_type=audit_action)

        
    # --- Quick reports ---
    try:
        # Support both dict {qr_id: meta} and iterable of IDs ['QuickReport412216', ...]
        if isinstance(quick_reports, dict):
            items = list(quick_reports.keys())
        else:
            items = list(quick_reports or [])
    except NameError:
        items = []

    for qr_id in items:
        pretty = f"Quick report - {qr_id}"
        if _skip(pretty):
            continue
        # IMPORTANT: pass the raw Quick Report ID (e.g., "QuickReport412216")
        grant_projection(qr_id, role_name, headers)




    # --- Workflows ---
    for key in sorted(workflows):
        if _skip(key):
            continue
        grant_bpas(key, role_name, headers)
        if audit_id:
            log_grant(audit_id, "projection", f"Workflow:{key}", access_level="FullAccess", action_type=audit_action)


    # --- Reports ---
    for rid, proj_name in reports.items():
        if _skip(proj_name):
            continue
        grant_projection(proj_name, role_name, headers)
        if audit_id:
            log_grant(audit_id, "projection", proj_name, access_level="FullAccess", action_type=audit_action)


    # --- Command grants (from modal JSON) ---
    try:
        payload = request.form.get("command_grants_json") or "{}"
        payload = json.loads(payload)
    except Exception:
        payload = {}

    svc_grant_projection_commands = None
    try:
        from ..services.ifs import grant_projection_commands as svc_grant_projection_commands
    except Exception:
        svc_grant_projection_commands = None

    items = payload.get("items") or []
    for it in items:
        proj = (it.get("projection") or "").strip()
        cmds = [c for c in (it.get("commands") or []) if c and str(c).strip()]
        if proj and (proj not in deleted_projections) and cmds and svc_grant_projection_commands:
            ok, err = svc_grant_projection_commands(role_name, proj, cmds, client=(it.get("client") or "web"))
            # optional: log if not ok

    # Keep finish-validation context in session so the final page can confirm sync in IFS.
    try:
        qr_expected = list(quick_reports.keys()) if isinstance(quick_reports, dict) else list(quick_reports or [])
    except Exception:
        qr_expected = []

    _finish_context_update(
        role_name,
        projections=sorted({str(t.get('projection') or '').strip() for t in ai_summary if str(t.get('projection') or '').strip() and str(t.get('projection') or '').strip() not in deleted_projections} | {str(qr_id).strip() for qr_id in qr_expected if str(qr_id).strip()} | {str(proj_name).strip() for proj_name in reports.values() if str(proj_name).strip()}),
        lobbies=sorted({str(lobby_id).strip() for lobby_id in lobby_pages.keys() if str(lobby_id).strip()}),
        workflows=sorted({str(key).strip() for key in workflows if str(key).strip()}),
        role_type=role_type,
    )

    # --- AJAX "Grant all" path ---
    if is_ajax and (request.args.get("noredirect") == "1" or request.args.get("no_redirect") == "1"):
        return jsonify({"ok": True, "role": role_name})

    # --- default web flow -> assign users screen ---
    return redirect(url_for('permissions.assign_users', role=role_name, entity='users'))




# ----------------------- Assign users/groups -----------------------

# ----------------------- Assign users/groups -----------------------

@permissions_bp.route('/assign_users', methods=["GET"], endpoint="assign_users")
@login_required
def assign_users():
    import requests
    from flask import current_app

    role   = (request.args.get('role') or '').strip()
    entity = (request.args.get('entity') or 'users').lower()
    if entity not in ('users', 'groups'):
        entity = 'users'

    if not role:
        return redirect(url_for('permissions.create_permission_ui'))

    token = get_access_token()
    if not token:
        return render_template(
            "error_inline.html",
            message="Failed to get token from IFS.",
            back_url=url_for('permissions.create_permission_ui')
        )

    base    = _psh_base()
    headers = _odata_headers(token)
    top     = 50  # adjust if needed

    try:
        if entity == 'groups':
            # User Groups
            url = f"{base}/UserGroups?$select=UserGroupId,Name&$orderby=Name&$top={top}"
            r = requests.get(url, headers=headers, timeout=20, verify=_permission_verify())
            if r.status_code != 200:
                return render_template(
                    "error_inline.html",
                    message=f"IFS UserGroups failed ({r.status_code}).\n{r.text[:600]}",
                    back_url=url_for('permissions.create_permission_ui'),
                )
            j = r.json() if r.content else {}
            items = j.get("value") if isinstance(j, dict) else []
            records = []
            for it in (items or []):
                gid   = (it.get("UserGroupId") or it.get("USER_GROUP_ID") or "").strip()
                name  = (it.get("Name") or it.get("NAME") or "").strip()
                if gid:
                    records.append({"id": gid, "label": name})
        else:
            # Users
            url = f"{base}/Users?$select=Identity,Description&$orderby=Identity&$top={top}"
            r = requests.get(url, headers=headers, timeout=20, verify=_permission_verify())
            if r.status_code != 200:
                # Some environments expose a singular 'User'
                url = f"{base}/User?$select=Identity,Description&$orderby=Identity&$top={top}"
                r = requests.get(url, headers=headers, timeout=20, verify=_permission_verify())

            if r.status_code != 200:
                return render_template(
                    "error_inline.html",
                    message=f"IFS Users failed ({r.status_code}).\n{r.text[:600]}",
                    back_url=url_for('permissions.create_permission_ui'),
                )

            j = r.json() if r.content else {}
            items = j.get("value") if isinstance(j, dict) else []
            records = []
            for it in (items or []):
                uid   = (it.get("Identity") or it.get("IDENTITY") or it.get("UserId") or "").strip()
                label = (it.get("Description") or it.get("DESCRIPTION") or it.get("Name") or "").strip()
                if uid:
                    records.append({"id": uid, "label": label})

        # Build the form POST url safely (works even if endpoint isn’t registered yet at render time)
        try:
            grant_post_url = url_for("permissions.assign_members")
        except BuildError:
            # Fallback path (works with or without a url_prefix on the blueprint)
            grant_post_url = f"{permissions_bp.url_prefix or ''}/assign_members"

        # Render the picker with the computed action URL
        return render_template(
            "assign_users.html",
            role=role,
            records=records,
            entity=entity,
            grant_post_url=grant_post_url,
        )

    except Exception as e:
        current_app.logger.exception("assign_users failed")
        return render_template(
            "error_inline.html",
            message=f"Exception while loading {entity}: {e}",
            back_url=url_for('permissions.create_permission_ui'),
        )


# ----------------------- Assign members (POST) -----------------------

@permissions_bp.route('/assign_members', methods=["POST"], endpoint="assign_members")
@login_required
def assign_members():
    """
    Grants the selected users or groups to the given role.
    Expects form fields:
      - role:       Permission set name
      - entity:     "users" | "groups"
      - ids[]:      One or more identities (user IDs or group IDs)
    """
    import traceback
    from app.services.ifs import grant_users, grant_groups, get_access_token

    role   = (request.form.get('role') or '').strip()
    entity = (request.form.get('entity') or 'users').lower()
    ids    = request.form.getlist('ids[]') or request.form.getlist('ids') or []

    if not role:
        return jsonify({"error": "missing_role", "details": "No role provided in form data."}), 400
    if entity not in ('users', 'groups'):
        return jsonify({"error": "bad_entity", "details": f"Unsupported entity: {entity}"}), 400
    if not ids:
        # Nothing selected: treat as success/no-op so the UX can continue
        return jsonify({"ok": True, "granted": 0})

    # Prebuild strings we might need
    grantees_str_simple = ";".join(str(i).strip() for i in ids if str(i).strip())
    grantees_str_users_encoded = ";".join(f"IDENTITY={str(i).strip()}^" for i in ids if str(i).strip())

    # --- AUDIT: attach to the latest recent header; otherwise create an Updated header ---
    audit_id, audit_action = resolve_permission_set_audit(role, default_action="Updated")

    try:
        if entity == 'users':
            # 1) Prefer the original, working signature first: helper(role, ids)
            ok = None
            try:
                ok = grant_users(role, ids)  # list-based signature (old working style)
            except TypeError:
                # Helper expects encoded + token – we'll fall back below
                ok = None

            # 2) If that didn't work (unsupported or False), fall back to caret-encoded + token
            if not ok:
                token = get_access_token()
                if not token:
                    return jsonify({"error": "token_failed", "details": "Could not fetch IFS access token."}), 500
                ok = grant_users(role, grantees_str_users_encoded, token)

        else:
            # Groups path (already working) — keep the simple "A;B;C" with token
            token = get_access_token()
            if not token:
                return jsonify({"error": "token_failed", "details": "Could not fetch IFS access token."}), 500
            ok = grant_groups(role, grantees_str_simple, token)

        if not ok:
            # Normalize to the same error shape you used before
            raise RuntimeError("IFS GrantUsers/GrantGroups returned false")

        granted_count = len(ids)
        
        # --- AUDIT: user/group grants (best-effort) ---
        if audit_id:
            gtype = "user" if entity == "users" else "group"
            for i in ids:
                s = str(i).strip()
                if s:
                    log_grant(audit_id, gtype, s, action_type=audit_action)


    except Exception as e:
        # Keep your detailed error reporting
        err_msg = str(e)
        try:
            resp = getattr(e, 'response', None)
            if resp is not None:
                body = getattr(resp, 'text', '') or ''
                err_msg = f"{err_msg} | HTTP {getattr(resp, 'status_code', '?')} - {body[:1000]}"
        except Exception:
            pass
        tb_tail = traceback.format_exc(limit=2)
        return jsonify({"error": "grant_failed", "details": f"{err_msg}\n{tb_tail}"}), 500

    return jsonify({"ok": True, "granted": int(granted_count)})


# ----------------------- Grants API used by row tabs -----------------------

def _odata_escape_value(v: str) -> str:
    """
    Double single quotes per OData and percent-encode the value so it is safe in key predicates.
    Example: Supplier Handling -> Supplier%20Handling
    """
    from urllib.parse import quote
    return quote((v or '').replace("'", "''"), safe='')

# ----------------------- Grants API used by row tabs -----------------------

@permissions_bp.route("/api/ifs/entity_action_grants", methods=["GET"], endpoint="api_entity_action_grants")
@login_required
def api_entity_action_grants():
    """
    Proxy to:
    {BASE}/PermissionSets(Role='{role}')/ProjectionGrants(Projection='{projection}',Role='{role}')/EntityActionGrants
    """
    import requests

    role = (request.args.get("role") or "").strip()
    projection = (request.args.get("projection") or "").strip()
    if not role or not projection:
        return jsonify({"error": "missing_params"}), 400

    token = get_access_token()
    if not token:
        return jsonify({"error": "token_failed"}), 500

    base = _psh_base()
    headers = _odata_headers(token)

    r_enc = _odata_escape_value(role)
    p_enc = _odata_escape_value(projection)

    url = (
        f"{base}/PermissionSets(Role='{r_enc}')"
        f"/ProjectionGrants(Projection='{p_enc}',Role='{r_enc}')"
        f"/EntityActionGrants"
    )

    try:
        resp = requests.get(url, headers=headers, timeout=30, verify=_permission_verify())
        if resp.status_code != 200:
            return jsonify({
                "error": "ifs_entity_action_grants_failed",
                "status": resp.status_code,
                "details": resp.text[:800],
            }), 502

        data = resp.json() if resp.content else {}
        # >>> minimal wrapper so FE can rely on j.ok <<<
        if isinstance(data, dict) and "value" in data:
            return jsonify({"ok": True, "value": data.get("value")})
        else:
            return jsonify({"ok": True, "value": []})
    except Exception as e:
        return jsonify({"error": "exception", "details": str(e)}), 500


@permissions_bp.route("/api/ifs/projection_action_grants", methods=["GET"], endpoint="api_projection_action_grants")
@login_required
def api_projection_action_grants():
    """
    Proxy to:
    {BASE}/PermissionSets(Role='{role}')/ProjectionGrants(Projection='{projection}',Role='{role}')/ProjectionActionGrants
    """
    import requests

    role = (request.args.get("role") or "").strip()
    projection = (request.args.get("projection") or "").strip()
    if not role or not projection:
        return jsonify({"error": "missing_params"}), 400

    token = get_access_token()
    if not token:
        return jsonify({"error": "token_failed"}), 500

    base = _psh_base()
    headers = _odata_headers(token)

    r_enc = _odata_escape_value(role)
    p_enc = _odata_escape_value(projection)

    url = (
        f"{base}/PermissionSets(Role='{r_enc}')"
        f"/ProjectionGrants(Projection='{p_enc}',Role='{r_enc}')"
        f"/ProjectionActionGrants"
    )

    try:
        resp = requests.get(url, headers=headers, timeout=30, verify=_permission_verify())
        if resp.status_code != 200:
            return jsonify({
                "error": "ifs_projection_action_grants_failed",
                "status": resp.status_code,
                "details": resp.text[:800],
            }), 502

        data = resp.json() if resp.content else {}
        # >>> minimal wrapper so FE can rely on j.ok <<<
        if isinstance(data, dict) and "value" in data:
            return jsonify({"ok": True, "value": data.get("value")})
        else:
            return jsonify({"ok": True, "value": []})
    except Exception as e:
        return jsonify({"error": "exception", "details": str(e)}), 500




# ----------------------- Endpoint aliases (safety) -----------------------

# In case decorators didn't execute due to import order, try to alias the two API endpoints.
try:
    permissions_bp.add_url_rule(
        "/api/ifs/entity_action_grants",
        endpoint="api_entity_action_grants",
        view_func=api_entity_action_grants,
        methods=["GET"],
    )
    permissions_bp.add_url_rule(
        "/api/ifs/projection_action_grants",
        endpoint="api_projection_action_grants",
        view_func=api_projection_action_grants,
        methods=["GET"],
    )
except Exception:
    pass


@permissions_bp.route('/grant_users_final', methods=['POST'], endpoint="grant_users_final")
@login_required
def grant_users_final():
    """
    Grants Users or Groups to the given role.
    Prefers calling services.ifs helpers with a list of IDs (old working style),
    but falls back to the encoded-string+token calling style if needed.
    """
    role_name   = (request.form.get('role_name') or '').strip()
    entity_type = (request.form.get('entity_type') or 'users').lower()
    go_next_val = (request.form.get('go_next') or '').strip().lower()
    go_next     = go_next_val in ('1', 'true', 'yes', 'on')

    if not role_name:
        return jsonify({"error": "missing_role"}), 400

    # 1) Collect selected IDs from the table
    ids = [i.strip() for i in request.form.getlist('selected') if i and i.strip()]

    # 2) If none were posted (e.g., no visible rows or JS-only path), try grantees_str
    grantees_str = (request.form.get('grantees_str') or '').strip()
    if not ids and grantees_str:
        # Parse something like: "IDENTITY=AA^;IDENTITY=BB^" or "GROUP_IDENTITY=G1^;…"
        parts = [p.strip() for p in grantees_str.split(';') if p.strip()]
        for p in parts:
            if p.upper().startswith('IDENTITY='):
                ids.append(p.split('=', 1)[1].rstrip('^'))
            elif p.upper().startswith('GROUP_IDENTITY='):
                ids.append(p.split('=', 1)[1].rstrip('^'))

    # 3) If still nothing to grant, just continue the wizard/finish gracefully
    if not ids:
        if go_next:
            return redirect(url_for('permissions.grant_structure', role=role_name))
        # No selections, render success-ish page (nothing to do)
        return render_template("success.html", role_name=role_name, entity_type=entity_type)

    # 4) Try the original, working signature first: helper(role, ids)
    try:
        if entity_type == 'groups':
            ok = grant_groups(role_name, ids)  # OLD/working style
        else:
            ok = grant_users(role_name, ids)   # OLD/working style
    except TypeError:
        # Helper likely expects encoded string + token. Build & retry.
        token = get_access_token()
        if not token:
            return jsonify({"error": "token_failed"}), 500
        prefix = 'GROUP_IDENTITY=' if entity_type == 'groups' else 'IDENTITY='
        grantees_str_fallback = ';'.join(f"{prefix}{i}^" for i in ids)

        try:
            if entity_type == 'groups':
                ok = grant_groups(role_name, grantees_str_fallback, token)  # NEW style
            else:
                ok = grant_users(role_name, grantees_str_fallback, token)   # NEW style
        except Exception as e:
            # Surface IFS details if available
            msg = getattr(e, 'args', ['grant_failed'])[0]
            return jsonify({"error": "grant_failed", "details": str(msg)}), 500
    except Exception as e:
        msg = getattr(e, 'args', ['grant_failed'])[0]
        return jsonify({"error": "grant_failed", "details": str(msg)}), 500

    # If your helpers return booleans, you can check ok here. Otherwise just proceed.
    if go_next:
        return redirect(url_for('permissions.grant_structure', role=role_name))

    return render_template("success.html", role_name=role_name, entity_type=entity_type)


@permissions_bp.route('/grant_success', methods=['GET'], endpoint='grant_success')
@login_required
def grant_success():
    role    = (request.args.get('role') or '').strip()
    entity  = (request.args.get('entity') or 'users').strip().lower()
    granted = int(request.args.get('granted') or 0)
    if role:
        _finish_context_arm(role, entity=entity)
    return render_template(
        'grant_success.html',
        role=role,
        entity=entity,
        granted=granted,
        dashboard_url=url_for('dashboard.dashboard_home'),
    )


@permissions_bp.route('/api/permission_set_finalize_status', methods=['GET'])
@login_required
def api_permission_set_finalize_status():
    role = (request.args.get('role') or '').strip()
    if not role:
        return jsonify({"ok": False, "error": "missing_role"}), 400
    payload, code = _compute_finish_validation(role)
    payload["ok"] = True
    return jsonify(payload), code


# ---- NEW: POST actions for EAG / PAG grant & revoke (uses IFS action endpoints) ----
@permissions_bp.route("/api/ifs/entity_action_grant", methods=["POST"])
@login_required
def api_entity_action_grant_mutate():
    """
    Body: { op: 'grant' | 'revoke', role, projection, entity, action }
    Calls:
      GET  .../EntityActionGrants(Projection='{p}',Entity='{e}',Action='{a}',Role='{r}')
      POST .../EntityActionGrants(...)/IfsApp.PermissionSetHandling.EntityActionGrant_Grant (or _Revoke)
    """
    import requests
    j = request.get_json(silent=True) or {}
    op         = (j.get("op") or "").lower()
    role       = (j.get("role") or "").strip()
    projection = (j.get("projection") or "").strip()
    entity     = (j.get("entity") or "").strip()
    action     = (j.get("action") or "").strip()

    if op not in ("grant", "revoke") or not role or not projection or not entity or not action:
        return jsonify({"error": "missing_params"}), 400

    token = get_access_token()
    if not token:
        return jsonify({"error": "token_failed"}), 500

    base = _psh_base()
    headers = _odata_headers(token)

    def esc(v: str) -> str:
        return (v or "").replace("'", "''")

    r_enc = esc(role)
    p_enc = esc(projection)
    e_enc = esc(entity)
    a_enc = esc(action)

    # 1) fetch row to get ETag
    get_url = (
        f"{base}/PermissionSets(Role='{r_enc}')"
        f"/ProjectionGrants(Projection='{p_enc}',Role='{r_enc}')"
        f"/EntityActionGrants(Projection='{p_enc}',Entity='{e_enc}',Action='{a_enc}',Role='{r_enc}')"
    )
    r0 = requests.get(get_url, headers=headers, timeout=30, verify=_permission_verify())
    if r0.status_code != 200:
        return jsonify({"error": "prefetch_failed", "status": r0.status_code, "details": r0.text[:800]}), 502
    etag = (r0.json() or {}).get("@odata.etag")

    # 2) post action
    suffix = "EntityActionGrant_Grant" if op == "grant" else "EntityActionGrant_Revoke"
    post_url = get_url + f"/IfsApp.PermissionSetHandling.{suffix}"

    act_headers = dict(headers)
    if etag:
        act_headers["If-Match"] = etag

    r1 = requests.post(post_url, headers=act_headers, json={}, timeout=30, verify=_permission_verify())
    if r1.status_code not in (200, 204):
        return jsonify({"error": "mutate_failed", "status": r1.status_code, "details": r1.text[:800]}), 502
    return jsonify({"ok": True})


@permissions_bp.route("/api/ifs/projection_action_grant", methods=["POST"])
@login_required
def api_projection_action_grant_mutate():
    """
    Body: { op: 'grant' | 'revoke', role, projection, action }
    Calls:
      GET  .../ProjectionActionGrants(Projection='{p}',Action='{a}',Role='{r}')
      POST .../ProjectionActionGrants(...)/IfsApp.PermissionSetHandling.ProjectionActionGrant_Grant (or _Revoke)
    """
    import requests
    j = request.get_json(silent=True) or {}
    op         = (j.get("op") or "").lower()
    role       = (j.get("role") or "").strip()
    projection = (j.get("projection") or "").strip()
    action     = (j.get("action") or "").strip()

    if op not in ("grant", "revoke") or not role or not projection or not action:
        return jsonify({"error": "missing_params"}), 400

    token = get_access_token()
    if not token:
        return jsonify({"error": "token_failed"}), 500

    base = _psh_base()
    headers = _odata_headers(token)

    def esc(v: str) -> str:
        return (v or "").replace("'", "''")

    r_enc = esc(role)
    p_enc = esc(projection)
    a_enc = esc(action)

    # 1) fetch row to get ETag
    get_url = (
        f"{base}/PermissionSets(Role='{r_enc}')"
        f"/ProjectionGrants(Projection='{p_enc}',Role='{r_enc}')"
        f"/ProjectionActionGrants(Projection='{p_enc}',Action='{a_enc}',Role='{r_enc}')"
    )
    r0 = requests.get(get_url, headers=headers, timeout=30, verify=_permission_verify())
    if r0.status_code != 200:
        return jsonify({"error": "prefetch_failed", "status": r0.status_code, "details": r0.text[:800]}), 502
    etag = (r0.json() or {}).get("@odata.etag")

    # 2) post action
    suffix = "ProjectionActionGrant_Grant" if op == "grant" else "ProjectionActionGrant_Revoke"
    post_url = get_url + f"/IfsApp.PermissionSetHandling.{suffix}"

    act_headers = dict(headers)
    if etag:
        act_headers["If-Match"] = etag

    r1 = requests.post(post_url, headers=act_headers, json={}, timeout=30, verify=_permission_verify())
    if r1.status_code not in (200, 204):
        return jsonify({"error": "mutate_failed", "status": r1.status_code, "details": r1.text[:800]}), 502
    return jsonify({"ok": True})


@permissions_bp.route("/api/ifs/projection_grant_readonly", methods=["POST"])
@login_required
def api_projection_grant_readonly():
    """
    Force a projection to ReadOnly for a role via:
      {BASE}/ProjectionGrants(Projection='{p}',Role='{r}')/
      IfsApp.PermissionSetHandling.ProjectionGrant_GrantReadOnly

    JSON body: { "role": "<ROLE>", "projection": "<PROJECTION>" }
    """
    import requests
    from urllib.parse import quote

    data = request.get_json(silent=True) or {}
    role = (data.get("role") or "").strip()
    projection = (data.get("projection") or "").strip()

    if not role or not projection:
        return jsonify({"ok": False, "error": "Missing role or projection"}), 400

    # Same auth flow as other endpoints
    token = get_access_token()
    if not token:
        return jsonify({"ok": False, "error": "Failed to get access token"}), 500

    base = _psh_base()
    headers = _odata_headers(token)

    # OData key predicate encoding: double quotes, then percent-encode
    def enc(v: str) -> str:
        return quote((v or "").replace("'", "''"), safe="")

    r_enc = enc(role)
    p_enc = enc(projection)

    url = (
        f"{base}/ProjectionGrants(Projection='{p_enc}',Role='{r_enc}')/"
        f"IfsApp.PermissionSetHandling.ProjectionGrant_GrantReadOnly"
    )

    try:
        resp = requests.post(url, headers=headers, json={}, timeout=30, verify=_permission_verify())
    except requests.exceptions.RequestException as ex:
        return jsonify({"ok": False, "error": f"Upstream error: {type(ex).__name__}: {ex}"}), 502

    if resp.status_code not in (200, 204):
        return jsonify({"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:600]}"}), 502


    # --- AUDIT: projection grant (best-effort) ---
    try:
        audit_id, audit_action = resolve_permission_set_audit(role, default_action="Updated")
        if audit_id:
            log_grant(audit_id, "projection", projection, access_level="ReadOnly", action_type="Updated")
    except Exception:
        pass

    return jsonify({"ok": True})


@permissions_bp.route("/api/ifs/projection_grant_full", methods=["POST"])
@login_required
def api_projection_grant_full():
    """
    Force a projection to Full Access for a role via:
      {BASE}/ProjectionGrants(Projection='{p}',Role='{r}')/
      IfsApp.PermissionSetHandling.ProjectionGrant_GrantFull

    JSON body: { "role": "<ROLE>", "projection": "<PROJECTION>" }
    """
    import requests
    from urllib.parse import quote

    data = request.get_json(silent=True) or {}
    role = (data.get("role") or "").strip()
    projection = (data.get("projection") or "").strip()

    if not role or not projection:
        return jsonify({"ok": False, "error": "Missing role or projection"}), 400

    token = get_access_token()
    if not token:
        return jsonify({"ok": False, "error": "Failed to get access token"}), 500

    base = _psh_base()
    headers = _odata_headers(token)

    def enc(v: str) -> str:
        # OData key predicate encoding: double single-quotes, then percent-encode
        return quote((v or "").replace("'", "''"), safe="")

    r_enc = enc(role)
    p_enc = enc(projection)

    url = (
        f"{base}/ProjectionGrants(Projection='{p_enc}',Role='{r_enc}')/"
        f"IfsApp.PermissionSetHandling.ProjectionGrant_GrantFull"
    )

    try:
        resp = requests.post(url, headers=headers, json={}, timeout=30, verify=_permission_verify())
    except requests.exceptions.RequestException as ex:
        return jsonify({"ok": False, "error": f"Upstream error: {type(ex).__name__}: {ex}"}), 502

    if resp.status_code not in (200, 204):
        return jsonify({"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:600]}"}), 502

    # --- AUDIT: projection grant (best-effort) ---
    try:
        audit_id = log_permission_set_updated(role)
        if audit_id:
            log_grant(audit_id, "projection", projection, access_level="FullAccess", action_type="Updated")
    except Exception:
        pass

    return jsonify({"ok": True})

# --- Grant user groups to a permission set (used by Assign Users/Groups UI) ---
@permissions_bp.route("/api/ifs/grant_user_groups", methods=["POST"])
def api_grant_user_groups():
    
    import os
    import requests
    from flask import request, jsonify, current_app, session
    """
    Accepts JSON: { "role": "OA_TEST_XXXX", "group_ids": ["AAA","BBB",...] }
    Calls IFS:
      1) POST .../PermissionSetHandling.svc/AddGroupsVirtuals   { "Role": "<role>" }
      2) POST .../PermissionSetHandling.svc/GrantGroups         { "Role": "<role>", "Grantees": "USER_GROUP_ID=A^USER_GROUP_ID=B^" }
    Returns JSON: { ok: true, granted: <count> }
    """
    # Parse input
    try:
        j = request.get_json(force=True, silent=False) or {}
    except Exception:
        return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

    role = (j.get("role") or "").strip()
    group_ids = j.get("group_ids") or []
    if not role:
        return jsonify({"ok": False, "error": "Missing 'role'"}), 400
    if not isinstance(group_ids, list):
        return jsonify({"ok": False, "error": "'group_ids' must be an array"}), 400

    # Resolve IFS base URL + token from the default Setup IFS connection
    token = get_access_token()
    base = _psh_base().rstrip("/")
    if not base or not token:
        return jsonify({"ok": False, "error": "IFS base URL or token not configured"}), 401

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # 1) Reset/seed IFS "virtual" table for group grants
    add_url = f"{base}/AddGroupsVirtuals"
    try:
        r = requests.post(add_url, headers=headers, json={"Role": role}, timeout=30, verify=_permission_verify())
        if r.status_code not in (200, 201, 204):
            # Try to surface server message if available
            try:
                msg = r.text[:500]
            except Exception:
                msg = f"HTTP {r.status_code}"
            return jsonify({"ok": False, "error": f"AddGroupsVirtuals failed: {msg}"}), 502
    except requests.RequestException as e:
        return jsonify({"ok": False, "error": f"AddGroupsVirtuals error: {e}"}), 502

    # 2) Build the caret-delimited string: USER_GROUP_ID=A^USER_GROUP_ID=B^...
    if group_ids:
        parts = [f"USER_GROUP_ID={gid}^" for gid in group_ids if gid]
        grantees = "".join(parts)
    else:
        grantees = ""  # allow empty; IFS may treat as no-ops

    grant_url = f"{base}/GrantGroups"
    payload = {"Role": role, "Grantees": grantees}

    try:
        r = requests.post(grant_url, headers=headers, json=payload, timeout=60, verify=_permission_verify())
        # Typical success is 200/201 with {} body
        if r.status_code not in (200, 201, 204):
            try:
                msg = r.text[:500]
            except Exception:
                msg = f"HTTP {r.status_code}"
            return jsonify({"ok": False, "error": f"GrantGroups failed: {msg}"}), 502
    except requests.RequestException as e:
        return jsonify({"ok": False, "error": f"GrantGroups error: {e}"}), 502

    return jsonify({"ok": True, "granted": len(group_ids)})



@permissions_bp.post("/api/ifs/command_actions")
def post_command_actions():
    """
    Preview the actions that a given command would grant for (role, projection).
    Steps (no commit):
      1) Ensure/Get ManageGrantsByCommandAssistantVirtual (Objkey + ETag)
      2) Reset selection to REVOKE (virtual state only)
      3) Derive CLIENT for the command from Reference_ActionCommand
      4) SelectCommands for just this command
      5) Read EntityActionGrantChanges (EntityName, ActionName, CurrentlyGranted, NewAccessLevel)
    Returns: { ok: bool, actions: [...] }
    """
    import requests
    from urllib.parse import quote

    data = request.get_json(force=True) or {}
    role       = (data.get("role") or "").strip()
    projection = (data.get("projection") or "").strip()
    command    = (data.get("command") or "").strip()

    if not role or not projection or not command:
        return jsonify(ok=False, error="role, projection, command are required"), 400

    token = get_access_token()
    if not token:
        return jsonify(ok=False, error="token_failed"), 500

    base = _psh_base().rstrip("/")
    H    = _psh_headers(token)

    # 1) Ensure the assistant exists; get (objkey, etag)
    try:
        objkey, etag = _get_or_create_virtual(token, role, projection)  # uses same svc+cache as other routes
    except Exception as e:
        return jsonify(ok=False, where="create_virtual", details=str(e)), 502

    entity_url = f"{base}/ManageGrantsByCommandAssistantVirtuals(Objkey='{objkey}')"

    def with_if_match(h):
        return {**h, **({"If-Match": etag} if etag else {})}

    # 2) Reset selection to REVOKE (virtual state only; do NOT apply)
    last = None
    for act in (
        "ManageGrantsByCommandAssistantVirtual_SetAllProjectionActionsToRevoke",
        "ManageGrantsByCommandAssistantVirtual_SetAllToRevoke",
        "ManageGrantsByCommandAssistantVirtual_SetAllActionsToRevoke",
    ):
        url = f"{entity_url}/IfsApp.PermissionSetHandling.{act}"
        r   = requests.post(url, json={}, headers=with_if_match(H), timeout=30, verify=_permission_verify())
        last = r
        if 200 <= r.status_code < 300:
            etag = r.headers.get("ETag") or etag
            break
    else:
        return jsonify(ok=False, where="set_all_to_revoke",
                       status=getattr(last, "status_code", None),
                       details=(getattr(last, "text", "") or "")[:800]), 502

    # 3) Derive the correct CLIENT for this command from Reference_ActionCommand (never trust UI 'client')
    q_proj = projection.replace("'", "''")
    ref_url = (f"{base}/Reference_ActionCommand"
               f"?$select=Command,Client&$filter=ProjectionName eq '{q_proj}'")
    rm = requests.get(ref_url, headers=H, timeout=30, verify=_permission_verify())
    if rm.status_code != 200:
        return jsonify(ok=False, where="read_ref_commands",
                       status=rm.status_code, details=rm.text[:800]), 502
    rows = (rm.json() or {}).get("value", []) if rm.content else []
    clients = [ (r or {}).get("Client") for r in rows if (r or {}).get("Command") == command ]
    clients = [c for c in clients if c]
    if not clients:
        return jsonify(ok=False, where="select_commands",
                       error=f"command '{command}' not found in Reference_ActionCommand"), 400
    chosen_client = "web" if "web" in clients else clients[0]

    # 4) Select just this command (no ApplyChanges)
    selection = f"CLIENT={chosen_client}^COMMAND={command}^PROJECTION_NAME={projection}^"
    sel_url   = f"{entity_url}/IfsApp.PermissionSetHandling.ManageGrantsByCommandAssistantVirtual_SelectCommands"
    rs        = requests.post(sel_url, json={"Selection": selection}, headers=with_if_match(H), timeout=30, verify=_permission_verify())
    if not (200 <= rs.status_code < 300):
        return jsonify(ok=False, where="select_commands",
                       status=rs.status_code, details=rs.text[:1200]), 502
    etag = rs.headers.get("ETag") or etag

    # 5) Read the preview list from EntityActionGrantChanges (this is the correct property)
    #    Page via @odata.nextLink just in case.
    select_cols = "EntityName,ActionName,CurrentlyGranted,NewAccessLevel"
    list_url    = f"{entity_url}/EntityActionGrantChanges?$select={select_cols}&$top=1000"
    actions     = []
    next_url    = list_url
    while next_url:
        rl = requests.get(next_url, headers=H, timeout=30, verify=_permission_verify())
        if rl.status_code != 200:
            return jsonify(ok=False, where="list_preview_actions",
                           status=rl.status_code, details=rl.text[:800]), 502
        j = rl.json() if rl.content else {}
        actions.extend(j.get("value", []))
        next_url = j.get("@odata.nextLink")

    return jsonify(ok=True, actions=actions)



# --- AI grouping helpers ---
# Build the BaselineMetadata URL for a specific client, e.g. ClientMetadata.client:PurchaseOrder
def _aurena_base() -> str:
    """
    Use the same host/env as PermissionSetHandling.svc, but point to AurenaPageDesigner.svc.
    """
    base = _psh_base().rstrip("/")
    return base.rsplit("/PermissionSetHandling.svc", 1)[0] + "/AurenaPageDesigner.svc"

# cache per client to avoid cross-client bleed
_virtual_label_cache = {"ts": 0, "client": None, "map": {}}

def _client_from_projection(projection: str) -> str:
    """
    Example: 'PurchaseOrderHandling' -> 'PurchaseOrder'
             'SalesGroupHandling'    -> 'SalesGroup'
    If it doesn't match, return the original (best effort) so we don't break flows.
    """
    import re
    s = (projection or "").strip()
    m = re.match(r"^([A-Za-z0-9_]+?)Handling", s)
    return m.group(1) if m else s

def _baseline_url_for_client(client_name: str) -> str:
    # OData key contains ':' which must be %3A; percent-encode the whole value.
    from urllib.parse import quote
    model = quote(f"ClientMetadata.client:{client_name}", safe="")
    base  = _aurena_base().rstrip("/")
    return f"{base}/GetBaselineMetadata(ModelId='{model}',ScopeId='global',ExcludeProjection=true)"

def _clean_label(lbl: str) -> str:
    """
    Extract a human-readable label from:
      1) IFS translation tokens: [#[translatesys:...:WEB:Text]#] -> 'Text'
      2) Bindings/expressions: ${DisplayTitle}, ${parent.TaxLinesLabel} -> 'Display Title', 'Tax Lines'
    """
    if not isinstance(lbl, str):
        return ""

    import re

    # 1) IFS translation token -> text after :WEB:
    m = re.search(r":WEB:([^]]+)\]#\]", lbl)
    if m:
        return m.group(1).strip()

    # 2) Binding expressions like ${...}
    if lbl.startswith("${") and lbl.endswith("}"):
        token = lbl[2:-1].strip()                 # e.g. "parent.TaxLinesLabel"
        token = token.split(".")[-1]              # take the last segment
        if token.endswith("Label"):
            token = token[:-5]                    # remove trailing 'Label'

        # split Camel/PascalCase into words
        words = re.sub(r"(?<!^)(?=[A-Z])", " ", token).strip()
        # compress multiple spaces and title-case
        words = re.sub(r"\s+", " ", words).strip().title()
        return words

    # 3) Fallback for other wrapped formats
    if lbl.startswith("[#[") and lbl.endswith("]#]"):
        parts = lbl.split(":")
        return parts[-1].replace("]#]", "").strip() if parts else lbl.strip()

    return lbl.strip()



def _get_virtual_friendly_map(token: str, projection: str | None = None):
    import time, requests, json
    now = time.time()
    client = _client_from_projection(projection or "")
    # NEW: Do NOT fall back to a default. If we can't derive a client, error out.
    if not client:
        raise ValueError("unable_to_identify_client")  # caller will return a 4xx with a clear message
    if (
        now - _virtual_label_cache["ts"] < 1800
        and _virtual_label_cache["map"]
        and _virtual_label_cache.get("client") == client
    ):
        return _virtual_label_cache["map"]

    mapping = {}
    try:
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        url = _baseline_url_for_client(client)  # safe default
        r = requests.get(url, headers=headers, timeout=30, verify=_permission_verify())
        r.raise_for_status()
        outer = r.json() or {}
        payload = outer.get("value")
        data = json.loads(payload) if isinstance(payload, str) else (payload or {})
    except Exception as e:
        # If the error is due to missing/undetermined client, bubble it up so the route can show a proper message.
        if isinstance(e, ValueError):
            raise
        # Otherwise: cache an empty map to avoid hammering the API on transient failures.
        _virtual_label_cache.update({"ts": now, "client": client, "map": mapping})
        return mapping

    # walk the decoded JSON and fill mapping
    def walk(x):
        if isinstance(x, dict):
            name   = str(x.get("name")   or x.get("Name")   or "")
            label  = str(x.get("label")  or x.get("Label")  or "")
            entity = str(x.get("entity") or x.get("Entity") or "")

            is_assistant = name.endswith("Assistant")
            is_virtual_name = name.endswith("Virtual")
            is_virtual_entity = entity.endswith("Virtual")

            # Case 1: node references a *Virtual entity and carries a label
            if is_virtual_entity and label:
                title = _clean_label(label)
                if is_assistant:
                    title = f"{title}"
                mapping.setdefault(entity, title)

            # Case 2: node's own name ends with Virtual and carries a label
            if is_virtual_name and label:
                title = _clean_label(label)
                # don't add "+ Assistant" here unless the node itself is an Assistant (rare)
                if is_assistant:
                    title = f"{title}"
                mapping.setdefault(name, title)

            # Recurse
            for v in x.values():
                walk(v)

        elif isinstance(x, list):
            for v in x:
                walk(v)


    walk(data)
    _virtual_label_cache.update({"ts": now, "client": client, "map": mapping})
    return mapping

_STATUS_WORDS = {
    "Approve","ApproveReleased","Cancel","Close","Confirm","Freeze","Release","ReleaseUnapproved",
    "Reopen","Reset","Scrap","UndoScrap","Unreceive","Receive","Arrive","HeaderConfirm",
    "CentralizeWithDemandSite","CentralizeWithPurchasingSite","CreateChangeOrders",
    "FetchAuthorizationRule","FetchExternalTax","ValidateApprovalRule",
}

def _friendly_entity_name(entity: str, virt_map: dict) -> str:
    if not entity:
        return entity
    return virt_map.get(entity, entity)

def _friendly_title(entity: str, virt_map: dict) -> str:
    disp = _friendly_entity_name(entity, virt_map)
    if disp == entity and isinstance(entity, str) and entity.endswith("Virtual"):
        return entity[:-7]
    return disp

import re

def _merge_header_line_groups(groups: dict) -> dict:
    """
    Merge pairs like CPOHeaderVirtual + CPOLineVirtual into one group.
    Prefer the header group's friendly/title. Keep all actions.
    """
    merged = {}
    singletons = {}

    for g in groups.values():
        ent = g["entity"]
        m = re.match(r"^(.*?)(Header|Line)Virtual$", ent)
        if not m:
            singletons[ent] = g
            continue

        base, kind = m.group(1), m.group(2).lower()
        key = f"{base}__merged"
        if key not in merged:
            merged[key] = {
                "entity": ent,          # will be replaced with combined list
                "friendly": g["friendly"],
                "title": g["title"],
                "status_changes": [],
                "cleanup": [],
                "crud": [],
                "other": [],
                "_entities": set(),
            }

        mg = merged[key]

        # Prefer header's title/friendly if present
        if kind == "header":
            mg["friendly"] = g["friendly"]
            mg["title"] = g["title"]

        # Append all items (they already carry per-item 'entity')
        for bucket in ("status_changes", "cleanup", "crud", "other"):
            mg[bucket].extend(g[bucket])

        mg["_entities"].add(ent)

    # finalize: combine entity names and remove helper field
    out = {}
    for key, mg in merged.items():
        ents_sorted = sorted(mg["_entities"])
        mg["entity"] = ",".join(ents_sorted)  # visible in muted parentheses
        del mg["_entities"]
        out[key] = mg

    # keep non-merged groups
    out.update(singletons)
    return out



import re

@permissions_bp.route("/api/ifs/entity_action_grants_grouped", methods=["GET"])
@login_required
def api_entity_action_grants_grouped():
    """
    Returns grouped grants with:
      - title (friendly display name; maps '*Virtual' via BaselineMetadata)
      - friendly (resolved name)
      - buckets: status_changes, cleanup, crud, other
      - merged header/line groups (e.g. CPOHeaderVirtual + CPOLineVirtual)
    """
    import requests

    role = (request.args.get("role") or "").strip()
    projection = (request.args.get("projection") or "").strip()
    if not role or not projection:
        return jsonify({"error": "missing_params"}), 400

    token = get_access_token()
    if not token:
        return jsonify({"error": "token_failed"}), 500

    base = _psh_base()
    headers = _odata_headers(token)

    r_enc = _odata_escape_value(role)
    p_enc = _odata_escape_value(projection)
    url = (
        f"{base}/PermissionSets(Role='{r_enc}')"
        f"/ProjectionGrants(Projection='{p_enc}',Role='{r_enc}')"
        f"/EntityActionGrants?$top=1000"
    )

    r = requests.get(url, headers=headers, timeout=30, verify=_permission_verify())
    if r.status_code != 200:
        return jsonify({
            "error": "ifs_entity_action_grants_failed",
            "status": r.status_code,
            "details": r.text[:800]
        }), 502

    raw = (r.json() or {}).get("value") or []
    # pass the projection so the baseline client is derived (…Handling → client)
    try:
        virt_map = _get_virtual_friendly_map(token, projection)
    except ValueError:
        return jsonify({
            "ok": False,
            "error": "unable_to_identify_client",
            "details": f"Projection '{projection}' does not match '<ClientName>Handling'."
        }), 400

    by_entity = {}

    for row in raw:
        entity  = (row.get("Entity") or row.get("ENTITY") or row.get("EntityName") or "").strip()
        action  = (row.get("Action") or row.get("ACTION") or row.get("ActionName") or "").strip()
        # Consider new and old shapes from IFS
        granted = bool(
            row.get("CurrentlyGranted")
            or row.get("Granted")
            or row.get("Grant")
            or row.get("IsGranted")
        )



        g = by_entity.setdefault(entity, {
            "entity": entity,
            "friendly": _friendly_entity_name(entity, virt_map),
            "title": _friendly_title(entity, virt_map),
            "status_changes": [],
            "cleanup": [],
            "crud": [],
            "other": [],
        })

        # include entity in each item (important for merged rows)
        item = {"entity": entity, "action": action, "granted": granted}

        if action == "CleanupVirtualEntity":
            g["cleanup"].append(item)
        elif action in {"Create", "Update", "Delete"}:
            g["crud"].append(item)
        elif action in _STATUS_WORDS:
            g["status_changes"].append(item)
        else:
            g["other"].append(item)

    # --- Merge header/line virtuals ---
    def _merge_header_line_groups(groups: dict) -> dict:
        """
        Merge pairs like CPOHeaderVirtual + CPOLineVirtual into one group.
        Prefer header's friendly/title and include all actions.
        """
        merged = {}
        singletons = {}

        for g in groups.values():
            ent = g["entity"]
            m = re.match(r"^(.*?)(Header|Line)Virtual$", ent)
            if not m:
                singletons[ent] = g
                continue

            base, kind = m.group(1), m.group(2).lower()
            key = f"{base}__merged"

            if key not in merged:
                merged[key] = {
                    "entity": ent,
                    "friendly": g["friendly"],
                    "title": g["title"],
                    "status_changes": [],
                    "cleanup": [],
                    "crud": [],
                    "other": [],
                    "_entities": set(),
                }

            mg = merged[key]

            # Prefer header title/friendly if present
            if kind == "header":
                mg["friendly"] = g["friendly"]
                mg["title"] = g["title"]

            # Merge all buckets
            for bucket in ("status_changes", "cleanup", "crud", "other"):
                mg[bucket].extend(g[bucket])

            mg["_entities"].add(ent)

        # Finalize merged + non-merged
        out = {}
        for key, mg in merged.items():
            ents_sorted = sorted(mg["_entities"])
            mg["entity"] = ",".join(ents_sorted)
            del mg["_entities"]
            out[key] = mg

        out.update(singletons)
        return out

    by_entity = _merge_header_line_groups(by_entity)

    # --- Sort and return ---
    out = list(by_entity.values())
    out.sort(key=lambda x: (x.get("title") or x.get("friendly") or x.get("entity") or "").lower())

    return jsonify({"ok": True, "groups": out})


# -------- NEW: Assistants tab API --------

@permissions_bp.route("/api/ifs/assistants_grouped", methods=["GET"])
@login_required
def api_assistants_grouped():
    """
    Returns owner -> assistants (virtuals) so the UI can show:
      PurchaseOrder
        Assistants:
          - CPOHeaderVirtual
          - CPOLineVirtual
    We derive this purely from grouped EAG output, matching by friendly title.
    """
    import requests

    role = (request.args.get("role") or "").strip()
    projection = (request.args.get("projection") or "").strip()
    if not role or not projection:
        return jsonify({"ok": False, "error": "missing_params"}), 400

    # 1) Get the same grouped data the EAG panel uses
    #    (same logic as api_entity_action_grants_grouped)
    token = get_access_token()
    if not token:
        return jsonify({"ok": False, "error": "token_failed"}), 500

    base    = _psh_base()
    headers = _odata_headers(token)
    r_enc   = _odata_escape_value(role)
    p_enc   = _odata_escape_value(projection)

    url = (
        f"{base}/PermissionSets(Role='{r_enc}')"
        f"/ProjectionGrants(Projection='{p_enc}',Role='{r_enc}')"
        f"/EntityActionGrants?$top=1000"
    )
    r = requests.get(url, headers=headers, timeout=30, verify=_permission_verify())
    if r.status_code != 200:
        return jsonify({"ok": False, "error": "ifs_entity_action_grants_failed", "status": r.status_code, "details": r.text[:600]}), 502

    rows = (r.json() or {}).get("value") or []
    # Build groups exactly like api_entity_action_grants_grouped does
    try:
        virt_map = _get_virtual_friendly_map(token, projection)
    except ValueError:
        return jsonify({
            "ok": False,
            "error": "unable_to_identify_client",
            "details": f"Projection '{projection}' does not match '<ClientName>Handling'."
        }), 400

    by_entity = {}
    for row in rows:
        entity  = (row.get("Entity") or row.get("ENTITY") or row.get("EntityName") or "").strip()
        action  = (row.get("Action") or row.get("ACTION") or row.get("ActionName") or "").strip()
        # Consider new and old shapes from IFS
        granted = bool(
            row.get("CurrentlyGranted")
            or row.get("Granted")
            or row.get("Grant")
            or row.get("IsGranted")
        )

        g = by_entity.setdefault(entity, {
            "entity": entity,
            "friendly": _friendly_entity_name(entity, virt_map),
            "title": _friendly_title(entity, virt_map),
            "status_changes": [],
            "cleanup": [],
            "crud": [],
            "other": [],
        })
        item = {"entity": entity, "action": action, "granted": granted}
        if action == "CleanupVirtualEntity":
            g["cleanup"].append(item)
        elif action in {"Create", "Update", "Delete"}:
            g["crud"].append(item)
        elif action in _STATUS_WORDS:
            g["status_changes"].append(item)
        else:
            g["other"].append(item)

    # Merge header/line into combined virtual groups (CPOHeaderVirtual + CPOLineVirtual)
    def _merge_header_line_groups(groups: dict) -> dict:
        import re
        merged = {}
        singletons = {}
        for g in groups.values():
            ent = g["entity"]
            m = re.match(r"^(.*?)(Header|Line)Virtual$", ent)
            if not m:
                singletons[ent] = g
                continue
            base, kind = m.group(1), m.group(2).lower()
            key = f"{base}__merged"
            if key not in merged:
                merged[key] = {
                    "entity": ent,
                    "friendly": g["friendly"],
                    "title": g["title"],
                    "status_changes": [],
                    "cleanup": [],
                    "crud": [],
                    "other": [],
                    "_entities": set(),
                }
            mg = merged[key]
            if kind == "header":
                mg["friendly"] = g["friendly"]
                mg["title"] = g["title"]
            for bucket in ("status_changes", "cleanup", "crud", "other"):
                mg[bucket].extend(g[bucket])
            mg["_entities"].add(ent)
        out = {}
        for key, mg in merged.items():
            ents_sorted = sorted(mg["_entities"])
            mg["entity"] = ",".join(ents_sorted)
            del mg["_entities"]
            out[key] = mg
        out.update(singletons)
        return out

    groups = list(_merge_header_line_groups(by_entity).values())

    # 2) Split into "owners" (non-virtual) and "virtual groups" (entity contains 'Virtual')
    def is_virtual_group(g):
        return "Virtual" in (g.get("entity") or "")

    owners        = [g for g in groups if not is_virtual_group(g)]
    virtual_groups= [g for g in groups if is_virtual_group(g)]

    # 3) Build owner -> assistants (each assistant = one virtual in that virtual group)
    #    We match by visible title (e.g., "Purchase Order"), which is what the UI shows.
    out_groups = []
    for owner in owners:
        owner_title = (owner.get("title") or owner.get("friendly") or owner.get("entity") or "").strip()
        assistants = []
        for vg in virtual_groups:
            vg_title = (vg.get("title") or vg.get("friendly") or vg.get("entity") or "").strip()
            if not vg_title or vg_title.lower() != owner_title.lower():
                continue
            # expand "A,B" into ["A","B"]
            ents = [s.strip() for s in str(vg.get("entity") or "").split(",") if s.strip()]
            for v in ents:
                assistants.append({
                    "virtual": v,
                    # label/code are optional for the current UI logic
                    "label": None,
                    "code":  None,
                })
        out_groups.append({
            "owner": owner.get("entity"),  # e.g., "PurchaseOrder"
            "assistants": assistants,
        })

    return jsonify({"ok": True, "groups": out_groups})

# ── app/permissions.py

@permissions_bp.route('/grant_structure', methods=["GET", "POST"], endpoint="grant_structure")
@login_required
def grant_structure():
    role = (request.values.get('role') or '').strip()

    # GET -> render page (the page JS will fetch the not-granted list)
    if request.method == 'GET':
        return render_template('grant_structure.html', role=role, roles=[])

    # POST -> grant selected roles
    try:
        token = get_access_token()
        if not token:
            return render_template(
                "error_inline.html",
                message="Failed to get token from IFS.",
                back_url=url_for('permissions.grant_structure', role=role),
            )

        # roles[] come from the checkboxes
        selected = request.form.getlist('roles')
        if not selected:
            # Nothing chosen; just reload the page
            return redirect(url_for('permissions.grant_structure', role=role))
        
        # --- AUDIT: attach to the latest recent header; otherwise create an Updated header ---
        audit_id, audit_action = resolve_permission_set_audit(role, default_action="Updated")

        base = _psh_base()
        url  = f"{base}/GrantPermissionSets"

        # Build payload exactly like the working Postman call
        roles_joined = ';'.join([f"ROLE={r}^" for r in selected])
        payload = {
            "Role": role,
            "RolesToGrant": roles_joined
        }

        headers = _odata_headers(token)
        headers['Content-Type'] = 'application/json'
        headers['Accept'] = 'application/json'

        r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30, verify=_permission_verify())

        if r.status_code not in (200, 201, 204):
            # Surface IFS error body if present
            body = r.text[:800]
            return render_template(
                "error_inline.html",
                message=f"IFS GrantPermissionSets failed ({r.status_code}).\n{body}",
                back_url=url_for('permissions.grant_structure', role=role),
            )
            
        # --- AUDIT: structure grants (best-effort) ---
        if audit_id:
            for rname in selected:
                s = str(rname).strip()
                if s:
                    log_grant(audit_id, "structure", s, action_type=audit_action)

        _finish_context_update(role, structures=selected)

        # Success → reload page to refresh the list
        return redirect(url_for('permissions.grant_structure', role=role))

    except Exception as e:
        current_app.logger.exception("grant_structure POST failed")
        return render_template(
            "error_inline.html",
            message=f"Grant failed: {e}",
            back_url=url_for('permissions.grant_structure', role=role),
        )


# --- Not Granted Permission Sets proxy ---------------------------------------
@permissions_bp.route("/api/ifs/not_granted_permission_sets", methods=["GET"])
@login_required
def api_not_granted_permission_sets():
    import requests
    from urllib.parse import quote

    role  = (request.args.get("role") or "").strip()
    skip  = (request.args.get("$skip") or "0").strip()
    top   = (request.args.get("$top") or "25").strip()
    # default columns; allow override if you want
    select = (request.args.get("$select")
              or "Role,Description,FndRoleType,Objgrants,luname,keyref").strip()

    if not role:
        return jsonify(ok=False, error="Missing role"), 400

    token = get_access_token()
    if not token:
        return jsonify(ok=False, error="Failed to get IFS token"), 401

    base    = _psh_base()
    headers = _odata_headers(token)

    # Build the IFS URL (role must be quoted in OData call)
    url = (
        f"{base}/NotGrantedPermissionSets(Role='{quote(role)}')"
        f"?$select={select}&$skip={skip}"
    )

    try:
        r = requests.get(url, headers=headers, timeout=30, verify=_permission_verify())
        if r.status_code == 200:
            j = r.json() if r.content else {}
            value = j.get("value") if isinstance(j, dict) else []
            return jsonify(ok=True, value=value)

        current_app.logger.warning(
            "NotGrantedPermissionSets failed for role %s with HTTP %s. Falling back to PermissionSets list. Body=%s",
            role, r.status_code, (r.text or "")[:300]
        )
    except Exception as e:
        current_app.logger.warning(
            "NotGrantedPermissionSets request failed for role %s. Falling back to PermissionSets list. Error=%s",
            role, e
        )

    try:
        all_roles = fetch_permission_sets(token, top=max(int(top or 25), 500)) or []
        skip_i = max(int(skip or 0), 0)
        top_i = max(int(top or 25), 1)
        value = []
        for item in all_roles:
            role_name = (item.get("role") or "").strip()
            if not role_name or role_name == role:
                continue
            value.append({
                "Role": role_name,
                "Description": item.get("description") or "",
                "FndRoleType": "",
                "Objgrants": "",
                "luname": "",
                "keyref": "",
            })
        return jsonify(ok=True, value=value[skip_i:skip_i + top_i], fallback=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@permissions_bp.route("/api/ifs/grant_permission_sets", methods=["POST"])
@login_required
def api_grant_permission_sets():
    import requests
    from flask import jsonify

    data = request.get_json(silent=True) or {}
    role = (data.get("Role") or "").strip()
    roles_to_grant = (data.get("RolesToGrant") or "").strip()
    if not role or not roles_to_grant:
        return jsonify(ok=False, error="Role and RolesToGrant are required"), 400

    token = get_access_token()
    if not token:
        return jsonify(ok=False, error="Failed to get IFS token"), 401

    base = _psh_base()
    headers = _odata_headers(token)
    url = f"{base}/GrantPermissionSets"

    try:
        r = requests.post(url, headers=headers, json={"Role": role, "RolesToGrant": roles_to_grant}, timeout=30, verify=_permission_verify())
        if r.status_code not in (200, 204):
            return jsonify(ok=False, error=f"IFS {r.status_code}", details=r.text[:800]), 502
        # Some IFS deployments return 204 No Content on success
        out = r.json() if r.content else {"ok": True}
        out["ok"] = True
        return jsonify(out)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

