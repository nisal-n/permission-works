# app/services/ifs.py
import os
import re
import base64
import requests
import xml.etree.ElementTree as ET
import zipfile
import tempfile
import itertools
import time

from typing import Tuple, Optional, Dict, Any

from flask import current_app
from app.settings import get_active_env, get_env

# --- project delivery output directory ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DELIVERY_DIR = os.path.join(BASE_DIR, "deliveries")
os.makedirs(DELIVERY_DIR, exist_ok=True)
# ----------------------------------------

# ===================== Helpers to build API bases =====================

def _projection_base(root: str) -> str:
    return f"{root.rstrip('/')}/main/ifsapplications/projection/v1".replace("//main", "/main").rstrip("/")

def _odata_base(root: str) -> str:
    return f"{root.rstrip('/')}/main/ifsapplications/odata/v1".replace("//main", "/main").rstrip("/")


# ===================== DEV (export) env =====================

def _dev_conf() -> dict:
    """
    Use the environment block named "DEV" from settings, not whatever is currently
    active for exports. This guarantees imports go to DEV even if CFG is the active env.
    """
    s_env = get_active_env("DEV") or get_env("DEV") or {}
    env = os.environ

    base_root = (s_env.get("base_root")
                 or env.get("DEV_BASE_ROOT")
                 or current_app.config.get("DEV_BASE_ROOT", "")
                 ).rstrip("/")

    token_url = (s_env.get("token_url")
                 or env.get("DEV_TOKEN_URL")
                 or current_app.config.get("DEV_TOKEN_URL", "")
                 ).strip()

    client_id = (s_env.get("client_id")
                 or env.get("DEV_CLIENT_ID")
                 or current_app.config.get("DEV_CLIENT_ID", "")
                 ).strip()

    client_secret = (s_env.get("client_secret")
                     or env.get("DEV_CLIENT_SECRET")
                     or current_app.config.get("DEV_CLIENT_SECRET", "")
                     ).strip()

    scope = (s_env.get("scope")
             or env.get("DEV_SCOPE")
             or current_app.config.get("DEV_SCOPE", "openid microprofile-jwt")
             ).strip()

    ssl_verify = bool(s_env.get("ssl_verify", current_app.config.get("DEV_SSL_VERIFY", True)))

    return {
        "base_root": base_root,
        "projection_base": _projection_base(base_root),
        "odata_base": _odata_base(base_root),
        "token_url": token_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
        "ssl_verify": ssl_verify,
    }

def _make_pw_version_id(prefix: str = "pw") -> str:
    """
    Build a unique version id like pw_YYMMDD_HHMMSS (adds _1, _2... if same-second collision).
    """
    ts = time.strftime("%y%m%d_%H%M%S", time.localtime())
    base = f"{prefix}_{ts}"
    vid = base
    i = 1
    while os.path.exists(os.path.join(DELIVERY_DIR, f"{vid}.zip")):
        vid = f"{base}_{i}"
        i += 1
    return vid


def get_access_token() -> str | None:
    """
    Token for the active DEV environment (export side).
    """
    c = _dev_conf()
    data = {
        "grant_type": "client_credentials",
        "client_id": c["client_id"],
        "client_secret": c["client_secret"],
        "scope": c["scope"],
    }
    if not c["token_url"]:
        return None
    try:
        r = requests.post(c["token_url"], data=data, timeout=20, verify=c["ssl_verify"])
        if r.status_code == 200:
            return r.json().get("access_token")
        return None
    except Exception:
        return None


def _std_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }


# ===================== Generic env (for targets other than DEV/CFG) =====================

def _generic_env_conf(name: str) -> dict:
    """
    Build config for an arbitrary env saved in Setup IFS (e.g., 'QA', 'UAT', 'CFG2', etc).
    """
    s = get_env(name) or {}
    base_root = (s.get("base_root") or s.get("cfg_base_root") or "").rstrip("/")
    token_url = (s.get("token_url") or s.get("cfg_token_url") or "").strip()
    client_id = (s.get("client_id") or s.get("cfg_client_id") or "").strip()
    client_secret = (s.get("client_secret") or s.get("cfg_client_secret") or "").strip()
    scope = (s.get("scope") or s.get("cfg_scope") or "openid microprofile-jwt").strip()
    ssl_verify = bool(s.get("ssl_verify", True))
    return {
        "name": name,
        "base_root": base_root,
        "projection_base": _projection_base(base_root) if base_root else "",
        "odata_base": _odata_base(base_root) if base_root else "",
        "token_url": token_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
        "ssl_verify": ssl_verify,
    }


def get_access_token_for_env(name: str) -> tuple[str | None, dict | None]:
    """
    Client credentials token for any named env block (other than DEV/CFG specialized helpers).
    """
    c = _generic_env_conf(name)
    if not c.get("token_url") or not c.get("client_id") or not c.get("client_secret"):
        return None, {"where": "token", "error": f"missing oauth config for env {name}"}
    data = {
        "grant_type": "client_credentials",
        "client_id": c["client_id"],
        "client_secret": c["client_secret"],
        "scope": c["scope"],
    }
    try:
        r = requests.post(c["token_url"], data=data, timeout=25, verify=c["ssl_verify"])
        if r.status_code != 200:
            return None, {"where": "token", "status": r.status_code, "text": (r.text or "")[:800]}
        j = r.json()
        return j.get("access_token"), None
    except requests.exceptions.RequestException as e:
        return None, {"where": "token", "error": str(e)}


# ===== Env-aware grant helpers (do NOT remove old ones) =====
def _env_proj_base(env_name: str) -> tuple[str, bool]:
    c = _env_conf_for((env_name or "DEV").strip().upper())
    return c["projection_base"].rstrip("/"), bool(c.get("ssl_verify", True))

def grant_projection_env(projection: str, role: str, token: str, env_name: str) -> tuple[bool, dict | None]:
    import requests
    base, verify = _env_proj_base(env_name)
    url = f"{base}/PermissionSetHandling.svc/GrantProjections"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}
    payload = {"Projections": f"PROJECTION_NAME={projection};", "Role": role}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=30, verify=verify)
        ok = r.status_code in (200, 201, 204)
        return ok, None if ok else {"status": r.status_code, "text": (r.text or "")[:600], "url": url}
    except Exception as e:
        return False, {"error": str(e), "url": url}

def grant_read_only_env(projection: str, role: str, token: str, env_name: str) -> tuple[bool, dict | None]:
    import requests
    base, verify = _env_proj_base(env_name)
    # action bound to ProjectionGrants entity
    url = f"{base}/PermissionSetHandling.svc/ProjectionGrants(Projection='{projection}',Role='{role}')/IfsApp.PermissionSetHandling.ProjectionGrant_GrantReadOnly"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}
    try:
        r = requests.post(url, json={}, headers=headers, timeout=30, verify=verify)
        ok = r.status_code in (200, 201, 204)
        return ok, None if ok else {"status": r.status_code, "text": (r.text or "")[:600], "url": url}
    except Exception as e:
        return False, {"error": str(e), "url": url}

def grant_lobby_page_env(lobby_id: str, role: str, token: str, env_name: str) -> tuple[str | None, dict | None]:
    import requests
    base, verify = _env_proj_base(env_name)
    url = f"{base}/PermissionSetHandling.svc/GrantLobbyPage"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}
    payload = {"Role": role, "LobbyId": lobby_id}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=30, verify=verify)
        if r.status_code not in (200, 201, 204):
            return None, {"status": r.status_code, "text": (r.text or "")[:800], "url": url}
        # Try to extract a title like your old helper did
        t = _extract_title_from_grant_response(r)
        return (t or None), None
    except Exception as e:
        return None, {"error": str(e), "url": url}

def grant_bpas_env(key: str, role: str, token: str, env_name: str) -> tuple[bool, dict | None]:
    import requests
    base, verify = _env_proj_base(env_name)
    url = f"{base}/PermissionSetHandling.svc/GrantBpas"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}
    payload = {"Bpas": f"ID={key}", "Role": role}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=30, verify=verify)
        ok = r.status_code in (200, 201, 204)
        return ok, None if ok else {"status": r.status_code, "text": (r.text or "")[:600], "url": url}
    except Exception as e:
        return False, {"error": str(e), "url": url}



def check_permission_set_exists(env_name: str, role: str) -> tuple[bool | None, dict | None]:
    """
    GET by key: PermissionSets(Role='{Role}') in the target env.
    """
    # Reuse specialized configs when possible
    if env_name.upper() == "DEV":
        c = _dev_conf()
        tok = get_access_token()
        if not tok:
            return None, {"where": "token", "error": "No DEV token"}
    elif env_name.upper() == "CFG":
        c = _cfg_conf()
        tok, terr = get_cfg_access_token()
        if not tok:
            return None, terr or {"where": "token", "error": "No CFG token"}
    else:
        c = _generic_env_conf(env_name)
        tok, terr = get_access_token_for_env(env_name)
        if not tok:
            return None, terr or {"where": "token", "error": f"No token for {env_name}"}

    headers = {
        "Authorization": f"Bearer {tok}",
        "Accept": "application/json",
        "OData-Version": "4.0",
        "OData-MaxVersion": "4.0",
    }
    url = f"{c['projection_base']}/PermissionSetHandling.svc/PermissionSets(Role='{role}')"
    try:
        r = requests.get(url, headers=headers, timeout=25, verify=c["ssl_verify"])
        if r.status_code == 200:
            return True, None
        if r.status_code == 404:
            return False, None
        return None, {"status": r.status_code, "text": (r.text or "")[:600], "url": url}
    except requests.exceptions.RequestException as e:
        return None, {"error": str(e), "url": url}


def preview_permission_sets(source_env: str, target_env: str, roles: list[str]) -> dict:
    """
    Return replace/new per role in target_env.
    """
    items = []
    for role in roles or []:
        exists, err = check_permission_set_exists(target_env, role)
        if exists is None:
            items.append({"role": role, "status": "unknown", "error": err})
        else:
            items.append({"role": role, "status": "replace" if exists else "new"})
    return {
        "source_env": source_env,
        "target_env": target_env,
        "items": items,
    }


def version_name(prefix: str = "PW-OA") -> str:
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{ts}"


# ===================== Readers (roles/users/groups) =====================

def fetch_permission_sets(token, top=200, q=None):
    base = f"{_dev_conf()['projection_base']}/PermissionSetHandling.svc/PermissionSets"
    params = [f"$top={int(top)}", "$select=Role,Description", "$orderby=Role"]
    if q:
        q_safe = q.replace("'", "''")
        params.append(f"$filter=startswith(Role,'{q_safe}')")
    url = f"{base}?{'&'.join(params)}"
    try:
        r = requests.get(url, headers=_std_headers(token), timeout=30)
        if r.status_code != 200:
            return []
        data = r.json()
        items = data.get("value") if isinstance(data, dict) else []
        roles = []
        for it in items or []:
            role = it.get("Role") or it.get("ROLE") or it.get("Id") or it.get("ID")
            desc = it.get("Description") or it.get("DESC") or ""
            if role:
                roles.append({"role": str(role), "description": str(desc)})
        roles.sort(key=lambda x: x["role"].lower())
        return roles
    except Exception:
        return []


def fetch_users_page(token, top=20):
    try:
        base = f"{_dev_conf()['projection_base']}/PermissionSetHandling.svc/Users"
        url = f"{base}?$top={int(top)}"
        r = requests.get(url, headers=_std_headers(token), timeout=30)
        if r.status_code != 200:
            return None, {"error": "ifs_users_failed", "status": r.status_code, "details": r.text[:500]}
        data = r.json()
        items = data.get("value") if isinstance(data, dict) else []
        users = []
        for it in items or []:
            identity = it.get("Identity") or it.get("UserId") or it.get("Id") or it.get("User") or it.get("USERNAME") or it.get("USERID")
            label = it.get("Description") or it.get("Name") or it.get("UserName") or identity
            if identity:
                users.append({"id": str(identity), "label": str(label) if label else str(identity)})
        return users, None
    except Exception as e:
        return None, {"error": "exception", "details": str(e)}


def fetch_user_groups_page(token, top=20):
    try:
        base = f"{_dev_conf()['projection_base']}/PermissionSetHandling.svc/UserGroups"
        url = f"{base}?$top={int(top)}"
        r = requests.get(url, headers=_std_headers(token), timeout=30)
        if r.status_code != 200:
            return None, {"error": "ifs_groups_failed", "status": r.status_code, "details": r.text[:500]}
        data = r.json()
        items = data.get("value") if isinstance(data, dict) else []
        groups = []
        for it in items or []:
            gid = (it.get("GroupId") or it.get("GroupIdentity") or it.get("Identity")
                   or it.get("UserGroup") or it.get("GROUP_ID") or it.get("GROUPIDENTITY"))
            label = it.get("Description") or it.get("Name") or gid
            if gid:
                groups.append({"id": str(gid), "label": str(label) if label else str(gid)})
        return groups, None
    except Exception as e:
        return None, {"error": "exception", "details": str(e)}


# ===================== Grant helpers =====================

def grant_projection(projection, role, headers):
    url = f"{_dev_conf()['projection_base']}/PermissionSetHandling.svc/GrantProjections"
    payload = {"Projections": f"PROJECTION_NAME={projection};", "Role": role}
    try:
        requests.post(url, json=payload, headers=headers, timeout=30, verify=_dev_conf()["ssl_verify"])
    except Exception:
        pass


def grant_read_only(projection, role, access_token):
    base = _dev_conf()["projection_base"]
    url = f"{base}/PermissionSetHandling.svc/ProjectionGrants(Projection='{projection}',Role='{role}')/IfsApp.PermissionSetHandling.ProjectionGrant_GrantReadOnly"
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    try:
        requests.post(url, headers=headers, timeout=30, verify=_dev_conf()["ssl_verify"])
    except Exception:
        pass


def _extract_title_from_grant_response(resp):
    try:
        data = resp.json()
    except Exception:
        data = None

    def _find_title(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and k.lower() in ("title", "lobbytitle", "name", "displayname"):
                    if v.strip():
                        return v.strip()
            for v in obj.values():
                t = _find_title(v)
                if t:
                    return t
        elif isinstance(obj, list):
            for item in obj:
                t = _find_title(item)
                if t:
                    return t
        return None

    if data is not None:
        t = _find_title(data)
        if t:
            return t
    m = re.search(r'"(?:Title|LobbyTitle|Name|DisplayName)"\s*:\s*"([^"]+)"', getattr(resp, "text", ""), flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def grant_lobby_page(lobby_id, role, access_token):
    url = f"{_dev_conf()['projection_base']}/PermissionSetHandling.svc/GrantLobbyPage"
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    try:
        r = requests.post(url, json={"Role": role, "LobbyId": lobby_id}, headers=headers, timeout=30, verify=_dev_conf()["ssl_verify"])
        title = _extract_title_from_grant_response(r)
        if title:
            return title
    except Exception:
        pass
    return None


# ===================== Export (DEV) → Save ZIP =====================

def export_permission_start(token):
    base = _dev_conf()["projection_base"]
    url = f"{base}/PermissionSetHandling.svc/ExportPermissionSetVirtuals"
    headers = _std_headers(token)
    try:
        r = requests.post(url, json={}, headers=headers, timeout=30, verify=_dev_conf()["ssl_verify"])
        if r.status_code not in (200, 201):
            return None, {"status": r.status_code, "text": r.text[:500]}
        j = r.json() if r.content else {}
        objkey = None
        if isinstance(j, dict):
            for k in ("Objkey", "OBJKEY", "ObjectKey", "Id", "id"):
                if k in j and j[k]:
                    objkey = str(j[k]); break
        return objkey, None
    except Exception as e:
        return None, {"error": str(e)}


def export_permission_update_list(token, objkey, roles):
    sel = ";".join([f"ROLE={r}^" for r in roles])
    base = _dev_conf()["projection_base"]
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ExportPermissionSetVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ExportPermissionSetVirtual_UpdateExportList"
    )
    headers = _std_headers(token)
    payload = {"Selection": sel, "ParentObjkeyExport": objkey}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=45, verify=_dev_conf()["ssl_verify"])
        ok = r.status_code in (200, 201, 204)
        return ok, None if ok else {"status": r.status_code, "text": r.text[:500]}
    except Exception as e:
        return False, {"error": str(e)}


def export_permission_create_export(token, objkey, user_grants=True, user_group_grants=False):
    base = _dev_conf()["projection_base"]
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ExportPermissionSetVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ExportPermissionSetVirtual_CreateExport"
    )
    headers = _std_headers(token)
    payload = {"UserGrants": bool(user_grants), "UserGroupGrants": bool(user_group_grants)}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=45, verify=_dev_conf()["ssl_verify"])
        ok = r.status_code in (200, 201, 204)
        return ok, None if ok else {"status": r.status_code, "text": r.text[:500]}
    except Exception as e:
        return False, {"error": str(e)}


def export_permission_get_zip(token, objkey):
    base = _dev_conf()["projection_base"]
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ExportPermissionSetVirtuals(Objkey='{objkey}')/ZipFile"
    )
    headers = _std_headers(token)
    try:
        r = requests.get(url, headers=headers, timeout=60, verify=_dev_conf()["ssl_verify"])
        if r.status_code != 200:
            return None, {"status": r.status_code, "text": r.text[:500]}
        repo = os.path.join(BASE_DIR, "tmp_repo")
        os.makedirs(repo, exist_ok=True)
        path = os.path.join(repo, f"{objkey}.zip")
        with open(path, "wb") as f:
            f.write(r.content)
        return path, None
    except Exception as e:
        return None, {"error": str(e)}


def finalize_export(token, objkey, roles, user_grants=True, user_group_grants=False):
    ok, err = export_permission_update_list(token, objkey, roles)
    if not ok:
        return None, {"where": "update_list", **(err or {})}
    ok, err = export_permission_create_export(token, objkey, user_grants=user_grants, user_group_grants=user_group_grants)
    if not ok:
        return None, {"where": "create_export", **(err or {})}
    path, err = export_permission_get_zip(token, objkey)
    if err or not path:
        return None, {"where": "get_zip", **(err or {})}

    # NEW: name the final artifact as pw_YYMMDD_HHMMSS.zip (not objkey.zip)
    new_version_id = _make_pw_version_id("pw")
    final_path = os.path.join(DELIVERY_DIR, f"{new_version_id}.zip")
    try:
        if os.path.abspath(path) != os.path.abspath(final_path):
            if os.path.exists(final_path):
                os.remove(final_path)
            os.replace(path, final_path)
    except Exception as e:
        return None, {"where": "rename_zip", "error": str(e)}

    return new_version_id, None



# ===================== CFG (import) env via discovery =====================

def _cfg_conf() -> dict:
    """
    Build CFG (import) config from the *active* CFG environment saved in settings.
    Supports both plain keys (base_root, realm, ...) and cfg_* keys (cfg_base_root, cfg_realm, ...).
    """
    s_env = get_env("CFG") or {}

    def pick(env: dict, *keys, default: str = ""):
        for k in keys:
            v = env.get(k)
            if v not in (None, ""):
                return v
        return default

    # accept either base_root or cfg_base_root, etc.
    base_root   = str(pick(s_env, "base_root", "cfg_base_root", default=current_app.config.get("CFG_ISSUER_ROOT", ""))).rstrip("/")
    realm       = str(pick(s_env, "realm", "cfg_realm", default=current_app.config.get("CFG_REALM", ""))).strip()
    client_id   = str(pick(s_env, "client_id", "cfg_client_id", default=current_app.config.get("CFG_CLIENT_ID", ""))).strip()
    client_sec  = str(pick(s_env, "client_secret", "cfg_client_secret", default=current_app.config.get("CFG_CLIENT_SECRET", "")))
    scope       = str(pick(s_env, "scope", "cfg_scope", default=current_app.config.get("CFG_SCOPE", "openid microprofile-jwt")))
    ssl_verify  = bool(pick(s_env, "ssl_verify", "cfg_ssl_verify", default=current_app.config.get("CFG_SSL_VERIFY", True)))
    odata_pref  = str(pick(s_env, "odata_prefix", "cfg_odata_prefix", default=current_app.config.get("CFG_ODATA_PREFIX", ""))).strip().strip("/")

    # allow OS env var to override FndTempLobs service base
    env_fnd_override = os.environ.get("CFG_ODATA_FNDTEMPLOBS_URL", "").strip().rstrip("/")
    fnd_override = str(
        pick(
            s_env,
            "fndtemplobs_url",
            "cfg_fndtemplobs_url",
            default=env_fnd_override or current_app.config.get("CFG_ODATA_FNDTEMPLOBS_URL", "")
        )
    ).strip().rstrip("/")

    token_url   = str(pick(s_env, "token_url", "cfg_token_url", default=current_app.config.get("CFG_TOKEN_URL", ""))).strip()

    # derive bases if we have a tenant root
    def _projection_base_local(root: str) -> str:
        return f"{root.rstrip('/')}/main/ifsapplications/projection/v1".replace("//main", "/main").rstrip("/")
    def _odata_base_local(root: str) -> str:
        return f"{root.rstrip('/')}/main/ifsapplications/odata/v1".replace("//main", "/main").rstrip("/")

    projection_base = _projection_base_local(base_root) if base_root else current_app.config.get("CFG_BASE", "")
    odata_base      = _odata_base_local(base_root) if base_root else current_app.config.get("CFG_ODATA_BASE", "")

    return {
        "base_root": base_root,
        "projection_base": projection_base,
        "odata_base": odata_base,
        "issuer_root": base_root or current_app.config.get("CFG_ISSUER_ROOT", ""),
        "realm": realm,
        "client_id": client_id,
        "client_secret": client_sec,
        "scope": scope,
        "ssl_verify": ssl_verify,
        "odata_prefix": odata_pref,
        "fndtemplobs_url": fnd_override,
        "token_url": token_url,
    }


def _cfg_discover_token_url():
    c = _cfg_conf()
    # Explicit override first
    if c["token_url"]:
        return c["token_url"], None

    root = c["issuer_root"].rstrip("/")
    realm = (c["realm"] or "").strip()
    if not root or not realm:
        return None, {"where": "config", "error": "Missing base_root/realm for CFG"}

    verify = c["ssl_verify"]
    candidates = [
        f"{root}/auth/realms/{realm}/.well-known/openid-configuration",
        f"{root}/realms/{realm}/.well-known/openid-configuration",
    ]
    last_err = None
    for url in candidates:
        try:
            r = requests.get(url, timeout=15, verify=verify, headers={"Accept": "application/json"})
            if r.status_code == 200:
                try:
                    j = r.json()
                    token_url = j.get("token_endpoint")
                    if token_url:
                        return token_url, None
                    last_err = {"where": "discovery_parse", "status": 200, "text": (r.text or "")[:500]}
                except Exception as e:
                    last_err = {"where": "discovery_json", "status": 200, "error": str(e)}
            else:
                last_err = {"where": "discovery_http", "status": r.status_code, "text": (r.text or "")[:300], "url": url}
        except requests.exceptions.RequestException as e:
            last_err = {"where": "discovery_http", "error": str(e), "url": url}
    return None, last_err or {"where": "discovery_http", "error": "No candidate succeeded"}


def get_cfg_access_token():
    token_url, derr = _cfg_discover_token_url()
    if not token_url:
        return None, {"where": "discovery", **(derr or {})}

    c = _cfg_conf()
    data = {
        "grant_type": "client_credentials",
        "client_id": c["client_id"],
        "client_secret": c["client_secret"],
        "scope": c["scope"],
    }
    if not data["client_id"] or not data["client_secret"]:
        return None, {"where": "config", "error": "Missing client_id/client_secret for CFG"}

    try:
        r = requests.post(token_url, data=data, timeout=20, verify=c["ssl_verify"], headers={"Accept": "application/json"})
        ct = r.headers.get("content-type", "")
        body_text = (r.text or "")[:600]
        if r.status_code == 200:
            try:
                j = r.json()
                tok = j.get("access_token")
                if tok:
                    return tok, None
                return None, {"where": "token_parse", "status": 200, "text": body_text}
            except Exception as e:
                return None, {"where": "json_decode", "status": 200, "error": str(e), "text": body_text}
        else:
            return None, {"where": "token_http", "status": r.status_code, "content_type": ct, "text": body_text, "token_url": token_url}
    except requests.exceptions.SSLError as e:
        return None, {"where": "ssl", "error": str(e)}
    except requests.exceptions.RequestException as e:
        return None, {"where": "network", "error": str(e)}


# ===================== CFG import helpers =====================

def _std_headers_for_cfg(token):
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }


def _probe_fndtemplobs_direct(token, root):
    c = _cfg_conf()
    verify = c["ssl_verify"]
    url = f"{root.rstrip('/')}/FndTempLobs?$top=0"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }
    try:
        r = requests.get(url, headers=headers, timeout=12, verify=verify)
        return r.status_code == 200
    except requests.exceptions.RequestException:
        return False


def _normalize_override_to_base(url: str) -> str:
    """
    Allow override to be either a service base OR a direct collection URL.

    Accepts examples like:
      - https://<root>/main/ifsapplications/odata/v1/ifsfoundation
      - https://<root>/main/ifsapplications/odata/v1/ifsfoundation/FndTempLobs
      - https://<root>/ifsapplications/odata/FndTempLobs
      - https://<root>/ifsapplications/odata/v1

    Returns the service base (without trailing slash), e.g.:
      https://<root>/main/ifsapplications/odata/v1/ifsfoundation
    """
    if not url:
        return ""
    u = url.strip().rstrip("/")

    # If the user pasted the collection URL, peel it back to the base
    if u.lower().endswith("/fndtemplobs"):
        u = u[: -len("/FndTempLobs")]
    # If the user pasted $metadata, peel it back to the base
    if u.lower().endswith("/$metadata"):
        u = u[: -len("/$metadata")]

    return u


def _candidate_odata_bases(c: dict) -> list[str]:
    """
    Build a wide set of plausible OData bases, prioritizing known-good paths.
    """
    root = (c.get("base_root") or "").rstrip("/")
    bases = []

    def add(path: str):
        if root:
            bases.append(f"{root}{path}")

    # 1) Keep explicit config first
    if c.get("odata_base"):
        bases.append(c["odata_base"].rstrip("/"))

    # 2) Known-good order:
    add("/main/ifsapplications/odata/v1")
    add("/ifsapplications/odata/v1")
    add("/main/ifsapplications/odata")
    add("/ifsapplications/odata")

    # Top-level ifsfoundation (seen on some landscapes)
    add("/main/ifsfoundation/odata/v1")
    add("/ifsfoundation/odata/v1")
    add("/main/ifsfoundation/odata")
    add("/ifsfoundation/odata")

    # Lower priority generic containers
    add("/applications/odata/v1")
    add("/applications/odata")
    add("/main/ifscloud/odata/v1")
    add("/ifscloud/odata/v1")
    add("/main/ifscloud/odata")
    add("/ifscloud/odata")

    # Deduplicate preserving order
    seen, uniq = set(), []
    for b in bases:
        b = b.replace("//main", "/main").rstrip("/")
        if b not in seen:
            seen.add(b)
            uniq.append(b)
    return uniq


def _discover_fndtemplobs_endpoint(token) -> Tuple[Optional[str], Optional[dict]]:
    """
    Find the correct OData service base hosting FndTempLobs.

    Strategy:
      - If override is present (env or config), accept either service base or full collection URL,
        normalize and verify via direct probe.
      - Else try many OData base variants (with/without /main, /v1, and several roots).
      - Under each base, try:
          1) $metadata (optional)
          2) direct probe: FndTempLobs?$top=0 (authoritative; cheap)
    Returns: (base_url, err) where base_url is like
             https://<host>/main/ifsapplications/odata/v1/ifsfoundation
    """
    c = _cfg_conf()
    verify = c["ssl_verify"]
    cfg_pref = (c.get("odata_prefix") or "").strip().strip("/")

    # Prefixes to try *under* a base
    prefixes = []
    if cfg_pref:
        prefixes.append(cfg_pref)
    for p in ("ifsfoundation", "foundation", "ifsapplications", "ifsapplication", "ifscore", ""):
        if p not in prefixes:
            prefixes.append(p)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, application/xml",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }

    def _direct_probe(root: str) -> bool:
        url = f"{root.rstrip('/')}/FndTempLobs?$top=0"
        try:
            r = requests.get(url, headers=headers, timeout=12, verify=verify)
            return r.status_code == 200
        except requests.exceptions.RequestException:
            return False

    # 0) Highest-priority: OS env override
    env_override_raw = os.environ.get("CFG_ODATA_FNDTEMPLOBS_URL", "").strip()
    if env_override_raw:
        base = _normalize_override_to_base(env_override_raw)
        if base:
            if _direct_probe(base):
                return base, None
            for p in prefixes:
                candidate = base if p == "" else f"{base.rstrip('/')}/{p}"
                if _direct_probe(candidate):
                    return candidate, None
        # continue to next strategies

    # 1) Config override
    override_raw = (c.get("fndtemplobs_url") or "").strip()
    if override_raw:
        base = _normalize_override_to_base(override_raw)
        if base:
            if _direct_probe(base):
                return base, None
            for p in prefixes:
                candidate = base if p == "" else f"{base.rstrip('/')}/{p}"
                if _direct_probe(candidate):
                    return candidate, None

    # 2) Try candidate OData bases
    tried = []
    for base in _candidate_odata_bases(c):
        base = base.rstrip("/")

        # metadata (informational)
        for p in prefixes:
            root = base if p == "" else f"{base}/{p}"
            meta_url = f"{root}/$metadata"
            try:
                m = requests.get(meta_url, headers=headers, timeout=10, verify=verify)
                tried.append({"step": "metadata", "url": meta_url, "status": getattr(m, "status_code", None)})
            except requests.exceptions.RequestException as e:
                tried.append({"step": "metadata", "url": meta_url, "status": f"exception: {e}"})

            # direct probe (authoritative)
            if _direct_probe(root):
                return root, None

    return None, {"error": "FndTempLobs not found under any candidate", "tried": tried[:30]}


def cfg_upload_temp_lob(token, file_path, file_name, content_type="application/octet-stream"):
    """
    Create a temp LOB in PermissionSetHandling.svc and upload the XML stream (CFG flavor).
    Returns: (lob_id, err)
    """
    c = _cfg_conf()
    verify = c["ssl_verify"]
    svc_base = f"{c['projection_base'].rstrip('/')}/PermissionSetHandling.svc"

    headers_json = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }
    headers_put = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": content_type,   # stream upload
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
        "If-Match": "*",
    }

    def _post_create(payload: dict) -> tuple[Optional[str], Optional[dict]]:
        url = f"{svc_base}/FndTempLobs"
        try:
            r = requests.post(url, json=payload, headers=headers_json, timeout=20, verify=verify)
            if r.status_code not in (200, 201):
                return None, {"step": "create", "status": r.status_code, "text": (r.text or "")[:900], "url": url}
            j = r.json() if r.content else {}
            lob_id = (j.get("LobId") or j.get("LOBID") or j.get("Id") or j.get("id"))
            if not lob_id:
                return None, {"step": "create", "status": r.status_code, "text": "Missing LobId", "url": url}
            return str(lob_id), None
        except requests.RequestException as e:
            return None, {"step": "create", "error": str(e), "url": url}

    def _sanitize_seed(seed: dict) -> dict:
        if not isinstance(seed, dict):
            return {}
        out = {}
        for k, v in seed.items():
            if k.startswith("@"):
                continue
            lk = k.lower()
            if (
                lk.startswith("lob") or
                lk.startswith("obj") or
                lk.startswith("row") or
                lk.startswith("created") or
                lk.startswith("modified") or
                lk.startswith("blob") or
                lk.startswith("etag") or
                "odata." in lk or
                "blobdata@odata" in lk or
                lk in {"id", "lobid", "objid", "objversion", "rowkey", "rowversion", "rowstate"}
            ):
                continue
            if isinstance(v, (str, int, float, bool)) or v is None:
                out[k] = v
        return out

    # 1) Minimal insert
    lob_id, err = _post_create({})
    if err and not lob_id:
        # 2) Default() -> sanitize -> POST
        def_url = f"{svc_base}/FndTempLobs/IfsApp.PermissionSetHandling.FndTempLobStore_Default()"
        try:
            hdr_def = dict(headers_json); hdr_def["If-Match"] = "*"
            rd = requests.get(def_url, headers=hdr_def, timeout=15, verify=verify)
            if rd.status_code != 200:
                return None, {"step": "default", "status": rd.status_code, "text": (rd.text or "")[:700], "url": def_url}
            seed = rd.json() if rd.content else {}
        except requests.RequestException as e:
            return None, {"step": "default", "error": str(e), "url": def_url}

        payload = _sanitize_seed(seed)
        lob_id, err = _post_create(payload)
        if err or not lob_id:
            return None, err

    # 3) Upload stream to BlobData
    put_url = f"{svc_base}/FndTempLobs(LobId='{lob_id}')/BlobData"
    try:
        with open(file_path, "rb") as fh:
            data = fh.read()
        r2 = requests.put(put_url, headers=headers_put, data=data, timeout=180, verify=verify)
        if r2.status_code not in (200, 201, 204):
            return None, {"step": "upload", "status": r2.status_code, "text": (r2.text or "")[:900], "url": put_url}
    except requests.RequestException as e:
        return None, {"step": "upload", "error": str(e), "url": put_url}

    return lob_id, None


def cfg_upload_temp_lob_by_base(token, base_url, file_path, file_name, content_type="application/xml"):
    c = _cfg_conf()
    verify = c["ssl_verify"]

    headers_json = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }
    headers_bin = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": content_type,
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }

    create_url = f"{base_url.rstrip('/')}/FndTempLobs"
    payload = {"FileName": file_name, "ContentType": content_type}
    try:
        r = requests.post(create_url, json=payload, headers=headers_json, timeout=30, verify=verify)
        if r.status_code not in (200, 201):
            return None, {"status": r.status_code, "text": r.text[:500], "step": "create", "url": create_url}
        j = r.json() if r.content else {}
        lob_id = (j.get("LobId") or j.get("LOBID") or j.get("Id") or j.get("id"))
        if not lob_id:
            return None, {"status": r.status_code, "text": "Missing LobId", "step": "create", "url": create_url}
        lob_id = str(lob_id)
    except Exception as e:
        return None, {"error": str(e), "step": "create", "url": create_url}

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        value_url = f"{base_url.rstrip('/')}/FndTempLobs({lob_id})/$value"
        r2 = requests.put(value_url, headers=headers_bin, data=data, timeout=180, verify=verify)
        if r2.status_code not in (200, 201, 204):
            return None, {"status": r2.status_code, "text": r2.text[:500], "step": "upload", "url": value_url}
    except Exception as e:
        return None, {"error": str(e), "step": "upload"}

    return lob_id, None


def cfg_import_start(token):
    c = _cfg_conf()
    base = c["projection_base"]
    url = f"{base}/PermissionSetHandling.svc/ImportPermissionSetsVirtuals"
    try:
        r = requests.post(url, json={}, headers=_std_headers_for_cfg(token), timeout=30, verify=c["ssl_verify"])
        if r.status_code not in (200, 201):
            return None, {"status": r.status_code, "text": r.text[:500]}
        j = r.json() if r.content else {}
        objkey = None
        if isinstance(j, dict):
            for k in ("Objkey", "OBJKEY", "ObjectKey", "Id", "id"):
                if j.get(k):
                    objkey = str(j[k]); break
        if not objkey:
            return None, {"status": r.status_code, "text": "Missing Objkey"}
        return objkey, None
    except Exception as e:
        return None, {"error": str(e)}


def cfg_import_create_file_record(token, objkey, file_name, lob_id):
    c = _cfg_conf()
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ImportPermissionSetsVirtual_CreateFileRecord"
    )
    headers = _std_headers_for_cfg(token)
    headers["If-Match"] = "*"
    payload = {"FileName": file_name, "LobId": lob_id}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=45, verify=c["ssl_verify"])
        if r.status_code not in (200, 201, 204):
            return False, {"status": r.status_code, "text": r.text[:800], "url": url}
        return True, None
    except Exception as e:
        return False, {"error": str(e), "url": url}


def cfg_import_fetch_permission_set_info(token, objkey):
    c = _cfg_conf()
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ImportPermissionSetsVirtual_FetchPermissionSetInfo"
    )
    headers = _std_headers_for_cfg(token)
    headers["If-Match"] = "*"
    try:
        r = requests.post(url, json={}, headers=headers, timeout=60, verify=c["ssl_verify"])
        if r.status_code not in (200, 201, 204):
            return False, {"status": r.status_code, "text": r.text[:800], "url": url}
        return True, None
    except Exception as e:
        return False, {"error": str(e), "url": url}


def cfg_import_finish(token: str, objkey: str, *, timeout: int = 60):
    c = _cfg_conf()
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ImportPermissionSetsVirtual_ImportFinish"
    )
    headers = _std_headers_for_cfg(token)
    headers["If-Match"] = "*"
    try:
        r = requests.post(url, json={}, headers=headers, timeout=timeout, verify=c.get("ssl_verify", True))
        if r.status_code in (200, 201, 204):
            return True, None
        return False, {"status": r.status_code, "text": (r.text or "")[:1000], "url": url}
    except requests.RequestException as e:
        return False, {"error": str(e), "url": url}


def cfg_import_cleanup(token: str, objkey: str, *, timeout: int = 30) -> bool:
    c = _cfg_conf()
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ImportPermissionSetsVirtual_CleanupVirtualEntity"
    )
    try:
        r = requests.post(
            url,
            json={},
            headers=_std_headers_for_cfg(token),
            timeout=timeout,
            verify=c.get("ssl_verify", True),
        )
        return r.status_code in (200, 201, 204)
    except Exception:
        return False


# ---------- Optional: direct property write ----------
def cfg_import_upload_permset_file(token, objkey, xml_bytes: bytes):
    """
    Writes the XML content directly to the ImportPermissionSetsVirtuals PermSetFile property.
    OData primitive stream pattern: PATCH the property with {"value": "<base64>"}.
    """
    c = _cfg_conf()
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{objkey}')/PermSetFile"
    )
    try:
        b64 = base64.b64encode(xml_bytes).decode("ascii")
        headers = _std_headers_for_cfg(token).copy()
        headers["Content-Type"] = "application/json"
        r = requests.patch(url, json={"value": b64}, headers=headers, timeout=60, verify=c["ssl_verify"])
        if r.status_code not in (200, 204):
            return False, {"status": r.status_code, "text": r.text[:700], "url": url}
        return True, None
    except Exception as e:
        return False, {"error": str(e), "url": url}


# ---------- Iterate XML files from a ZIP ----------

def iter_permission_xmls(zip_path):
    """Yield (filename, bytes) for each *.xml in the zip (flattens subfolders)."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            if name.lower().endswith(".xml"):
                with zf.open(name) as fh:
                    yield os.path.basename(name), fh.read()


# ===== Import-target selector (DEV vs CFG vs Other) =====

def _import_target() -> str:
    """
    Which environment to import into. Defaults to DEV.
    Set current_app.config['IMPORT_TARGET'] = 'CFG' only if you want CFG explicitly.
    """
    try:
        target = (current_app.config.get("IMPORT_TARGET", "DEV") or "DEV").upper()
    except Exception:
        target = "DEV"
    return "CFG" if target == "CFG" else "DEV"


def _env_conf_for(target: str) -> dict:
    t = (target or "").upper()
    if t == "CFG":
        return _cfg_conf()
    if t == "DEV":
        return _dev_conf()
    return _generic_env_conf(target)


def _env_headers_for(token: str, target: str) -> dict:
    return _std_headers_for_cfg(token) if (target or "").upper() == "CFG" else _std_headers(token)


def _env_token_for(target: str, cfg_token_hint: str | None) -> tuple[str | None, dict | None]:
    """
    For CFG we keep using the passed-in token (cfg_token_hint) if provided;
    otherwise we fetch one. For DEV we fetch DEV token. For others, use generic token.
    """
    t = (target or "").upper()
    if t == "CFG":
        if cfg_token_hint:
            return cfg_token_hint, None
        tok, terr = get_cfg_access_token()
        return (tok, terr) if tok else (None, terr or {"where": "get_cfg_access_token"})
    if t == "DEV":
        tok = get_access_token()
        if not tok:
            return None, {"where": "get_access_token", "error": "No DEV access token (set DEV_* credentials)"}
        return tok, None
    # generic
    tok, terr = get_access_token_for_env(target)
    return (tok, terr) if tok else (None, terr or {"where": "get_access_token_for_env"})


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def _assert_dev_base_or_error(conf: dict) -> tuple[bool, dict | None]:
    """
    Ensure DEV projection_base is set and not obviously pointing to CFG.
    Returns (ok, err). If ok=False, err is a dict you can bubble up.
    """
    base = (conf.get("projection_base") or "").strip()
    if not base:
        return False, {"where": "config", "error": "DEV projection_base is not configured (set DEV_BASE_ROOT or DEV_PROJECTION_BASE)"}
    host = _host_of(base)
    if "cfg." in host or host.endswith("-cfg.ifs.cloud") or "aagl-cfg" in host:
        return False, {"where": "config", "error": f"DEV projection_base points to CFG host: {host}"}
    return True, None


# ===================== DEV/CFG/Other-agnostic upload + actions =====================

def _upload_temp_lob_env(token: str, file_path: str, file_name: str, *, target: str, content_type: str = "application/octet-stream"):
    """
    Create a temp LOB via <projection_base>/PermissionSetHandling.svc/FndTempLobs
    and upload the file to BlobData (stream). Works for DEV/CFG/other envs.
    Returns: (lob_id, err)
    """
    c = _env_conf_for(target)
    verify = c["ssl_verify"]
    svc_base = f"{c['projection_base'].rstrip('/')}/PermissionSetHandling.svc"

    headers_json = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }
    headers_put = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": content_type,
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
        "If-Match": "*",  # stream updates/actions commonly require If-Match
    }

    def _post_create(payload: dict) -> tuple[str | None, dict | None]:
        url = f"{svc_base}/FndTempLobs"
        try:
            r = requests.post(url, json=payload, headers=headers_json, timeout=20, verify=verify)
            if r.status_code not in (200, 201):
                return None, {"step": "create", "status": r.status_code, "text": (r.text or "")[:900], "url": url}
            j = r.json() if r.content else {}
            lob_id = (j.get("LobId") or j.get("LOBID") or j.get("Id") or j.get("id"))
            if not lob_id:
                return None, {"step": "create", "status": r.status_code, "text": "Missing LobId", "url": url}
            return str(lob_id), None
        except requests.RequestException as e:
            return None, {"step": "create", "error": str(e), "url": url}

    # 1) Minimal insert (let DB assign everything)
    lob_id, err = _post_create({})
    if err and not lob_id:
        # 2) Seed with Default(), sanitize, then insert
        def_url = f"{svc_base}/FndTempLobs/IfsApp.PermissionSetHandling.FndTempLobStore_Default()"
        try:
            hdr_def = dict(headers_json); hdr_def["If-Match"] = "*"
            rd = requests.get(def_url, headers=hdr_def, timeout=15, verify=verify)
            if rd.status_code != 200:
                return None, {"step": "default", "status": rd.status_code, "text": (rd.text or "")[:700], "url": def_url}
            seed = rd.json() if rd.content else {}
        except requests.RequestException as e:
            return None, {"step": "default", "error": str(e), "url": def_url}

        # Strip any DB-managed/audit/metadata fields the server rejects
        def _sanitize_seed(s: dict) -> dict:
            if not isinstance(s, dict):
                return {}
            out = {}
            for k, v in s.items():
                if k.startswith("@"):
                    continue
                lk = k.lower()
                if (
                    lk.startswith("lob") or lk.startswith("obj") or lk.startswith("row") or
                    lk.startswith("created") or lk.startswith("modified") or
                    lk.startswith("blob") or lk.startswith("etag") or
                    "odata." in lk or "blobdata@odata" in lk or
                    lk in {"id", "lobid", "objid", "objversion", "rowkey", "rowversion", "rowstate"}
                ):
                    continue
                if isinstance(v, (str, int, float, bool)) or v is None:
                    out[k] = v
            return out

        payload = _sanitize_seed(seed)
        lob_id, err = _post_create(payload)
        if err or not lob_id:
            return None, err

    # 3) Upload the bytes to the BlobData stream
    put_url = f"{svc_base}/FndTempLobs(LobId='{lob_id}')/BlobData"
    try:
        with open(file_path, "rb") as fh:
            data = fh.read()
        r2 = requests.put(put_url, headers=headers_put, data=data, timeout=180, verify=verify)
        if r2.status_code not in (200, 201, 204):
            return None, {"step": "upload", "status": r2.status_code, "text": (r2.text or "")[:900], "url": put_url}
    except requests.RequestException as e:
        return None, {"step": "upload", "error": str(e), "url": put_url}

    return lob_id, None


def _import_start_env(token: str, *, target: str):
    c = _env_conf_for(target)
    base = c["projection_base"].rstrip("/")
    url = f"{base}/PermissionSetHandling.svc/ImportPermissionSetsVirtuals"
    try:
        r = requests.post(url, json={}, headers=_env_headers_for(token, target), timeout=30, verify=c["ssl_verify"])
        if r.status_code not in (200, 201):
            return None, {"status": r.status_code, "text": r.text[:500], "url": url}
        j = r.json() if r.content else {}
        objkey = None
        if isinstance(j, dict):
            for k in ("Objkey", "OBJKEY", "ObjectKey", "Id", "id"):
                if j.get(k):
                    objkey = str(j[k]); break
        if not objkey:
            return None, {"status": r.status_code, "text": "Missing Objkey", "url": url}
        return objkey, None
    except Exception as e:
        return None, {"error": str(e), "url": url}


def _import_create_file_record_env(token: str, objkey: str, file_name: str, lob_id: str, *, target: str):
    c = _env_conf_for(target)
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ImportPermissionSetsVirtual_CreateFileRecord"
    )
    headers = _env_headers_for(token, target)
    headers["If-Match"] = "*"
    payload = {"FileName": file_name, "LobId": lob_id}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=45, verify=c["ssl_verify"])
        if r.status_code not in (200, 201, 204):
            return False, {"status": r.status_code, "text": r.text[:800], "url": url}
        return True, None
    except Exception as e:
        return False, {"error": str(e), "url": url}


def _import_fetch_permission_set_info_env(token: str, objkey: str, *, target: str):
    c = _env_conf_for(target)
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ImportPermissionSetsVirtual_FetchPermissionSetInfo"
    )
    headers = _env_headers_for(token, target)
    headers["If-Match"] = "*"
    try:
        r = requests.post(url, json={}, headers=headers, timeout=60, verify=c["ssl_verify"])
        if r.status_code not in (200, 201, 204):
            return False, {"status": r.status_code, "text": r.text[:800], "url": url}
        return True, None
    except Exception as e:
        return False, {"error": str(e), "url": url}


def _import_finish_env(token: str, objkey: str, *, target: str, timeout: int = 60):
    c = _env_conf_for(target)
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ImportPermissionSetsVirtual_ImportFinish"
    )
    headers = _env_headers_for(token, target)
    headers["If-Match"] = "*"
    try:
        r = requests.post(url, json={}, headers=headers, timeout=timeout, verify=c.get("ssl_verify", True))
        if r.status_code in (200, 201, 204):
            return True, None
        return False, {"status": r.status_code, "text": (r.text or "")[:1000], "url": url}
    except requests.RequestException as e:
        return False, {"error": str(e), "url": url}


def _import_cleanup_env(token: str, objkey: str, *, target: str) -> bool:
    c = _env_conf_for(target)
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ImportPermissionSetsVirtual_CleanupVirtualEntity"
    )
    try:
        r = requests.post(url, json={}, headers=_env_headers_for(token, target), timeout=30, verify=c["ssl_verify"])
        return r.status_code in (200, 201, 204)
    except Exception:
        return False


# ===================== Public import entrypoints (env-aware; default DEV) =====================

def cfg_import_zip(cfg_token, zip_path, target_env: str = "DEV"):
    """
    ZIP import path. By default targets DEV for backward compatibility,
    but you can pass target_env (e.g., 'CFG', 'QA', 'UAT').
    """
    target = ((target_env or "DEV").strip().upper())

    token, terr = _env_token_for(target, cfg_token_hint=cfg_token)
    if terr or not token:
        return False, {"where": "token", **(terr or {})}

    conf = _env_conf_for(target)
    if target.upper() == "DEV":
        ok, err = _assert_dev_base_or_error(conf)
        if not ok:
            return False, err

    file_name = os.path.basename(zip_path)

    # Upload the ZIP as a temp LOB in the projection service
    lob_id, err = _upload_temp_lob_env(token, zip_path, file_name, target=target, content_type="application/zip")
    if err or not lob_id:
        return False, {"where": "upload_temp_lob", **(err or {})}

    # Create virtual row, attach file, preview, finish
    objkey, err = _import_start_env(token, target=target)
    if err or not objkey:
        return False, {"where": "import_start", **(err or {})}

    ok, err = _import_create_file_record_env(token, objkey, file_name, lob_id, target=target)
    if not ok:
        return False, {"where": "create_file_record", **(err or {})}

    ok, err = _import_fetch_permission_set_info_env(token, objkey, target=target)
    if not ok:
        return False, {"where": "fetch_permission_set_info", **(err or {})}

    ok, err = _import_finish_env(token, objkey, target=target)
    if not ok:
        return False, {"where": "import_finish", **(err or {})}

    try:
        _import_cleanup_env(token, objkey, target=target)
    except Exception:
        pass

    return True, None


def cfg_import_xmls(cfg_token, zip_path, target_env: str = "DEV"):
    """
    Import all permission-set XMLs from ZIP into target_env using the same call pattern
    the web app uses (no FndTempLobs). Defaults to DEV for backward compatibility.
    """
    target = ((target_env or "DEV").strip().upper())

    # Get token for the chosen target
    token, terr = _env_token_for(target, cfg_token_hint=cfg_token)
    if terr or not token:
        return False, {"where": "token", **(terr or {})}

    # Sanity: ensure DEV base doesn't point at CFG
    conf = _env_conf_for(target)
    if target.upper() == "DEV":
        ok, err = _assert_dev_base_or_error(conf)
        if not ok:
            return False, {"where": "config", **(err or {})}

    # 1) Create parent virtual
    objkey, err = _import_start_env(token, target=target)
    if err or not objkey:
        return False, {"where": "start", **(err or {})}

    # Prepare XMLs from ZIP
    try:
        import zipfile as _zipfile
        zf = _zipfile.ZipFile(zip_path)
        names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
        if not names:
            return False, {"where": "zip", "error": "No .xml files in archive"}
    except Exception as e:
        return False, {"where": "zip", "error": str(e)}

    for fname in names:
        try:
            xml_bytes = zf.read(fname)
        except Exception as e:
            return False, {"where": "read_xml", "file": fname, "error": str(e)}

        # 2) GET parent => ETag (like the browser does before each create)
        parent_etag, err = _import_get_parent_etag_env(token, objkey, target=target)
        if err or not parent_etag:
            return False, {"where": "parent_etag", "file": fname, **(err or {})}

        # 3) Create file record ({} with If-Match: <parent ETag>) => child Objkey
        child_objkey, err = _import_create_file_record_stream_env(token, objkey, parent_etag, target=target)
        if err or not child_objkey:
            return False, {"where": "create_file_record", "file": fname, **(err or {})}

        # 4) GET child => ETag
        child_etag, err = _import_get_child_etag_env(token, objkey, child_objkey, target=target)
        if err or not child_etag:
            return False, {"where": "child_etag", "file": fname, **(err or {})}

        # 5) PATCH child PermSetFile with raw XML
        ok, err = _import_upload_permset_stream_env(token, objkey, child_objkey, child_etag, xml_bytes, target=target)
        if not ok:
            return False, {"where": "upload_permset_file", "file": fname, **(err or {})}

        # 6) Preview/parse
        ok, err = _import_fetch_permission_set_info_env(token, objkey, target=target)
        if not ok:
            return False, {"where": "fetch_permission_set_info", "file": fname, **(err or {})}

    # 7) Finish the import batch
    ok, err = _import_finish_env(token, objkey, target=target)
    if not ok:
        return False, {"where": "import_finish", **(err or {})}

    # 8) Best-effort cleanup
    try:
        _import_cleanup_env(token, objkey, target=target)
    except Exception:
        pass

    return True, None


# --- group/user grant helpers ---

def grant_groups(role, grantees_str, token):
    """
    Grant role to user groups (DEV env).
    grantees_str: "GRP_A;GRP_B" or "GRP_A,GRP_B"
    """
    base = _dev_conf()["projection_base"]
    url = f"{base}/PermissionSetHandling.svc/GrantGroups"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"Role": role, "Grantees": grantees_str}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=30, verify=_dev_conf()["ssl_verify"])
        return r.status_code in (200, 201, 204)
    except Exception:
        return False


def grant_users(role, grantees_str, token):
    """
    Grant role to users (DEV env).
    grantees_str: "USR1;USR2" or "USR1,GRP2"
    """
    base = _dev_conf()["projection_base"]
    url = f"{base}/PermissionSetHandling.svc/GrantUsers"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"Role": role, "Grantees": grantees_str}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=30, verify=_dev_conf()["ssl_verify"])
        return r.status_code in (200, 201, 204)
    except Exception:
        return False


def fetch_lobby_title_via_psh(lobby_id, token):
    """
    Read a lobby page title via PermissionSetHandling.svc (DEV env).
    """
    base = _dev_conf()["projection_base"]
    url = f"{base}/PermissionSetHandling.svc/LobbyPages(Id='{lobby_id}')"
    headers = _std_headers(token)
    try:
        r = requests.get(url, headers=headers, timeout=12, verify=_dev_conf()["ssl_verify"])
        if r.status_code == 200:
            j = r.json() if r.content else {}
            title = j.get("Title") or j.get("title") or j.get("Name") or j.get("DisplayName")
            if isinstance(title, str) and title.strip():
                return title.strip()
    except Exception:
        pass
    return None


def fetch_lobby_title_via_lobbyconfig(lobby_id, token):
    """
    Try LobbyConfig.svc to resolve a lobby title (DEV env).
    Checks both Lobbies and LobbyPages entity sets.
    """
    base = _dev_conf()["projection_base"]
    headers = _std_headers(token)

    # Try Lobbies first
    try:
        url = f"{base}/LobbyConfig.svc/Lobbies?$filter=LobbyId eq guid'{lobby_id}'&$select=Title"
        r = requests.get(url, headers=headers, timeout=12, verify=_dev_conf()["ssl_verify"])
        if r.status_code == 200:
            j = r.json() if r.content else {}
            items = j.get("value") if isinstance(j, dict) else None
            if isinstance(items, list) and items:
                t = items[0].get("Title")
                if isinstance(t, str) and t.strip():
                    return t.strip()
    except Exception:
        pass

    # Fallback: LobbyPages
    try:
        url = f"{base}/LobbyConfig.svc/LobbyPages?$filter=LobbyId eq guid'{lobby_id}'&$select=Title"
        r = requests.get(url, headers=headers, timeout=12, verify=_dev_conf()["ssl_verify"])
        if r.status_code == 200:
            j = r.json() if r.content else {}
            items = j.get("value") if isinstance(j, dict) else None
            if isinstance(items, list) and items:
                t = items[0].get("Title")
                if isinstance(t, str) and t.strip():
                    return t.strip()
    except Exception:
        pass

    return None


def grant_bpas(key, role, token):
    """
    Grant a BPA (business process) to a role in the DEV env.
    """
    base = _dev_conf()["projection_base"]
    url = f"{base}/PermissionSetHandling.svc/GrantBpas"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"Bpas": f"ID={key}", "Role": role}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=30, verify=_dev_conf()["ssl_verify"])
        return r.status_code in (200, 201, 204)
    except Exception:
        return False


# ===================== Stream-upload helpers for XML import (browser-matching) =====================

def _resp_etag(resp) -> str | None:
    # Return W/"..." value if present
    for k, v in resp.headers.items():
        if k.lower() == "etag":
            return v
    return None


def _import_get_parent_etag_env(token: str, objkey: str, *, target: str):
    c = _env_conf_for(target)
    base = c["projection_base"].rstrip("/")
    url = f"{base}/PermissionSetHandling.svc/ImportPermissionSetsVirtuals(Objkey='{objkey}')"
    hdr = _env_headers_for(token, target).copy()
    hdr["Accept"] = "application/json;odata.metadata=full;IEEE754Compatible=true"
    r = requests.get(url, headers=hdr, timeout=30, verify=c["ssl_verify"])
    if r.status_code != 200:
        return None, {"status": r.status_code, "text": (r.text or "")[:800], "url": url}
    return _resp_etag(r), None


def _import_create_file_record_stream_env(token: str, parent_objkey: str, parent_etag: str, *, target: str):
    """
    Mirrors the browser: POST {} with If-Match: <parent ETag> to create a child file record.
    Returns the child Objkey.
    """
    c = _env_conf_for(target)
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{parent_objkey}')/"
        "IfsApp.PermissionSetHandling.ImportPermissionSetsVirtual_CreateFileRecord"
    )
    hdr = _env_headers_for(token, target).copy()
    hdr["If-Match"] = parent_etag or "*"
    hdr["Accept"] = "application/json;odata.metadata=full;IEEE754Compatible=true"
    r = requests.post(url, json={}, headers=hdr, timeout=60, verify=c["ssl_verify"])
    if r.status_code not in (200, 201):
        return None, {"status": r.status_code, "text": (r.text or "")[:900], "url": url}
    j = r.json() if r.content else {}
    child = (j.get("Objkey") or j.get("OBJKEY") or j.get("Id") or j.get("id"))
    if not child:
        return None, {"status": r.status_code, "text": "Missing child Objkey", "url": url}
    return str(child), None


def _import_get_child_etag_env(token: str, parent_objkey: str, child_objkey: str, *, target: str):
    c = _env_conf_for(target)
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{parent_objkey}')/"
        f"PermissionSetsToImport(Objkey='{child_objkey}')?$select=PermSetFile"
    )
    hdr = _env_headers_for(token, target).copy()
    hdr["Accept"] = "application/json;odata.metadata=full;IEEE754Compatible=true"
    r = requests.get(url, headers=hdr, timeout=30, verify=c["ssl_verify"])
    if r.status_code != 200:
        return None, {"status": r.status_code, "text": (r.text or "")[:900], "url": url}
    return _resp_etag(r), None


def _import_upload_permset_stream_env(token: str, parent_objkey: str, child_objkey: str, child_etag: str, xml_bytes: bytes, *, target: str):
    """
    PATCH the stream property with raw bytes: Content-Type: application/octet-stream,
    If-Match: <child ETag>
    """
    c = _env_conf_for(target)
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ImportPermissionSetsVirtuals(Objkey='{parent_objkey}')/"
        f"PermissionSetsToImport(Objkey='{child_objkey}')/PermSetFile"
    )
    hdr = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/octet-stream",
        "If-Match": child_etag or "*",
    }
    r = requests.patch(url, data=xml_bytes, headers=hdr, timeout=180, verify=c["ssl_verify"])
    if r.status_code not in (200, 204):
        return False, {"status": r.status_code, "text": (r.text or "")[:900], "url": url}
    return True, None

# ===================== Convenience wrappers & orchestrators =====================

def delivery_path(version_id: str) -> str:
    """
    Absolute path to a delivery ZIP that finalize_export() wrote.
    """
    return os.path.join(DELIVERY_DIR, f"{version_id}.zip")


def export_roles_to_zip(roles: list[str], *, include_user_grants: bool = True, include_group_grants: bool = False) -> tuple[Optional[str], Optional[dict]]:
    """
    High-level helper:
      1) Get DEV token
      2) Start an export
      3) Finalize & write ZIP into deliveries/ (returns <version_id>)
    """
    tok = get_access_token()
    if not tok:
        return None, {"where": "token", "error": "No DEV access token (set DEV_* credentials)"}

    conf = _dev_conf()
    ok, err = _assert_dev_base_or_error(conf)
    if not ok:
        return None, {"where": "config", **(err or {})}

    objkey, err = export_permission_start(tok)
    if err or not objkey:
        return None, {"where": "export_start", **(err or {})}

    version_id, err = finalize_export(
        tok,
        objkey,
        roles,
        user_grants=include_user_grants,
        user_group_grants=include_group_grants,
    )
    if err or not version_id:
        return None, {"where": "finalize_export", **(err or {})}

    return version_id, None


def list_xmls_in_zip(zip_path: str) -> list[str]:
    """
    Return a sorted list of XML file names present in a permission-set ZIP.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = [os.path.basename(n) for n in zf.namelist() if n.lower().endswith(".xml")]
            return sorted({n for n in names if n})
    except Exception:
        return []


def roles_from_xml(xml_bytes: bytes) -> list[str]:
    """
    Best-effort parse of a permission set XML payload to extract role names.
    The XML structures vary; we try common patterns:
      - <PermissionSet Id="ROLE"/>
      - <PermissionSet Role="ROLE"/>
      - Elements named Role/ROLE whose text is the role name
    """
    roles: set[str] = set()
    try:
        root = ET.fromstring(xml_bytes)
    except Exception:
        return []

    # Attribute-based
    for ps in root.iter():
        tag = ps.tag.lower().split("}")[-1]
        if tag in {"permissionset", "permission-set", "permission_set"}:
            for attr in ("Id", "ID", "Role", "ROLE", "Name", "NAME"):
                v = ps.attrib.get(attr) or ps.attrib.get(attr.lower())
                if isinstance(v, str) and v.strip():
                    roles.add(v.strip())

    # Text-based fallbacks
    for el in root.iter():
        tag = el.tag.lower().split("}")[-1]
        if tag in {"role", "permissionrole", "permissionsetname"}:
            txt = (el.text or "").strip()
            if txt:
                roles.add(txt)

    return sorted(roles)


def collect_roles_from_zip(zip_path: str) -> list[str]:
    """
    Aggregate unique role names from all XMLs in a ZIP.
    """
    out: set[str] = set()
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                if not name.lower().endswith(".xml"):
                    continue
                try:
                    data = zf.read(name)
                    for r in roles_from_xml(data):
                        out.add(r)
                except Exception:
                    # Skip unreadable files
                    continue
    except Exception:
        return []
    return sorted(out)


def export_and_import(
    roles: list[str],
    *,
    target_env: str = "DEV",
    include_user_grants: bool = True,
    include_group_grants: bool = False,
    import_mode: str = "xmls",
    cfg_token: Optional[str] = None,
) -> tuple[bool, Optional[dict]]:
    """
    One-shot: export the specified roles from DEV to deliveries/, then import into target_env.

    Parameters
    ----------
    roles : list[str]
        Role names to export.
    target_env : str
        Where to import (default 'DEV'; can be 'CFG', 'QA', 'UAT', etc. Must exist in settings).
    include_user_grants : bool
        Include user-level grants in the export.
    include_group_grants : bool
        Include group-level grants in the export.
    import_mode : str
        'xmls' (default) to stream each XML like the browser does,
        or 'zip' to upload the ZIP as a single temp LOB and let the server process it.
    cfg_token : Optional[str]
        Optional token to use when target_env='CFG'. If not provided, we'll fetch one.

    Returns
    -------
    (ok, err) where ok is True/False and err is a dict on failure.
    """
    if not roles:
        return False, {"where": "input", "error": "No roles provided"}

    version_id, err = export_roles_to_zip(
        roles,
        include_user_grants=include_user_grants,
        include_group_grants=include_group_grants,
    )
    if err or not version_id:
        return False, {"where": "export", **(err or {})}

    zpath = delivery_path(version_id)
    if not os.path.exists(zpath):
        return False, {"where": "export", "error": f"Delivery ZIP not found: {zpath}"}

    mode = (import_mode or "xmls").lower()
    if mode not in {"xmls", "zip"}:
        mode = "xmls"

    if mode == "xmls":
        ok, ierr = cfg_import_xmls(cfg_token, zpath, target_env=target_env)
    else:
        ok, ierr = cfg_import_zip(cfg_token, zpath, target_env=target_env)

    if not ok:
        return False, {"where": "import", **(ierr or {})}

    return True, None


def resolve_lobby_title(lobby_id: str, token: str) -> Optional[str]:
    """
    Try both PermissionSetHandling.svc and LobbyConfig.svc to resolve a lobby page title (DEV env).
    """
    t = fetch_lobby_title_via_psh(lobby_id, token)
    if t:
        return t
    return fetch_lobby_title_via_lobbyconfig(lobby_id, token)


# Public surface (optional)
__all__ = [
    # config/env helpers
    "_dev_conf", "_cfg_conf", "_generic_env_conf",
    "get_access_token", "get_cfg_access_token", "get_access_token_for_env",
    "_env_conf_for", "_env_headers_for", "_env_token_for",
    # preview & readers
    "preview_permission_sets", "check_permission_set_exists",
    "fetch_permission_sets", "fetch_users_page", "fetch_user_groups_page",
    # export
    "export_permission_start", "export_permission_update_list",
    "export_permission_create_export", "export_permission_get_zip",
    "finalize_export", "export_roles_to_zip", "version_name",
    "delivery_path", "list_xmls_in_zip", "collect_roles_from_zip",
    # import (CFG/DEV/Other aware)
    "cfg_import_zip", "cfg_import_xmls", "export_backup_zip_for_replace_roles",
    # grants & lookups
    "grant_projection", "grant_read_only", "grant_lobby_page",
    "fetch_lobby_title_via_psh", "fetch_lobby_title_via_lobbyconfig", "resolve_lobby_title",
    "grant_groups", "grant_users", "grant_bpas",
    # orchestrator
    "export_and_import",
]


# ... keep everything that’s already in this file ...

# ===================== Command-level grants (Projection actions) =====================

# --- add near your other imports ---
import json

# ... keep all your existing code ...


# ===================== Command-level grants (after role create/update) =====================

def _psh_base() -> str:
    # DEV env (export side). The command grant assistant lives here.
    return _dev_conf()["projection_base"].rstrip("/") + "/PermissionSetHandling.svc"


def _json_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }


def grant_projection_commands(role: str, projection: str, commands: list[str], client: str = None):
    """
    Use the assistant the way the official API describes:
      SetAllProjectionActionsToRevoke -> SelectCommands -> ApplyChanges
    All posts carry If-Match with the latest ETag.

    Returns (ok, info_or_error)
    """
    import requests

    if not role or not projection or not isinstance(commands, list):
        return False, "missing role/projection/commands"

    desired = {c.strip() for c in (commands or []) if isinstance(c, str) and c.strip()}

    tok = get_access_token()
    if not tok:
        return False, "no token"

    conf = _dev_conf()
    base = conf["projection_base"].rstrip("/") + "/PermissionSetHandling.svc"
    verify = conf.get("ssl_verify", True)

    # Browser-like headers required by your OpenAPI (note: IEEE754 & metadata=full)
    H = {
        "Authorization": f"Bearer {tok}",
        "Accept": "application/json;odata.metadata=full;IEEE754Compatible=true",
        "Content-Type": "application/json;IEEE754Compatible=true",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }

    # 1) Create assistant
    create_url = f"{base}/ManageGrantsByCommandAssistantVirtuals"
    r = requests.post(create_url, json={"Role": role, "ProjectionName": projection}, headers=H, timeout=30, verify=verify)
    if r.status_code not in (200, 201, 204):
        return False, {"where": "create_assistant", "status": r.status_code, "text": (r.text or "")[:1000]}

    j = r.json() if r.content else {}
    objkey = (j.get("Objkey") or j.get("objkey") or "").strip()
    if not objkey:
        return False, {"where": "create_assistant", "error": "missing Objkey"}

    # OData string key needs single quotes doubled
    objkey_sql = objkey.replace("'", "''")
    entity_url = f"{base}/ManageGrantsByCommandAssistantVirtuals(Objkey='{objkey_sql}')"
    if not objkey or not entity_url:
        return False, {"where": "create_assistant", "error": "missing Objkey"}

    # Helper: GET to capture current ETag (required by your OpenAPI on actions)
    def get_etag():
        g = requests.get(entity_url, headers=H, timeout=30, verify=verify)
        if g.status_code != 200:
            return None, {"where": "get_assistant", "status": g.status_code, "text": (g.text or "")[:800]}
        return g.headers.get("ETag") or g.headers.get("Etag") or g.headers.get("etag"), None

    etag, err = get_etag()
    if err:
        return False, err

    def with_if_match(h, et):
        hh = dict(h)
        if et:
            hh["If-Match"] = et
        return hh

    # 2) **Mark ALL actions for revoke** (this is the key step you were missing)
    set_all_revoke_variants = [
        "ManageGrantsByCommandAssistantVirtual_SetAllProjectionActionsToRevoke",  # shown in your OpenAPI
        # keep a couple of fallbacks seen on some tenants:
        "ManageGrantsByCommandAssistantVirtual_SetAllToRevoke",
        "ManageGrantsByCommandAssistantVirtual_SetAllActionsToRevoke",
    ]
    last = None
    for action in set_all_revoke_variants:
        url = f"{entity_url}/IfsApp.PermissionSetHandling.{action}"
        last = requests.post(url, json={}, headers=with_if_match(H, etag), timeout=30, verify=verify)
        if 200 <= last.status_code < 300:
            etag = last.headers.get("ETag") or etag  # refresh if server sends a new one
            break
    else:
        return False, {"where": "set_all_to_revoke", "status": last.status_code if last else None, "text": (getattr(last, "text", "") or "")[:1200]}

    # 3) Read command->client mapping from server
    q_proj = projection.replace("'", "''")
    ref_url = f"{base}/Reference_ActionCommand?$select=Command,Client&$filter=ProjectionName eq '{q_proj}'"
    rr = requests.get(ref_url, headers=H, timeout=30, verify=verify)
    if rr.status_code != 200:
        return False, {"where": "read_ref_commands", "status": rr.status_code, "text": (rr.text or "")[:1000]}
    rows = (rr.json() or {}).get("value", [])
    cmd_to_clients = {}
    all_cmds = set()
    for row in rows:
        cmd = (row.get("Command") or "").strip()
        cli = (row.get("Client") or "").strip()
        if not cmd:
            continue
        all_cmds.add(cmd)
        cmd_to_clients.setdefault(cmd, [])
        if cli and cli not in cmd_to_clients[cmd]:
            cmd_to_clients[cmd].append(cli)

    missing = sorted([c for c in desired if c not in cmd_to_clients])
    if missing:
        return False, {"where": "select_commands", "error": "commands not found for projection", "projection": projection, "missing": missing}

    def choose_client_for(cmd: str) -> str | None:
        clients = cmd_to_clients.get(cmd, [])
        if client and client in clients:
            return client
        if "web" in clients:
            return "web"
        return clients[0] if clients else client

    grant_pairs = []
    for ccmd in desired:
        ch = choose_client_for(ccmd)
        if not ch:
            return False, {"where": "select_commands", "error": f"no client for command {ccmd}"}
        grant_pairs.append((ch, ccmd))

    selection_grant = ";".join(f"CLIENT={cl}^COMMAND={cmd}^PROJECTION_NAME={projection}^" for (cl, cmd) in grant_pairs)

    # 4) Select the desired commands to GRANT back
    sel_url = f"{entity_url}/IfsApp.PermissionSetHandling.ManageGrantsByCommandAssistantVirtual_SelectCommands"
    rg = requests.post(sel_url, json={"Selection": selection_grant}, headers=with_if_match(H, etag), timeout=30, verify=verify)
    if not (200 <= rg.status_code < 300):
        return False, {"where": "select_commands", "status": rg.status_code, "text": (rg.text or "")[:1500]}
    etag = rg.headers.get("ETag") or etag

    # 5) ApplyChanges (commits both grants & revokes)
    apply_url = f"{entity_url}/IfsApp.PermissionSetHandling.ManageGrantsByCommandAssistantVirtual_ApplyChanges"
    ra = requests.post(apply_url, json={}, headers=with_if_match(H, etag), timeout=30, verify=verify)
    if not (200 <= ra.status_code < 300):
        return False, {"where": "apply_changes", "status": ra.status_code, "text": (ra.text or "")[:1200]}

    return True, {
        "role": role,
        "projection": projection,
        "granted": sorted(desired),
        "revoked": sorted(all_cmds - desired),  # FYI
        "pairs_grant": grant_pairs,
    }



def grant_projection_commands_batch(role: str, items: list[dict]) -> list[dict]:
    """
    Batch convenience: items = [{projection, commands:[...], client:'web'|'aurena'|...}, ...]
    Returns per-item results:
      {
        "projection": str,
        "ok": bool,
        "details": dict|None,   # details on success
        "error": dict|str|None  # error info on failure
      }
    """
    out = []
    for it in (items or []):
        proj = (it.get("projection") or "").strip()
        cmds = it.get("commands") or []
        client = (it.get("client") or "web").strip() or "web"

        if not proj or not cmds:
            out.append({
                "projection": proj,
                "ok": False,
                "details": None,
                "error": {"where": "input", "error": "missing projection/commands"}
            })
            continue

        ok, info = grant_projection_commands(role, proj, cmds, client=client)
        out.append({
            "projection": proj,
            "ok": ok,
            "details": info if ok else None,
            "error": None if ok else info
        })
    return out



def apply_command_grants_after_role_create(role: str, command_grants_json: str | dict) -> tuple[bool, list[dict]]:
    """
    Helper you can call at the end of your role create/update handler:
      - role: the final role name
      - command_grants_json: JSON string or dict with shape:
            {"items":[{"projection":"X","commands":["A","B"],"client":"web"}, ...]}

    Returns (ok_overall, results).
    """
    try:
        data = json.loads(command_grants_json) if isinstance(command_grants_json, str) else (command_grants_json or {})
    except Exception:
        data = {}
    items = data.get("items") or []
    results = grant_projection_commands_batch(role, items)
    ok_overall = all(r.get("ok") for r in results)
    return ok_overall, results

# --- NEW: env-aware role reader ---
def fetch_permission_sets_env(env_name: str = "CFG", top: int = 200, q: str | None = None):
    """
    Read PermissionSets from the given env (default: active CFG).
    Returns (roles, err) where roles=[{role, description}], err=None or dict
    """
    name = (env_name or "CFG").upper()

    # pick conf + token per env
    if name == "CFG":
        conf = _cfg_conf()
        tok, terr = get_cfg_access_token()
        if not tok:
            return [], terr or {"where": "token", "error": "CFG token failed"}
        headers = _std_headers_for_cfg(tok)
    elif name == "DEV":
        conf = _dev_conf()
        tok = get_access_token()
        if not tok:
            return [], {"where": "token", "error": "DEV token failed"}
        headers = _std_headers(tok)
    else:
        conf = _generic_env_conf(name)
        tok, terr = get_access_token_for_env(name)
        if not tok:
            return [], terr or {"where": "token", "error": f"{name} token failed"}
        headers = _std_headers(tok)

    base = f"{conf['projection_base']}/PermissionSetHandling.svc/PermissionSets"
    params = [f"$top={int(top)}", "$select=Role,Description", "$orderby=Role"]
    if q:
        q_safe = q.replace("'", "''")
        params.append(f"$filter=startswith(Role,'{q_safe}')")
    url = f"{base}?{'&'.join(params)}"

    try:
        r = requests.get(url, headers=headers, timeout=30, verify=conf.get("ssl_verify", True))
        if r.status_code != 200:
            return [], {"status": r.status_code, "text": (r.text or "")[:500], "url": url}
        data = r.json()
        items = data.get("value") if isinstance(data, dict) else []
        roles = []
        for it in items or []:
            role = it.get("Role") or it.get("ROLE") or it.get("Id") or it.get("ID")
            desc = it.get("Description") or it.get("DESC") or ""
            if role:
                roles.append({"role": str(role), "description": str(desc)})
        roles.sort(key=lambda x: x["role"].lower())
        return roles, None
    except Exception as e:
        return [], {"error": str(e), "url": url}


# ===== add near your other env-agnostic helpers =====

def export_permission_start_env(token: str, source_env: str) -> tuple[str | None, dict | None]:
    c = _env_conf_for(source_env)
    base = c["projection_base"].rstrip("/")
    url = f"{base}/PermissionSetHandling.svc/ExportPermissionSetVirtuals"
    try:
        r = requests.post(url, json={}, headers=_env_headers_for(token, source_env), timeout=30, verify=c["ssl_verify"])
        if r.status_code not in (200, 201):
            return None, {"status": r.status_code, "text": (r.text or "")[:500], "url": url}
        j = r.json() if r.content else {}
        objkey = None
        if isinstance(j, dict):
            for k in ("Objkey", "OBJKEY", "ObjectKey", "Id", "id"):
                if j.get(k): objkey = str(j[k]); break
        return (objkey, None) if objkey else (None, {"status": r.status_code, "text": "Missing Objkey", "url": url})
    except requests.exceptions.RequestException as e:
        return None, {"error": str(e), "url": url}


# app/services/ifs.py

def export_permission_update_list_env(token: str, objkey: str, roles: list[str], source_env: str) -> tuple[bool, dict | None]:
    """
    Update the selection for the current ExportPermissionSetVirtuals object.
    NOTE: Selection must be a single string in the format: 'ROLE=<r1>^;ROLE=<r2>^;...'
    """
    # Build the selection string exactly like the working DEV path
    sel = ";".join([f"ROLE={r}^" for r in (roles or [])])

    c = _env_conf_for(source_env)
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ExportPermissionSetVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ExportPermissionSetVirtual_UpdateExportList"
    )
    headers = _env_headers_for(token, source_env)
    payload = {"Selection": sel, "ParentObjkeyExport": objkey}

    try:
        r = requests.post(
            url, json=payload, headers=headers, timeout=45, verify=c.get("ssl_verify", True)
        )
        ok = r.status_code in (200, 201, 204)
        return (ok, None) if ok else (False, {
            "status": r.status_code,
            "text": (r.text or "")[:600],
            "url": url
        })
    except requests.exceptions.RequestException as e:
        return False, {"error": str(e), "url": url}



def export_permission_create_export_env(token: str, objkey: str, source_env: str, *, user_grants=True, user_group_grants=False) -> tuple[bool, dict | None]:
    c = _env_conf_for(source_env)
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ExportPermissionSetVirtuals(Objkey='{objkey}')/"
        "IfsApp.PermissionSetHandling.ExportPermissionSetVirtual_CreateExport"
    )
    headers = _env_headers_for(token, source_env)
    payload = {"UserGrants": bool(user_grants), "UserGroupGrants": bool(user_group_grants)}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=45, verify=c["ssl_verify"])
        return (r.status_code in (200, 201, 204), None) if r.status_code in (200, 201, 204) else (False, {"status": r.status_code, "text": (r.text or "")[:500], "url": url})
    except requests.exceptions.RequestException as e:
        return False, {"error": str(e), "url": url}


def export_permission_get_zip_env(token: str, objkey: str, source_env: str) -> tuple[str | None, dict | None]:
    c = _env_conf_for(source_env)
    base = c["projection_base"].rstrip("/")
    url = (
        f"{base}/PermissionSetHandling.svc/"
        f"ExportPermissionSetVirtuals(Objkey='{objkey}')/ZipFile"
    )
    headers = _env_headers_for(token, source_env)
    try:
        r = requests.get(url, headers=headers, timeout=60, verify=c["ssl_verify"])
        if r.status_code != 200:
            return None, {"status": r.status_code, "text": (r.text or "")[:500], "url": url}
        repo = os.path.join(BASE_DIR, "tmp_repo")
        os.makedirs(repo, exist_ok=True)
        path = os.path.join(repo, f"{objkey}.zip")
        with open(path, "wb") as f:
            f.write(r.content)
        return path, None
    except requests.exceptions.RequestException as e:
        return None, {"error": str(e), "url": url}


def finalize_export_env(token: str, objkey: str, roles: list[str], source_env: str, *, user_grants=True, user_group_grants=False) -> tuple[str | None, dict | None]:
    ok, err = export_permission_update_list_env(token, objkey, roles, source_env)
    if not ok:
        return None, {"where": "update_list", **(err or {})}
    ok, err = export_permission_create_export_env(token, objkey, source_env, user_grants=user_grants, user_group_grants=user_group_grants)
    if not ok:
        return None, {"where": "create_export", **(err or {})}
    path, err = export_permission_get_zip_env(token, objkey, source_env)
    if err or not path:
        return None, {"where": "get_zip", **(err or {})}

    # NEW: name the final artifact as pw_YYMMDD_HHMMSS.zip (not objkey.zip)
    new_version_id = _make_pw_version_id("pw")
    final_path = os.path.join(DELIVERY_DIR, f"{new_version_id}.zip")
    try:
        if os.path.abspath(path) != os.path.abspath(final_path):
            if os.path.exists(final_path):
                os.remove(final_path)
            os.replace(path, final_path)
    except Exception as e:
        return None, {"where": "rename_zip", "error": str(e)}

    return new_version_id, None

def export_backup_zip_for_replace_roles(target_env: str, roles: list[str], backup_version_id: str) -> tuple[bool, dict | None]:
    """
    Export the given roles FROM the target_env (the destination) into deliveries/backup/<version>.zip.
    Only the provided roles are exported (so the ZIP contains exactly the 'replace' XMLs).

    Returns (ok, {path: ...}|err)
    """
    roles = [r for r in (roles or []) if isinstance(r, str) and r.strip()]
    if not roles:
        return True, {"path": None, "note": "no roles to backup"}

    target = (target_env or "DEV").strip().upper()

    # Token for the target
    tok, terr = _env_token_for(target, cfg_token_hint=None)
    if terr or not tok:
        return False, {"where": "token", **(terr or {})}

    # Start export in the TARGET env
    objkey, err = export_permission_start_env(tok, target)
    if err or not objkey:
        return False, {"where": "export_start", **(err or {})}

    ok, err = export_permission_update_list_env(tok, objkey, roles, target)
    if not ok:
        return False, {"where": "update_list", **(err or {})}

    ok, err = export_permission_create_export_env(tok, objkey, target, user_grants=True, user_group_grants=False)
    if not ok:
        return False, {"where": "create_export", **(err or {})}

    tmp_zip, err = export_permission_get_zip_env(tok, objkey, target)
    if err or not tmp_zip:
        return False, {"where": "get_zip", **(err or {})}

    # Save as deliveries/backup/<version>.zip
    backup_dir = os.path.join(DELIVERY_DIR, "backup")
    os.makedirs(backup_dir, exist_ok=True)
    dest = os.path.join(backup_dir, f"{backup_version_id}.zip")
    try:
        if os.path.exists(dest):
            os.remove(dest)
        os.replace(tmp_zip, dest)
    except Exception as e:
        return False, {"where": "backup_rename", "error": str(e)}

    return True, {"path": dest}
