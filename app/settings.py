# app/settings.py
import os
import json
import threading
from typing import Dict, Any, Optional

# ---------------- Paths ----------------
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
SETTINGS_PATH = os.path.join(INSTANCE_DIR, "ifs_settings.json")

_lock = threading.Lock()

# ----------- defaults & helpers -----------

DEFAULT_ENV_NAMES = ("CFG", "DEV", "PROD")

DEFAULT_ENV_SHAPE = {
    # generic keys (UI)
    "base_root": "",
    "realm": "",
    "client_id": "",
    "client_secret": "",
    "scope": "openid microprofile-jwt",
    "ssl_verify": True,
    "odata_prefix": "",
    "fndtemplobs_url": "",
    "token_url": "",

    # backward compatible aliases the UI might send
    "cfg_base_root": "",
    "cfg_realm": "",
    "cfg_client_id": "",
    "cfg_client_secret": "",
    "cfg_scope": "openid microprofile-jwt",
    "cfg_ssl_verify": True,
    "cfg_odata_prefix": "",
    "cfg_fndtemplobs_url": "",
    "cfg_token_url": "",
}

DEFAULT_ROOT = {
    "environments": {
        "CFG": {**DEFAULT_ENV_SHAPE},
        "DEV": {**DEFAULT_ENV_SHAPE},
        "PROD": {**DEFAULT_ENV_SHAPE},
    },
    # Track “active” roles to avoid breaking existing logic
    "active_env": "CFG",          # used by UI
    "active_export_env": "DEV",   # where we export from (roles list, deliveries)
    "active_import_env": "CFG",   # where we import to (CFG)
    # New: default env (user selection)
    "default_env": "CFG"
}


def _read() -> Dict[str, Any]:
    with _lock:
        if not os.path.exists(SETTINGS_PATH):
            _write(DEFAULT_ROOT)
            return json.loads(json.dumps(DEFAULT_ROOT))
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
        # bootstrap missing keys safely
        data.setdefault("environments", {})
        for name in DEFAULT_ENV_NAMES:
            data["environments"].setdefault(name, {**DEFAULT_ENV_SHAPE})
        data.setdefault("active_env", "CFG")
        data.setdefault("active_export_env", "DEV")
        data.setdefault("active_import_env", "CFG")
        data.setdefault("default_env", "CFG")
        return data


def _write(payload: Dict[str, Any]) -> None:
    with _lock:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)


def _normalize_env_block(block: Dict[str, Any]) -> Dict[str, Any]:
    """Accepts either cfg_* keys or plain keys, normalizes and mirrors both ways."""
    out = {**DEFAULT_ENV_SHAPE}

    def pick(d: Dict[str, Any], *keys, default=None):
        for k in keys:
            if k in d and d[k] not in (None, ""):
                return d[k]
        return default

    # normalize
    base_root = pick(block, "base_root", "cfg_base_root", default="")
    if base_root:
        base_root = str(base_root).rstrip("/") + "/"

    out["base_root"] = base_root
    out["cfg_base_root"] = base_root

    realm = pick(block, "realm", "cfg_realm", default="")
    out["realm"] = realm
    out["cfg_realm"] = realm

    client_id = pick(block, "client_id", "cfg_client_id", default="")
    out["client_id"] = client_id
    out["cfg_client_id"] = client_id

    client_secret = pick(block, "client_secret", "cfg_client_secret", default="")
    out["client_secret"] = client_secret
    out["cfg_client_secret"] = client_secret

    scope = pick(block, "scope", "cfg_scope", default="openid microprofile-jwt") or "openid microprofile-jwt"
    out["scope"] = scope
    out["cfg_scope"] = scope

    ssl_verify = pick(block, "ssl_verify", "cfg_ssl_verify", default=True)
    out["ssl_verify"] = bool(ssl_verify)
    out["cfg_ssl_verify"] = bool(ssl_verify)

    odata_prefix = pick(block, "odata_prefix", "cfg_odata_prefix", default="")
    out["odata_prefix"] = str(odata_prefix or "").strip()
    out["cfg_odata_prefix"] = out["odata_prefix"]

    fnd = pick(block, "fndtemplobs_url", "cfg_fndtemplobs_url", default="")
    out["fndtemplobs_url"] = str(fnd or "").rstrip("/")
    out["cfg_fndtemplobs_url"] = out["fndtemplobs_url"]

    token_url = pick(block, "token_url", "cfg_token_url", default="")
    out["token_url"] = str(token_url or "").strip()
    out["cfg_token_url"] = out["token_url"]

    return out


# ----------------- Public API used by views/services -----------------

def list_envs_full() -> Dict[str, Any]:
    """Return the entire shape the UI expects."""
    data = _read()
    return {
        "active_env": data.get("active_env"),
        "active_export_env": data.get("active_export_env"),
        "active_import_env": data.get("active_import_env"),
        "default_env": data.get("default_env"),
        "environments": data.get("environments", {}),
    }


def list_envs() -> Dict[str, Dict[str, Any]]:
    return list_envs_full().get("environments", {})


def get_env(name: str) -> Optional[Dict[str, Any]]:
    data = _read()
    env = data.get("environments", {}).get(name)
    return _normalize_env_block(env or {}) if env else None


def create_or_update_env(name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    name = (name or "").strip()
    if not name:
        raise ValueError("blank name")
    data = _read()
    block = data["environments"].get(name, {**DEFAULT_ENV_SHAPE})
    block.update(payload or {})
    block = _normalize_env_block(block)
    data["environments"][name] = block
    # if this env did not exist previously and we have no default, set default to first created
    if name not in DEFAULT_ENV_NAMES and not data.get("default_env"):
        data["default_env"] = name
    _write(data)
    return block


def delete_env(name: str) -> bool:
    data = _read()
    envs = data.get("environments", {})
    if name in envs:
        del envs[name]
        # clean references
        if data.get("active_env") == name:
            data["active_env"] = "CFG"
        if data.get("active_export_env") == name:
            data["active_export_env"] = "DEV"
        if data.get("active_import_env") == name:
            data["active_import_env"] = "CFG"
        if data.get("default_env") == name:
            data["default_env"] = "CFG"
        _write(data)
        return True
    return False


def set_active(which: str, name: str) -> Dict[str, str]:
    """which: 'all' | 'export' | 'import' | 'ui'"""
    data = _read()
    if name not in data.get("environments", {}):
        raise KeyError("environment not found")

    if which == "all":
        data["active_env"] = name
        data["active_export_env"] = name
        data["active_import_env"] = name
    elif which == "export":
        data["active_export_env"] = name
    elif which == "import":
        data["active_import_env"] = name
    elif which == "ui":
        data["active_env"] = name
    else:
        raise KeyError("invalid selector")

    _write(data)
    return {
        "active_env": data["active_env"],
        "active_export_env": data["active_export_env"],
        "active_import_env": data["active_import_env"],
    }


def set_default(name: str) -> Dict[str, Any]:
    """
    Marks 'name' as the default environment, and also sets it as active
    for both export/import to keep existing logic functioning.
    """
    data = _read()
    if name not in data.get("environments", {}):
        raise KeyError("environment not found")
    data["default_env"] = name
    # keep rest of app working without changes: default also becomes active
    data["active_env"] = name
    data["active_export_env"] = name
    data["active_import_env"] = name
    _write(data)
    return {
        "default_env": name,
        "active_env": name,
        "active_export_env": name,
        "active_import_env": name,
    }


def get_default_name() -> str:
    return _read().get("default_env", "CFG")


def get_active_env(kind: str) -> Optional[Dict[str, Any]]:
    """
    Backwards compatible resolver used by services/ifs.py.
    kind: "DEV" (export) | "CFG" (import) | "PROD" or custom.
    We map:
      - "DEV"  -> active_export_env
      - "CFG"  -> active_import_env
      - other  -> exact name, else fall back to default_env.
    """
    data = _read()
    envs = data.get("environments", {})

    if kind == "DEV":
        name = data.get("active_export_env") or data.get("default_env") or "DEV"
    elif kind == "CFG":
        name = data.get("active_import_env") or data.get("default_env") or "CFG"
    else:
        name = kind

    env = envs.get(name) or envs.get(data.get("default_env"))
    return _normalize_env_block(env or {})


# ------------- legacy convenience for /api/setup-ifs -------------
def load_settings() -> Dict[str, Any]:
    """
    Return the default environment as a flat dict (legacy GET /api/setup-ifs).
    """
    data = _read()
    name = data.get("default_env") or data.get("active_env") or "CFG"
    env = data["environments"].get(name, {})
    return _normalize_env_block(env)


def save_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Legacy POST /api/setup-ifs — writes into the *default* environment.
    """
    data = _read()
    name = data.get("default_env") or "CFG"
    create_or_update_env(name, payload or {})
    return load_settings()
