# services/classifier.py

import re
import requests

# Import the same token helper you already use across the app
from ..services.ifs import get_access_token

CPI_RE = re.compile(r"/ifsapplications/web/server/metadata/cpi/([^/?#]+)", re.IGNORECASE)
from ..utils.parsers import STATUS_COMMANDS


IGNORE_PROJECTIONS = {
    "LobbyConfiguration",
    "QuickReportHandling",
    "WorkFlowBpmnHandling",
}

_NAV_SEG_RE = re.compile(r"/([A-Za-z0-9_]+Navigator)(?:\.svc)?(?:/|$)")

def _looks_like_ignored_projection_token(token: str) -> bool:
    if not token:
        return False
    return token in IGNORE_PROJECTIONS or token.endswith("Navigator")


def _should_ignore_url(url: str) -> bool:
    u = url or ""

    for p in IGNORE_PROJECTIONS:
        if p in u or f"{p}.svc" in u:
            return True

    if _NAV_SEG_RE.search(u):
        return True

    return False


def _is_crud(method: str) -> bool:
    return (method or "").upper() in ("POST", "PATCH", "DELETE")

def _fetch_projection_name_from_cpi(url: str, timeout: int = 20) -> str | None:
    """
    Calls the CPI metadata URL again with Bearer auth and returns projection.name.
    Example response shape:
      { ..., "projection": { "name": "PurchaseOrderHandling", ... } }
    """
    token = get_access_token()
    if not token:
        return None

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code != 200:
            return None
        data = r.json() if r.content else {}
    except Exception:
        return None

    proj = (data or {}).get("projection") or {}
    name = (proj or {}).get("name")
    return name if isinstance(name, str) and name.strip() else None


def classify_projections_with_ai(traces):
    """
    New behavior:
      - If trace url matches .../metadata/cpi/<Client>, re-fetch it (with auth),
        extract projection.name, and include that in summary.
      - Keep existing CRUD/status logic for access level determination.
    """
    results = []
    seen = set()  # prevent duplicates (projection, access)
        # Precompute access flags from ALL traces that already have a projection parsed
    proj_flags = {}  # proj -> {"CRUD","STATUS"}
    for tt in (traces or []):
        p = tt.get("projection")
        if not p:
            continue
        if _looks_like_ignored_projection_token(p):
            continue

        flags = proj_flags.setdefault(p, set())
        mth = (tt.get("method") or "").upper()
        if mth in ("POST", "PATCH", "DELETE"):
            flags.add("CRUD")

        mn = (tt.get("methodName") or "").strip()
        if (mn in STATUS_COMMANDS) or tt.get("isStatusChange"):
            flags.add("STATUS")


    for t in (traces or []):
        url = (t.get("url") or "").strip()
        method = (t.get("method") or "").strip().upper()
        
        if _should_ignore_url(url):
            continue

        # ---- NEW: CPI metadata fetch path ----
        m = CPI_RE.search(url)
        if m:
            proj_name = _fetch_projection_name_from_cpi(url)
            if not proj_name:
                continue
            if _looks_like_ignored_projection_token(proj_name):
                continue

            flags = proj_flags.get(proj_name, set())
            access = "full" if ("CRUD" in flags or "STATUS" in flags) else "read"

            key = (proj_name, access)
            if key not in seen:
                results.append({"projection": proj_name, "access": access})
                seen.add(key)

            # continue to next trace (don’t apply the old “Handling suffix” filter)
            continue

        # ---- Existing behavior for non-CPI traces ----
        # Keep your old parsing here (whatever you had: projection extraction from URL, etc.)
        # Example skeleton:
        #
        # projection = extract_projection_somehow(url)
        # if not projection: continue
        # access = "full" if _is_crud(method) or is_status_change(url, t) else "read"
        # ...
        #
        pass

    return results
