import re, json, base64
from urllib.parse import urlparse, unquote

STATUS_COMMANDS = {
    "Release","Cancel","Complete","Close","Approve","Reject","Activate","Deactivate",
    "Confirm","Freeze","Unfreeze","Hold","Unhold","Start","Stop","Finish","Post",
    "Void","Unvoid","Reopen","Submit","Reschedule","Reassign"
}

def normalize_method_name(raw_method):
    if not raw_method:
        return raw_method
    lower = raw_method.lower()
    for cmd in STATUS_COMMANDS:
        if cmd.lower() in lower:
            return cmd
    if "Release" in raw_method:
        return "Release"
    if "Cancel" in raw_method:
        return "Cancel"
    parts = raw_method.split("_")
    return parts[-1] if parts else raw_method

def extract_projection_and_method(url, body_text):
    try:
        path = urlparse(url).path or ""
        if "/projection/v1/" in path:
            parts = path.split("/projection/v1/")[1].split("/")
            if len(parts) >= 2:
                svc = parts[0]
                projection = svc.split(".svc")[0]
                last_segment = parts[-1]
                if last_segment == "$batch":
                    match = re.search(r"POST\s+[^\s]+/IfsApp\.([^.]+)\.([A-Za-z0-9_]+)", body_text)
                    if match:
                        projection = match.group(1)
                        raw_method = match.group(2)
                        method = normalize_method_name(raw_method)
                        return projection, method
                else:
                    if "." in last_segment:
                        raw_method = last_segment.split(".")[-1]
                        method = normalize_method_name(raw_method)
                    else:
                        method = parts[1].split("(")[0]
                    return projection, method
    except Exception:
        pass
    return None, None

_LOBBY_URL_RE = re.compile(
    r"/web/(?:server/)?lobby(?:/page)?/([0-9a-fA-F-]{36})",
    re.IGNORECASE
)

def maybe_capture_lobby_from_url(url: str):
    from ..state import lobby_pages
    try:
        m = _LOBBY_URL_RE.search(url)
        if m:
            lobby_id = m.group(1)
            if lobby_id not in lobby_pages:
                lobby_pages[lobby_id] = {"title": None}
            return lobby_id
    except Exception:
        pass
    return None

def _decode_base64_padded(s: str) -> str:
    try:
        padding = "=" * (-len(s) % 4)
        return base64.b64decode(s + padding).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def maybe_capture_quick_report_from_url(url: str):
    from ..state import quick_reports
    try:
        dec = unquote(url)
        is_ui = "/web/page/QuickReport/Form" in dec
        is_odata = "/projection/v1/QuickReportHandling.svc/QuickReportSet" in dec

        if not (is_ui or is_odata):
            return None

        m = re.search(r"QuickReportId\s*eq\s*(\d+)", dec)
        qr_id = None
        if m:
            qr_id = m.group(1)
        else:
            m2 = re.search(r"record=([^;]+)", dec)
            if m2:
                rec_val = unquote(m2.group(1))
                decoded = _decode_base64_padded(rec_val)
                m3 = re.search(r"QuickReportId\s*=\s*(\d+)", decoded)
                if m3:
                    qr_id = m3.group(1)
        if qr_id:
            name = f"QuickReport{qr_id}"
            quick_reports.add(name)
            return name
    except Exception:
        pass
    return None

def maybe_capture_workflow_from_url(url: str):
    from ..state import workflows
    try:
        dec = unquote(url)
        is_ui = "/web/page/Workflow/BpmnProcessPage" in dec
        is_odata = "/projection/v1/WorkFlowBpmnHandling.svc/BpmnProcessSet" in dec

        if not (is_ui or is_odata):
            return None

        m = re.search(r"ProcessKey\s*eq\s*'([^']+)'", dec, flags=re.IGNORECASE)
        if m:
            key = m.group(1).strip()
            if key:
                workflows.add(key)
                return key
        m2 = re.search(r"record=([^;]+)", dec)
        if m2:
            rec_val = unquote(m2.group(1))
            decoded = _decode_base64_padded(rec_val)
            m2a = re.search(r"ProcessKey\s*=\s*'([^']+)'", decoded, flags=re.IGNORECASE)
            if m2a:
                key = m2a.group(1).strip()
                if key:
                    workflows.add(key)
                    return key
        m3 = re.search(r"treenodeid=([^;]+)", dec)
        if m3:
            tn_val = unquote(m3.group(1))
            decoded_tn = _decode_base64_padded(tn_val)
            m3a = re.search(r"PROCESSKEY\s*=\s*([A-Za-z0-9_\-]+)", decoded_tn, flags=re.IGNORECASE)
            if not m3a:
                m3a = re.search(r"ProcessKey\s*=\s*'([^']+)'", decoded_tn, flags=re.IGNORECASE)
            if m3a:
                key = m3a.group(1).strip()
                if key:
                    workflows.add(key)
                    return key
    except Exception:
        pass
    return None

def maybe_capture_report_from_request(url: str, body_text: str):
    from ..state import reports
    try:
        path = urlparse(url).path or ""
        if not path:
            return None
        if "CustomerOrderHandling.svc" in path and "CustomerOrder_PrintResultKey" in path:
            rid = None
            try:
                payload = json.loads(body_text or "{}")
                if isinstance(payload, dict):
                    rid = payload.get("ReportId")
            except Exception:
                rid = None
            if isinstance(rid, str) and rid.strip():
                rid = rid.strip()
                reports[rid] = "CustomerOrderConfRep"
                return rid
    except Exception:
        pass
    return None
