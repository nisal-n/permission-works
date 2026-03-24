# app/tickets.py
import os
import json
import time
from typing import Dict, Any, List, Tuple

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
TICKETS_PATH = os.path.join(INSTANCE_DIR, "tickets.json")

FILE_DEFAULTS = {
    "next_counter": 1,
    "tickets": {}  # "PW-001": { id, user_id, subject, priority, description, created_ts, messages: [...] }
}

def _read() -> Dict[str, Any]:
    if os.path.exists(TICKETS_PATH):
        try:
            with open(TICKETS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return dict(FILE_DEFAULTS)

def _write(data: Dict[str, Any]) -> Dict[str, Any]:
    with open(TICKETS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return data

def _now() -> int:
    return int(time.time())

def _fmt_id(n: int) -> str:
    return f"PW-{n:03d}"

def create_ticket(user_id: str, subject: str, priority: str, description: str) -> Dict[str, Any]:
    data = _read()
    tid = _fmt_id(int(data.get("next_counter", 1)))
    data["next_counter"] = int(data.get("next_counter", 1)) + 1

    ticket = {
        "id": tid,
        "user_id": user_id or "unknown",
        "subject": subject.strip(),
        "priority": (priority or "Medium").capitalize(),
        "description": description.strip(),
        "created_ts": _now(),
        "messages": [
            {
                "author": user_id or "unknown",
                "text": description.strip(),
                "ts": _now(),
                "system": False,
            }
        ],
        "status": "Open",
    }
    data["tickets"][tid] = ticket

    # Auto-reply
    data["tickets"][tid]["messages"].append({
        "author": "system",
        "text": "Thanks! We’ll keep you updated and will start looking into your issue ASAP.",
        "ts": _now(),
        "system": True,
    })

    _write(data)
    return ticket

def list_tickets_for_user(user_id: str) -> List[Dict[str, Any]]:
    data = _read()
    out = [t for t in data["tickets"].values() if t.get("user_id") == user_id]
    out.sort(key=lambda x: x.get("created_ts", 0), reverse=True)
    return out

def get_ticket(tid: str) -> Dict[str, Any] | None:
    data = _read()
    return data["tickets"].get(tid)

def add_reply(tid: str, author: str, text: str, system: bool = False) -> Dict[str, Any] | None:
    data = _read()
    t = data["tickets"].get(tid)
    if not t:
        return None
    t["messages"].append({
        "author": author or "unknown",
        "text": text.strip(),
        "ts": _now(),
        "system": bool(system),
    })
    _write(data)
    return t
