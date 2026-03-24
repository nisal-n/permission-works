"""
Supabase client
- Prefers SERVICE ROLE key from environment (bypasses RLS on server)
- Falls back to anon key if service role key is not provided
"""

from __future__ import annotations
import os
from typing import Optional

try:
    from supabase import create_client, Client  # pip install "supabase>=2,<3"
except Exception as e:  # pragma: no cover
    create_client, Client = None, None
    _IMPORT_ERROR: Optional[Exception] = e
else:
    _IMPORT_ERROR = None

# Defaults; you can also set these in your environment
DEFAULT_SUPABASE_URL = "https://ocigxexhtgpcxqaedled.supabase.co"
DEFAULT_SUPABASE_ANON_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9jaWd4ZXhodGdwY3hxYWVkbGVkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTk5MjcyNzMsImV4cCI6MjA3NTUwMzI3M30."
    "vLOaRA3jA7FybsV5VYobFiaHMshkAV5QKso9W2ZNLBY"
)

_client: Optional["Client"] = None


def supabase() -> "Client":
    """
    Returns a configured Supabase client (singleton).
    Prefers SUPABASE_SERVICE_ROLE_KEY; falls back to SUPABASE_ANON_KEY.
    """
    if _IMPORT_ERROR:
        raise RuntimeError(
            "Supabase SDK not installed. Install with: pip install 'supabase>=2,<3'"
        ) from _IMPORT_ERROR

    global _client
    if _client is not None:
        return _client

    url = os.environ.get("SUPABASE_URL", DEFAULT_SUPABASE_URL).strip()
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip() or os.environ.get(
        "SUPABASE_ANON_KEY", DEFAULT_SUPABASE_ANON_KEY
    ).strip()

    if not url or not key:
        raise RuntimeError("Supabase configuration missing (URL/key).")

    _client = create_client(url, key)
    return _client
