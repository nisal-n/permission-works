import os
import time
import json
from flask import Blueprint, render_template, redirect, url_for, jsonify, request, current_app, session, send_from_directory  
from .auth import login_required, require_roles as roles_at_least
import requests  # NEW
import threading
import uuid as _uuid

from werkzeug.security import generate_password_hash

from werkzeug.security import generate_password_hash
from .supabase_client import supabase           # -> your create_client wrapper
from .auth import roles_at_least                # you’re already using this decorator
from datetime import datetime, timezone


from time import time as _now

from .services.ifs import (
    get_access_token, fetch_permission_sets,
    export_permission_start, finalize_export,
    cfg_import_zip, cfg_import_xmls, get_cfg_access_token,
    preview_permission_sets,  # used for Replace/New preview
    _env_conf_for, _env_headers_for, _env_token_for,   # NEW
    export_permission_start_env, finalize_export_env, 
)
from .settings import (
    list_envs_full, get_env, create_or_update_env, delete_env, set_active, set_default
)
from .services.ifs import grant_projection_commands

from .tickets import create_ticket, list_tickets_for_user, get_ticket, add_reply
from flask import session


dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

_ONLINE_LAST_SEEN = {}
_ONLINE_LOCK = threading.Lock()
_ONLINE_TTL_SEC = 60  

def _as_uuid_or_none(v):
    """
    Return a normalized UUID string if v is a valid uuid; otherwise None.
    """
    if not v:
        return None
    try:
        return str(_uuid.UUID(str(v)))
    except Exception:
        return None

def _data_dir():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    d = os.path.join(base_dir, "data")
    os.makedirs(d, exist_ok=True)
    return d

def _users_file():
    return os.path.join(_data_dir(), "users.json")

def _load_users():
    path = _users_file()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh) or []
                # sanitize structure
                out = []
                for u in data:
                    if isinstance(u, dict) and u.get("id") and u.get("username"):
                        out.append(u)
                return out
        except Exception:
            return []
    return []

def _save_users(users):
    try:
        with open(_users_file(), "w", encoding="utf-8") as fh:
            json.dump(users, fh, indent=2)
    except Exception:
        pass


@dashboard_bp.route("")
@login_required
def dashboard_home():
    body = """
    <div class="row g-3">
      <!-- Tile: Un-migrated deliveries -->
      <div class="col-md-6 col-xl-4">
        <div class="card p-3 h-100">
          <div class="d-flex justify-content-between align-items-center">
            <h6 class="mb-1 text-muted">Un-migrated deliveries</h6>
            <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('dashboard.dash_deploy_deliveries') }}">View</a>
          </div>
          <div class="display-5 fw-bold mt-2" id="unMigCount">–</div>
          <small class="text-muted">Packages in /deliveries with no migrations yet</small>
        </div>
      </div>

      <!-- Tile: Pending approvals -->
      <div class="col-md-6 col-xl-4">
        <div class="card p-3 h-100">
          <div class="d-flex justify-content-between align-items-center">
            <h6 class="mb-1 text-muted">Pending approval migrations</h6>
            <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('dashboard.dash_deploy_deliveries') }}">Open</a>
          </div>
          <div class="display-5 fw-bold mt-2" id="pendingCount">–</div>
          <small class="text-muted">Awaiting approval / pending status</small>
        </div>
      </div>

      <!-- Tile: Quick access to Start Recording -->
      <div class="col-md-12 col-xl-4">
        <div class="card p-3 h-100 d-flex justify-content-between">
          <div>
            <h6 class="mb-1 text-muted">Quick access</h6>
            <h4 class="mt-2">Start Recording</h4>
            <small class="text-muted">Open the trace capture screen</small>
          </div>
          <div class="mt-3">
            <a class="btn btn-primary" href="/traces">Start Recording</a>
            <a class="btn btn-outline-secondary ms-2" href="{{ url_for('dashboard.dash_permission_create') }}">Create Role</a>
          </div>
        </div>
      </div>

      <!-- Tile: Default IFS environment -->
      <div class="col-md-6 col-xl-4">
        <div class="card p-3 h-100">
          <h6 class="mb-1 text-muted">Default IFS environment</h6>
          <div class="mt-2">
            <span id="defaultEnv" class="badge bg-primary fs-6 px-3 py-2">–</span>
          </div>
          <small class="text-muted d-block mt-2">Change in Setup IFS</small>
          <div class="mt-2">
            <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('dashboard.dash_basic_setup_ifs') }}">Setup IFS</a>
          </div>
        </div>
      </div>

      <!-- Tile: Realtime users chart -->
      <div class="col-md-12 col-xl-8">
        <div class="card p-3 h-100">
          <div class="d-flex justify-content-between align-items-center">
            <h6 class="mb-1 text-muted">Users online (last minute)</h6>
            <small class="text-muted" id="usersOnlineNow">– online</small>
          </div>
          <canvas id="usersChart" height="110" style="width:100%"></canvas>
          <small class="text-muted">This page pings the server; other users on this page will appear here.</small>
        </div>
      </div>
    </div>

    <script>
      // --- Minimal chart (no external libs) ---
      const canvas = document.getElementById('usersChart');
      const ctx = canvas.getContext('2d');
      const W = () => canvas.clientWidth, H = () => canvas.height;
      let points = [];   // [{t: ms, v: count}, ...]
      function drawChart() {
        const w = canvas.width = canvas.clientWidth;
        const h = canvas.height; // fixed
        ctx.clearRect(0,0,w,h);

        // Axes
        ctx.lineWidth = 1; ctx.strokeStyle = '#ccc';
        ctx.beginPath(); ctx.moveTo(40, 10); ctx.lineTo(40, h-25); ctx.lineTo(w-10, h-25); ctx.stroke();

        if (!points.length) return;
        const now = Date.now();
        const minT = now - 60*1000;
        const view = points.filter(p => p.t >= minT);

        const maxV = Math.max(1, ...view.map(p => p.v));
        const x0 = 40, x1 = w-10, y0 = h-25, y1 = 10;
        const tx = t => x0 + ( (t-minT) / (60*1000) ) * (x1-x0);
        const ty = v => y0 - (v/maxV) * (y0-y1);

        // line
        ctx.beginPath();
        ctx.lineWidth = 2; ctx.strokeStyle = '#0d6efd';
        view.forEach((p, i) => { const x = tx(p.t), y = ty(p.v); i?ctx.lineTo(x,y):ctx.moveTo(x,y); });
        ctx.stroke();

        // y labels
        ctx.fillStyle = '#666'; ctx.font = '12px system-ui, -apple-system, Segoe UI, Roboto, Arial';
        ctx.fillText('0', 10, y0+4);
        ctx.fillText(String(maxV), 10, y1+4);
      }

      // --- Metrics loader ---
      async function refreshSummary(){
        try {
          const r = await fetch('/dashboard/api/metrics/summary',{headers:{'Accept':'application/json'}});
          const j = await r.json();
          if (j) {
            document.getElementById('unMigCount').textContent = j.unmigrated_count ?? '0';
            document.getElementById('pendingCount').textContent = j.pending_approval_count ?? '0';
            document.getElementById('defaultEnv').textContent = j.default_env || 'DEV';
          }
        } catch(e) { /* ignore */ }
      }

      // --- Online: ping & poll ---
      async function pingMe(){
        try { await fetch('/dashboard/api/online/ping',{method:'POST'}); } catch(e){}
      }
      async function pollOnline(){
        try {
          const r = await fetch('/dashboard/api/online/stats',{headers:{'Accept':'application/json'}});
          const j = await r.json();
          if (j) {
            points.push({t: Date.now(), v: j.current_online || 0});
            // keep only last 90s for smoothness
            const cutoff = Date.now() - 90*1000;
            points = points.filter(p => p.t >= cutoff);
            document.getElementById('usersOnlineNow').textContent = (j.current_online||0) + ' online';
            drawChart();
          }
        } catch(e){}
      }

      // kick things off
      refreshSummary();
      pingMe(); pollOnline(); drawChart();
      setInterval(refreshSummary, 10000);
      setInterval(pingMe, 10000);
      setInterval(pollOnline, 5000);
      window.addEventListener('resize', drawChart);
    </script>
    """
    return render_template("dashboard.html", title="Dashboard", subtitle="Overview", body_html=body)


# === 3) ADD THESE SIMPLE METRICS/ONLINE API ENDPOINTS (anywhere below helpers) ===

def _iter_delivery_metas():
    """Yield meta dicts for each delivery (paired .json if present, else {})."""
    ddir = _deliveries_dir()
    for name in os.listdir(ddir):
        if name.lower().endswith(".zip"):
            vid = name[:-4]
            yield _load_meta(vid) or {}

@dashboard_bp.route("/api/metrics/summary")
@login_required
def api_metrics_summary():
    # 1) Un-migrated deliveries: no 'migrations' or empty list
    unmigrated = 0
    pending_approval = 0
    for meta in _iter_delivery_metas():
        migs = meta.get("migrations") or []
        if not migs:
            unmigrated += 1
        # 2) Pending approvals: look for any migration with a pending-ish status
        for m in migs:
            st = (m or {}).get("status", "").lower()
            if st in {"pending", "pending_approval", "awaiting_approval"}:
                pending_approval += 1
                break  # count this delivery once

    # 4) Default IFS env
    envs = (list_envs_full() or {})
    default_env = (envs.get("default_env") or "DEV").upper()

    return jsonify({
        "unmigrated_count": unmigrated,
        "pending_approval_count": pending_approval,
        "default_env": default_env
    })


@dashboard_bp.route("/api/online/ping", methods=["POST"])
@login_required
def api_online_ping():
    uid = _current_user_id()
    with _ONLINE_LOCK:
        _ONLINE_LAST_SEEN[uid] = _now()
        # opportunistic cleanup
        cutoff = _now() - (_ONLINE_TTL_SEC * 3)
        for k, ts in list(_ONLINE_LAST_SEEN.items()):
            if ts < cutoff:
                _ONLINE_LAST_SEEN.pop(k, None)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/online/stats", methods=["GET"])
@login_required
def api_online_stats():
    now = _now()
    with _ONLINE_LOCK:
        current_online = sum(1 for ts in _ONLINE_LAST_SEEN.values() if (now - ts) <= _ONLINE_TTL_SEC)
    return jsonify({"current_online": current_online, "window_sec": _ONLINE_TTL_SEC})


# ======================= Permission Set: Create / Update =======================

@dashboard_bp.route("/permission-set/update-existing")
@login_required
def dash_permission_update():
    """
    In-app role picker (filter + single select) that proceeds to an update trace screen.
    """
    # Simple body with filterable table and proceed
    body = """
    <div class="card p-3">
      <div class="d-flex align-items-center justify-content-between">
        <h5 class="mb-0">Update an existing Permission Set</h5>
        <a href="{{ url_for('dashboard.dashboard_home') }}" class="btn btn-outline-secondary btn-sm">Back</a>
      </div>

      <div id="alert" class="alert d-none mt-3" role="alert"></div>

      <div class="row g-2 mt-2">
        <div class="col-sm-8">
          <input id="roleFilter" class="form-control" placeholder="Filter roles by name...">
        </div>
        <div class="col-sm-4 d-grid">
          <button id="proceedBtn" class="btn btn-primary" disabled>Proceed</button>
        </div>
      </div>

      <div class="table-responsive mt-3">
        <table class="table table-sm table-hover align-middle mb-0" id="rolesTbl">
          <thead class="table-light">
            <tr>
              <th style="width:48px;"></th>
              <th>Permission Set (Role)</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody id="rolesTbody">
            <tr><td colspan="3" class="text-muted p-3">Loading roles…</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <script>
      const alertEl = document.getElementById('alert');
      function showAlert(type, msg) {
        alertEl.className = 'alert alert-' + type;
        alertEl.textContent = msg;
        alertEl.classList.remove('d-none');
      }
      function hideAlert(){ alertEl.classList.add('d-none'); }

      const tbody = document.getElementById('rolesTbody');
      const filterInput = document.getElementById('roleFilter');
      const proceedBtn = document.getElementById('proceedBtn');
      let allRoles = [];
      let selectedRole = '';

      function renderRows(list) {
        if (!list.length) {
          tbody.innerHTML = '<tr><td colspan="3" class="text-muted p-3">No roles found.</td></tr>';
          return;
        }
        tbody.innerHTML = list.map(r => {
          const safeRole = (r.role || '').replace(/"/g,'&quot;');
          const checked = (selectedRole && selectedRole === r.role) ? 'checked' : '';
          return `
            <tr>
              <td>
                <input type="radio" name="rolePick" value="${safeRole}" ${checked}
                       onclick="window.__pickRole(this.value)">
              </td>
              <td><code>${safeRole}</code></td>
              <td>${(r.description || '')}</td>
            </tr>
          `;
        }).join('');
      }

      window.__pickRole = function(v){
        selectedRole = v || '';
        proceedBtn.disabled = !selectedRole;
      };

      function applyFilter(){
        const q = (filterInput.value || '').toLowerCase().trim();
        if (!q) { renderRows(allRoles); return; }
        const filtered = allRoles.filter(r => (r.role || '').toLowerCase().includes(q));
        renderRows(filtered);
      }

      filterInput.addEventListener('input', applyFilter);

      proceedBtn.addEventListener('click', () => {
        if (!selectedRole) {
          showAlert('warning', 'Please select a permission set to update.');
          return;
        }
        // Navigate into the trace wrapper for update, passing the role
        location.href = `/dashboard/permission-set/update/trace?role=${encodeURIComponent(selectedRole)}`;
      });

      async function loadRoles(){
        hideAlert();
        try{
          const r = await fetch('/dashboard/api/deploy/export/roles', { headers: {'Accept':'application/json'}});
          const j = await r.json();
          if (!r.ok) throw new Error((j && j.error) || ('HTTP ' + r.status));
          allRoles = (j.roles || []);
          renderRows(allRoles);
        }catch(e){
          tbody.innerHTML = '<tr><td colspan="3" class="text-danger p-3">Failed to load roles.</td></tr>';
          showAlert('danger', 'Failed to load roles: ' + e.message);
        }
      }

      loadRoles();
    </script>
    """
    return render_template(
        "dashboard.html",
        title="Permission set • Update",
        subtitle="Choose a role and run a trace to update it",
        body_html=body,
    )


@dashboard_bp.route("/permission-set/update/trace")
@login_required
def dash_permission_update_trace():
    """
    Wrapper for the trace UI in UPDATE mode.
    - Do NOT start tracing here.
    - Just remember the selected role and show /traces.
    - Pass autolaunch=1 so /traces opens the default IFS base in a new tab.
    """
    role = (request.args.get("role") or "").strip()
    if not role:
        return redirect(url_for("dashboard.dash_permission_update"))

    # Remember which role we’re updating (used by the summary step later)
    session["update_role"] = role

    body = f"""
    <div class="card p-3">
      <div class="alert alert-warning d-flex align-items-center" role="alert">
        <div>
          <strong>Update mode:</strong> You will update the existing permission set
          <code>{role}</code>. Click <strong>Start</strong> when you’re ready, perform actions in IFS,
          then click <strong>Stop</strong> to generate the summary.
        </div>
      </div>
      <div class="iframe-wrap" style="min-height:70vh">
        <!-- NOTE: no /start_trace here; just load /traces and let the user click Start -->
        <iframe src="/traces?mode=update&role={role}&autolaunch=1" title="IFS Trace Capture" style="width:100%;height:70vh;border:1px solid #e5e7eb;border-radius:.5rem;"></iframe>
      </div>
    </div>
    """
    return render_template(
        "dashboard.html",
        title="Permission set • Update",
        subtitle="Trace & update an existing role",
        body_html=body,
    )



@dashboard_bp.route("/permission-set/create-new")
@login_required
def dash_permission_create():
    # This is the "Create New" menu entry: make sure we are NOT in update mode.
    session.pop("update_role", None)          # <<— IMPORTANT: clear any previous update selection

    body = """
    <div class="iframe-wrap">
      <iframe src="/traces" title="IFS Trace Capture"></iframe>
    </div>
    """
    return render_template(
        "dashboard.html",
        title="Permission set • Create New",
        subtitle="Trace & build a role without leaving the dashboard.",
        body_html=body,
    )


@dashboard_bp.route("/permission-set/templates")
@login_required
@roles_at_least("admin")
@login_required
def dash_permission_templates():
    body = """
    <p class="mb-3">Starter names/descriptions you can paste into your existing Create flow:</p>
    <div class="table-responsive">
      <table class="table table-sm">
        <thead class="table-light">
          <tr><th>Template Name</th><th>Description</th></tr>
        </thead>
        <tbody>
          <tr><td>OPS_ReadOnly</td><td>Operations read-only access for monitoring.</td></tr>
          <tr><td>OPS_FullOrderMgmt</td><td>Full access for CustomerOrderHandling plus related lobbies.</td></tr>
          <tr><td>FIN_AP_Read</td><td>Finance AP read-only, reports enabled.</td></tr>
          <tr><td>FIN_AR_Clerk</td><td>AR clerk access with posting permissions.</td></tr>
        </tbody>
      </table>
    </div>
    <p class="subtle mb-0">These are examples only; your app logic remains unchanged.</p>
    """
    return render_template(
        "dashboard.html",
        title="Permission set • Templates",
        subtitle="Copy/paste into your current create flow as needed.",
        body_html=body,
    )


@dashboard_bp.route("/permission-set/history")
@roles_at_least("admin")
@login_required
def dash_permission_history():
    body = """
    <div class="card p-3">
      <div class="d-flex align-items-center justify-content-between">
        <div>
          <h5 class="mb-0">Permission Set History</h5>
          <small class="text-muted">Recent role exports/updates</small>
        </div>
        <div class="d-flex gap-2">
          <button id="refreshBtn" class="btn btn-sm btn-outline-secondary">Refresh</button>
        </div>
      </div>

      <div class="table-responsive mt-3">
        <table class="table table-sm table-hover align-middle mb-0">
          <thead class="table-light">
            <tr>
              <th>Permission Set</th>
              <th>Created by</th>
              <th>Created at</th>
              <th>Source</th>
              <th>Target</th>
              <th>Version</th>
              <th style="width:1%"></th>
            </tr>
          </thead>
          <tbody id="histTbody">
            <tr><td colspan="7" class="text-muted p-3">Loading…</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <script>
      function esc(s){ return String(s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]||c)); }
      function fmtIso(s){
        if(!s) return '';
        try{ return new Date(s).toLocaleString(); }catch(e){ return s; }
      }

      async function loadHist(){
        const tbody = document.getElementById('histTbody');
        tbody.innerHTML = '<tr><td colspan="7" class="text-muted p-3">Loading…</td></tr>';
        try{
          const r = await fetch('/dashboard/api/ps-history/list', { headers: {'Accept':'application/json'}});
          const j = await r.json();
          if(!r.ok || !j.ok) throw new Error(j.error||('HTTP '+r.status));
          const rows = (j.items||[]).map(it => `
            <tr>
              <td><code>${esc(it.permission_set)}</code></td>
              <td>${esc(it.created_by)}</td>
              <td>${fmtIso(it.created_at)}</td>
              <td>${esc(it.source_env||'')}</td>
              <td>${esc(it.target_env||'')}</td>
              <td><code>${esc(it.version_id||'')}</code></td>
              <td class="text-nowrap">
                <a class="btn btn-sm btn-outline-primary" href="/dashboard/permission-set/history/${encodeURIComponent(it.id)}">View detail</a>
              </td>
            </tr>
          `).join('');
          tbody.innerHTML = rows || '<tr><td colspan="7" class="text-muted p-3">No history yet.</td></tr>';
        }catch(e){
          tbody.innerHTML = '<tr><td colspan="7" class="text-danger p-3">Failed to load history.</td></tr>';
        }
      }

      document.getElementById('refreshBtn').addEventListener('click', loadHist);
      loadHist();
    </script>
    """
    return render_template(
        "dashboard.html",
        title="Permission set • History",
        subtitle="List of exports/updates",
        body_html=body,
    )



@dashboard_bp.route("/basic/setup-ifs")
@login_required
@roles_at_least("superadmin")
def dash_basic_setup_ifs():
    body = render_template("setup_ifs_body.html")
    return render_template(
        "dashboard.html",
        title="Basic data • Setup IFS environment",
        subtitle="Manage multiple environments (CFG/DEV/PROD & custom).",
        body_html=body,
    )


# ======================= Deliveries =======================

@dashboard_bp.route("/deployment/deliveries")
@roles_at_least("admin")
@login_required
def dash_deploy_deliveries():
    body = render_template("deliveries_body.html")
    return render_template(
        "dashboard.html",
        title="Deployment • Deliveries",
        subtitle="Created deliveries with one-click migration",
        body_html=body,
    )


def _deliveries_dir():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    deliveries_dir = os.path.join(base_dir, "deliveries")
    os.makedirs(deliveries_dir, exist_ok=True)
    return deliveries_dir

def _backups_dir():
    bdir = os.path.join(_deliveries_dir(), "backup")
    os.makedirs(bdir, exist_ok=True)
    return bdir



def _meta_path(version_id: str) -> str:
    return os.path.join(_deliveries_dir(), f"{version_id}.json")


def _load_meta(version_id: str) -> dict:
    path = _meta_path(version_id)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}
    return {}


def _save_meta(version_id: str, meta: dict):
    try:
        with open(_meta_path(version_id), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
    except Exception:
        pass


@dashboard_bp.route("/api/deliveries/list")
@login_required
@roles_at_least("admin")
def api_deliveries_list():
    deliveries_dir = _deliveries_dir()

    items = []
    for name in os.listdir(deliveries_dir):
        if not name.lower().endswith(".zip"):
            continue
        version_id = name[:-4]
        path = os.path.join(deliveries_dir, name)
        try:
            ts = os.path.getmtime(path)
        except Exception:
            ts = 0

        meta = _load_meta(version_id)
        items.append({
            "version_id": version_id,
            "file_name": name,
            "created_ts": ts,
            "source_env": meta.get("source_env", "DEV"),
            "default_target_env": meta.get("default_target_env"),
            "migrations": meta.get("migrations", []),
        })

    items.sort(key=lambda x: x["created_ts"], reverse=True)
    for it in items:
        it["created_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(it["created_ts"]))
    return jsonify({"deliveries": items})


@dashboard_bp.route("/api/deliveries/migrate-cfg", methods=["POST"])
@login_required
@roles_at_least("admin")
def api_deliveries_migrate_cfg():
    """
    Migrates the selected delivery into the requested target environment.
    Body:
      - version_id (required)
      - target_env (optional; default uses delivery's default_target_env or IMPORT_TARGET or 'DEV')
    """
    data = request.get_json(force=True) or {}
    version_id = (data.get("version_id") or "").strip()
    if not version_id:
        return jsonify({"error": "missing_version_id"}), 400

    deliveries_dir = _deliveries_dir()
    zip_path = os.path.join(deliveries_dir, f"{version_id}.zip")
    if not os.path.exists(zip_path):
        return jsonify({"error": "file_not_found"}), 404

    meta = _load_meta(version_id)
    default_target_env = (meta.get("default_target_env") or current_app.config.get("IMPORT_TARGET", "DEV") or "DEV").upper()
    target = ((data.get("target_env") or default_target_env) or "DEV").strip().upper()

    # Only fetch a CFG token if target is CFG. For others, helpers fetch tokens as needed.
    cfg_token = None
    if target == "CFG":
        cfg_token, t_err = get_cfg_access_token()
        if not cfg_token:
            return jsonify({"error": "cfg_token_failed", "details": t_err, "target": target}), 502

    mode = (current_app.config.get("CFG_IMPORT_MODE", "xml") or "xml").lower()
    if mode == "zip":
        ok, err = cfg_import_zip(cfg_token, zip_path, target_env=target)
    else:
        ok, err = cfg_import_xmls(cfg_token, zip_path, target_env=target)

    if not ok:
        return jsonify({"error": "import_failed", "details": err, "mode": mode, "target": target}), 502

    # Append metadata for this delivery
    if not meta:
        meta = {
            "version_id": version_id,
            "source_env": "DEV",
            "created_ts": os.path.getmtime(zip_path),
            "migrations": [],
        }
    migrations = meta.get("migrations", [])
    migrations.append({
        "to": target,
        "mode": mode,
        "ts": time.time(),
        "status": "ok"
    })
    meta["migrations"] = migrations
    # don't overwrite default_target_env unless it was missing
    if not meta.get("default_target_env"):
        meta["default_target_env"] = target
    _save_meta(version_id, meta)

    return jsonify({
        "status": "ok",
        "message": f"Migrated {version_id} to {target} via {mode.upper()} import",
        "target": target,
        "migrations": migrations
    })


# =================== Create Delivery (wizard) ===================

@dashboard_bp.route("/deployment/create-delivery")
@login_required
def dash_create_delivery_wizard():
    body = render_template("delivery_wizard_body.html")
    return render_template(
        "dashboard.html",
        title="Deployment • Create Delivery",
        subtitle="Export roles to a versioned delivery package",
        body_html=body,
    )


@dashboard_bp.route("/api/deploy/export/roles")
@login_required
def api_export_roles():
    # Prefer explicit ?source_env=..., else use Setup IFS default, else DEV.
    pick = (request.args.get("source_env") or "").strip().upper()
    envs = list_envs_full() or {}
    source_env = pick or (envs.get("default_env") or "DEV").upper()

    token, terr = _env_token_for(source_env, cfg_token_hint=None)
    if terr or not token:
        return jsonify({"error": "token_failed", "details": terr, "source_env": source_env}), 500

    conf = _env_conf_for(source_env)
    base = f"{conf['projection_base'].rstrip('/')}/PermissionSetHandling.svc/PermissionSets"
    url = f"{base}?$top=500&$select=Role,Description&$orderby=Role"

    try:
        r = requests.get(url, headers=_env_headers_for(token, source_env), timeout=30, verify=conf.get("ssl_verify", True))
        if r.status_code != 200:
            return jsonify({"error": "ifs_roles_failed", "status": r.status_code, "details": (r.text or "")[:600], "source_env": source_env}), 502
        data = r.json() if r.content else {}
        items = data.get("value") if isinstance(data, dict) else []
        roles = []
        for it in items or []:
            role = it.get("Role") or it.get("ROLE") or it.get("Id") or it.get("ID")
            desc = it.get("Description") or it.get("DESC") or ""
            if role:
                roles.append({"role": str(role), "description": str(desc)})
        roles.sort(key=lambda x: x["role"].lower())
        return jsonify({"roles": roles, "source_env": source_env})
    except Exception as e:
        return jsonify({"error": "exception", "details": str(e), "source_env": source_env}), 502



@dashboard_bp.route("/api/deploy/preview-target", methods=["POST"])
@login_required
@roles_at_least("admin")
def api_deploy_preview_target():
    data = request.get_json(force=True) or {}
    target_env = (data.get("target_env") or "").strip()
    roles = data.get("roles") or []
    source_env = (data.get("source_env") or "DEV").strip().upper()
    if not target_env:
        return jsonify({"ok": False, "error": "missing_target_env"}), 400
    if not roles:
        return jsonify({"ok": False, "error": "missing_roles"}), 400

    preview = preview_permission_sets(source_env, target_env, roles)
    return jsonify({"ok": True, "preview": preview})



@dashboard_bp.route("/api/deploy/export/finalize", methods=["POST"])
@login_required
@roles_at_least("admin")
def api_export_finalize():
    data = request.get_json(force=True) or {}
    roles = data.get("roles") or []
    if not roles:
        return jsonify({"error": "missing_roles"}), 400

    user_grants = bool(data.get("user_grants", True))
    user_group_grants = bool(data.get("user_group_grants", False))
    target_env = (data.get("target_env") or "").strip().upper()
    source_env = (data.get("source_env") or "DEV").strip().upper()

    # Determine which roles would be REPLACE in the target (keep this early)
    backup_roles = []
    try:
        prev = preview_permission_sets(source_env, target_env, roles)
        for it in (prev.get("items") or []):
            if str(it.get("status", "")).lower() == "replace":
                r = it.get("role")
                if r:
                    backup_roles.append(r)
    except Exception:
        backup_roles = []

    # get token for SOURCE env
    token, terr = _env_token_for(source_env, cfg_token_hint=None)
    if terr or not token:
        return jsonify({"error": "token_failed", "details": terr, "source_env": source_env}), 500

    # start export (env-aware)
    objkey, err = export_permission_start_env(token, source_env)
    if err or not objkey:
        return jsonify({"error": "export_start_failed", "details": err, "source_env": source_env}), 502

    # finalize export (env-aware) -> returns pw_YYMMDD_HHMMSS version_id
    version_id, ferr = finalize_export_env(
        token, objkey, roles, source_env,
        user_grants=user_grants, user_group_grants=user_group_grants
    )
    if ferr or not version_id:
        return jsonify({"error": "finalize_failed", "details": ferr, "source_env": source_env}), 502

    # NOW we have version_id: create backup ZIP for REPLACE roles (if any)
    if backup_roles and target_env:
        try:
            from .services.ifs import export_backup_zip_for_replace_roles
            okb, berr = export_backup_zip_for_replace_roles(target_env, backup_roles, version_id)

            # store breadcrumb in meta (non-blocking)
            try:
                meta_b = _load_meta(version_id) or {}
                meta_b["backup"] = {
                    "path": f"backup/{version_id}.zip",
                    "roles": backup_roles,
                    "count": len(backup_roles),
                    "target_env": target_env,
                    "ok": bool(okb),
                    "error": berr if not okb else None,
                }
                _save_meta(version_id, meta_b)
            except Exception:
                pass
        except Exception:
            pass

        # --- HISTORY LOG (Supabase) ---
    try:
        # Attempt to collect deep snapshots per role (best-effort).
        # If you have a helper in services.ifs you can plug it here.
        snapshots = {}
        try:
            from .services.ifs import get_permission_set_grants  # OPTIONAL (if you implement it)
        except Exception:
            get_permission_set_grants = None

        if get_permission_set_grants:
            for rname in roles:
                try:
                    snaps = get_permission_set_grants(source_env, rname)  # expected dict
                    snapshots[rname] = snaps or {}
                except Exception:
                    snapshots[rname] = {}
        else:
            # Fallback: store minimal structure; you can enrich later
            for rname in roles:
                snapshots[rname] = {
                    "projections": [],
                    "reports": [],
                    "users": [],
                    "structures": [],
                }

        details = {
            "roles": roles,
            "grants": {
                "user_grants": bool(user_grants),
                "user_group_grants": bool(user_group_grants),
            },
            "backup_roles": backup_roles,
            # Optionally include preview to show Replace/New decisions:
            # "preview": prev,   # uncomment if prev is available here
            "snapshots": snapshots,
        }

        # If multiple roles chosen, write one log per role to make the list cleaner
        for rname in roles:
            _history_insert(
                permission_set=rname,
                source_env=source_env,
                target_env=target_env,
                version_id=version_id,
                details=details if len(roles) == 1 else {**details, "roles": [rname]}
            )
    except Exception as e:
        current_app.logger.warning(f"history logging failed: {e}")


    # write/augment meta as before
    deliveries_dir = _deliveries_dir()
    zip_path = os.path.join(deliveries_dir, f"{version_id}.zip")
    try:
        meta = _load_meta(version_id) or {}
        meta.update({
            "version_id": version_id,
            "source_env": source_env,
            "created_ts": os.path.getmtime(zip_path),
            "default_target_env": target_env or meta.get("default_target_env") or None,
            "migrations": meta.get("migrations", []),
        })
        _save_meta(version_id, meta)
    except Exception:
        pass

    return jsonify({"status": "ok", "version_id": version_id})

# ======================= Support =======================

@dashboard_bp.route("/support/permissionsync")
@login_required
def dash_permissionsync_support():
    body = render_template("support_tickets_body.html")
    return render_template(
        "dashboard.html",
        title="PermissionWorks Support",
        subtitle="Create tickets and view your threads.",
        body_html=body,
    )


@dashboard_bp.route("/api/debug/cfg-token")
@login_required
def api_debug_cfg_token():
    tok, err = get_cfg_access_token()
    if not tok:
        return jsonify({"ok": False, "err": err}), 502
    return jsonify({"ok": True, "token_prefix": tok[:16] + "...", "len": len(tok)})


# =============== Setup IFS API (used by the Setup page) ===============

@dashboard_bp.route("/api/setup-ifs/envs", methods=["GET"])
@login_required
@roles_at_least("superadmin")
def api_envs_list():
    return jsonify(list_envs_full())


@dashboard_bp.route("/api/setup-ifs/envs/create", methods=["POST"])
@login_required
@roles_at_least("superadmin")
def api_envs_create():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "missing_name"}), 400
    env = create_or_update_env(name, data)
    return jsonify({"ok": True, "env": env})


@dashboard_bp.route("/api/setup-ifs/envs/<name>", methods=["POST"])
@login_required
@roles_at_least("superadmin")
def api_envs_update(name):
    data = request.get_json(force=True) or {}
    env = create_or_update_env(name, data)
    return jsonify({"ok": True, "env": env})


@dashboard_bp.route("/api/setup-ifs/envs/<name>", methods=["DELETE"])
@login_required
@roles_at_least("superadmin")
def api_envs_delete(name):
    if delete_env(name):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "not_found"}), 404


@dashboard_bp.route("/api/setup-ifs/envs/select", methods=["POST"])
@login_required
@roles_at_least("superadmin")
def api_envs_make_active():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "missing_name"}), 400
    try:
        active = set_active("all", name)
        return jsonify({"ok": True, **active})
    except KeyError as e:
        return jsonify({"ok": False, "error": str(e)}), 404


@dashboard_bp.route("/api/setup-ifs/envs/default", methods=["POST"])
@login_required
@roles_at_least("superadmin")
def api_envs_make_default():
    """
    Mark an environment as Default (also sets it active). No redirects.
    """
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "missing_name"}), 400
    try:
        info = set_default(name)
        env = get_env(name) or {}
        return jsonify({"ok": True, "default": info, "env": env})
    except KeyError as e:
        return jsonify({"ok": False, "error": str(e)}), 404


# ======================= Ticketing =======================

@dashboard_bp.route("/api/tickets", methods=["GET"])
@login_required
def api_tickets_list():
    uid = _current_user_id()
    return jsonify({"ok": True, "tickets": list_tickets_for_user(uid)})

@dashboard_bp.route("/api/tickets", methods=["POST"])
@login_required
def api_tickets_create():
    data = request.get_json(force=True) or {}
    subject = (data.get("subject") or "").strip()
    priority = (data.get("priority") or "Medium").strip()
    description = (data.get("description") or "").strip()

    if not subject or not description:
        return jsonify({"ok": False, "error": "subject_and_description_required"}), 400

    uid = _current_user_id()
    t = create_ticket(uid, subject, priority, description)
    return jsonify({"ok": True, "ticket": t})

@dashboard_bp.route("/api/tickets/<tid>", methods=["GET"])
@login_required
def api_tickets_get(tid):
    t = get_ticket(tid)
    if not t:
        return jsonify({"ok": False, "error": "not_found"}), 404
    if t.get("user_id") != _current_user_id():
        return jsonify({"ok": False, "error": "forbidden"}), 403
    return jsonify({"ok": True, "ticket": t})

@dashboard_bp.route("/api/tickets/<tid>/reply", methods=["POST"])
@login_required
def api_tickets_reply(tid):
    data = request.get_json(force=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "text_required"}), 400

    t = get_ticket(tid)
    if not t:
        return jsonify({"ok": False, "error": "not_found"}), 404
    if t.get("user_id") != _current_user_id():
        return jsonify({"ok": False, "error": "forbidden"}), 403

    updated = add_reply(tid, _current_user_id(), text, system=False)
    return jsonify({"ok": True, "ticket": updated})


def _current_user_id():
    return (
        session.get("user_id")
        or session.get("username")
        or session.get("email")
        or session.get("name")
        or "anonymous"
    )


# ======================= Debug: CFG =======================

@dashboard_bp.route("/api/debug/cfg-discovery")
@login_required
def api_debug_cfg_discovery():
    tok, err = get_cfg_access_token()
    if not tok:
        return jsonify({"ok": False, "err": err}), 502
    from .services.ifs import cfg_debug_snapshot
    snap = cfg_debug_snapshot(tok)
    return jsonify({"ok": True, **snap})


@dashboard_bp.route("/api/debug/cfg-probe")
@login_required
def api_debug_cfg_probe():
    """
    Quick probe that exercises the minimum steps of the XML path without uploading:
    - Get CFG token
    - Discover FndTempLobs base
    """
    tok, err = get_cfg_access_token()
    if not tok:
        return jsonify({"ok": False, "err": err}), 502
    from .services.ifs import _discover_fndtemplobs_endpoint
    base, derr = _discover_fndtemplobs_endpoint(tok)
    if not base:
        return jsonify({"ok": False, "step":"discover", "err": derr}), 502
    return jsonify({"ok": True, "fndtemplobs_base": base})


@dashboard_bp.route("/api/debug/cfg-fndtemplobs")
@login_required
def api_debug_cfg_fndtemplobs():
    tok, err = get_cfg_access_token()
    if not tok:
        return jsonify({"ok": False, "err": err}), 502
    from .services.ifs import _discover_fndtemplobs_endpoint
    base, derr = _discover_fndtemplobs_endpoint(tok)
    if base:
        return jsonify({"ok": True, "base": base})
    return jsonify({"ok": False, "err": derr}), 502


# ======================= Command grants (call AFTER role create/update) =======================

@dashboard_bp.route("/api/ifs/grant-commands", methods=["POST"])
@login_required
def api_ifs_grant_commands():
    """
    Body:
      {
        "role": "OPS_ReadOnly",
        "projection": "CustomerOrderHandling",
        "commands": ["Create", "Modify", "Cancel"],
        "client": "web"        # optional; defaults to 'web'
      }
    """
    data = request.get_json(force=True) or {}
    role = (data.get("role") or "").strip()
    projection = (data.get("projection") or "").strip()
    commands = data.get("commands") or []
    client = (data.get("client") or "web").strip() or "web"

    if not role or not projection:
        return jsonify({"ok": False, "error": "role_and_projection_required"}), 400
    if not isinstance(commands, list):
        return jsonify({"ok": False, "error": "commands_must_be_list"}), 400

    ok, err = grant_projection_commands(role, projection, commands, client=client)
    if not ok:
        return jsonify({"ok": False, "error": err}), 502
    return jsonify({"ok": True})


@dashboard_bp.route("/api/ifs/grant-commands/batch", methods=["POST"])
@login_required
def api_ifs_grant_commands_batch():
    """
    Body:
      {
        "role": "OPS_ReadOnly",
        "items": [
          {"projection":"CustomerOrderHandling","commands":["Create","Modify"],"client":"web"},
          {"projection":"SalesOrderHandling","commands":["Approve"]}
        ]
      }
    """
    data = request.get_json(force=True) or {}
    role = (data.get("role") or "").strip()
    items = data.get("items") or []
    if not role or not isinstance(items, list) or not items:
        return jsonify({"ok": False, "error": "role_and_items_required"}), 400

    results = []
    for it in items:
        proj = (it.get("projection") or "").strip()
        cmds = it.get("commands") or []
        client = (it.get("client") or "web").strip() or "web"
        if not proj:
            results.append({"projection": proj, "ok": False, "error": "missing_projection"})
            continue
        ok, err = grant_projection_commands(role, proj, cmds, client=client)
        results.append({"projection": proj, "ok": ok, "error": err})

    ok_overall = all(r.get("ok") for r in results)
    return jsonify({"ok": ok_overall, "results": results}), (200 if ok_overall else 207)


@dashboard_bp.route("/permission-set/update-existing/start", methods=["POST"])
@login_required
def dash_permission_update_start():
    """
    Called from your 'Update existing' picker. Body/form must contain 'role'.
    Saves the role in session and opens the trace screen.
    """
    role = (request.form.get("role") or (request.json or {}).get("role") or "").strip()
    if not role:
        return jsonify({"ok": False, "error": "missing_role"}), 400

    session["update_role"] = role  # <-- remember chosen role
    # Change 'traces.traces_screen' to your trace entry route
    return redirect(url_for("traces.traces_screen", mode="update"))

@dashboard_bp.route("/deployment/backups")
@login_required
@roles_at_least("superadmin")
def dash_backups():
    # simple list UI
    body = """
    <div class="card p-3">
      <div class="d-flex align-items-center justify-content-between">
        <h5 class="mb-0">Backups</h5>
        <a href="{{ url_for('dashboard.dashboard_home') }}" class="btn btn-outline-secondary btn-sm">Back</a>
      </div>

      <div class="table-responsive mt-3">
        <table class="table table-sm align-middle" id="bkTable">
          <thead class="table-light">
            <tr>
              <th>Version</th>
              <th>File</th>
              <th class="text-end">Size</th>
              <th>Created</th>
              <th style="width: 1%;"></th>
            </tr>
          </thead>
          <tbody id="bkTbody">
            <tr><td colspan="5" class="text-muted p-3">Loading…</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <script>
      const tbody = document.getElementById('bkTbody');
      const fmtSize = (b) => {
        if (b == null) return '';
        const units = ['B','KB','MB','GB'];
        let i = 0, x = b;
        while (x >= 1024 && i < units.length-1) { x /= 1024; i++; }
        return x.toFixed(x >= 10 ? 0 : 1) + ' ' + units[i];
      };
      const esc = s => String(s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

      async function loadBackups(){
        try{
          const r = await fetch('/dashboard/api/backups/list', {headers:{'Accept':'application/json'}});
          const j = await r.json();
          if(!r.ok) throw new Error(j.error || ('HTTP '+r.status));
          const rows = (j.backups||[]).map(it => `
            <tr>
              <td><code>${esc(it.version_id)}</code></td>
              <td>${esc(it.file_name)}</td>
              <td class="text-end">${fmtSize(it.size_bytes)}</td>
              <td>${esc(it.created_at)}</td>
              <td class="text-nowrap">
                <a class="btn btn-sm btn-outline-primary" href="/dashboard/backups/download/${encodeURIComponent(it.file_name)}">Download</a>
              </td>
            </tr>`).join('');
          tbody.innerHTML = rows || '<tr><td colspan="5" class="text-muted p-3">No backups found.</td></tr>';
        }catch(e){
          tbody.innerHTML = `<tr><td colspan="5" class="text-danger p-3">Failed to load: ${esc(e.message)}</td></tr>`;
        }
      }
      loadBackups();
    </script>
    """
    return render_template(
        "dashboard.html",
        title="Deployment • Backups",
        subtitle="Download backup ZIPs created for REPLACE roles",
        body_html=body,
    )

@dashboard_bp.route("/api/backups/list")
@login_required
@roles_at_least("superadmin")
def api_backups_list():
    bdir = _backups_dir()
    items = []
    for name in os.listdir(bdir):
        if not name.lower().endswith(".zip"):
            continue
        path = os.path.join(bdir, name)
        version_id = name[:-4]
        try:
            ts = os.path.getmtime(path)
            size = os.path.getsize(path)
        except Exception:
            ts, size = 0, None

        # optional meta enrich (if present alongside main delivery)
        meta = _load_meta(version_id)
        items.append({
            "version_id": version_id,
            "file_name": name,
            "size_bytes": size,
            "created_ts": ts,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "",
            "target_env": (meta.get("backup", {}) or {}).get("target_env"),
            "roles_count": (meta.get("backup", {}) or {}).get("count"),
        })
    items.sort(key=lambda x: x["created_ts"], reverse=True)
    return jsonify({"backups": items})


@dashboard_bp.route("/backups/download/<path:fname>")
@login_required
@roles_at_least("superadmin")
def backups_download(fname):
    # prevent path traversal
    name = os.path.basename(fname)
    if not name.lower().endswith(".zip"):
        return jsonify({"error":"not_found"}), 404
    bdir = _backups_dir()
    fpath = os.path.join(bdir, name)
    if not os.path.exists(fpath):
        return jsonify({"error":"not_found"}), 404
    return send_from_directory(bdir, name, as_attachment=True)

@dashboard_bp.route("/users")
@login_required
@roles_at_least("superadmin")
def dash_users():
    # Language LOV (code, label)
    lang_lov = [
        ("en", "English"), ("sv", "Swedish"), ("de", "German"), ("fr", "French"),
        ("es", "Spanish"), ("it", "Italian"), ("pt", "Portuguese"), ("nl", "Dutch"),
        ("pl", "Polish"), ("tr", "Turkish"), ("zh", "Chinese"), ("ja", "Japanese")
    ]

    # Build the <option> markup once
    options_html = "".join([f'<option value="{c}">{lbl}</option>' for c, lbl in lang_lov])

    # Plain triple-quoted string (NOT an f-string) to avoid { } escaping hell
    body = """
    <div class="card p-3">
      <div class="d-flex align-items-center justify-content-between mb-2">
        <div>
          <h5 class="mb-0">Create User</h5>
          <small class="text-muted">Add a new application user</small>
        </div>
        <a href="{{ url_for('dashboard.dashboard_home') }}" class="btn btn-outline-secondary btn-sm">Back</a>
      </div>

      <div id="msg" class="alert d-none" role="alert"></div>

      <form id="userForm" class="row g-3">
        <div class="col-md-6">
          <label class="form-label">Name</label>
          <input type="text" class="form-control" id="name" required>
        </div>
        <div class="col-md-6">
          <label class="form-label">Language</label>
          <select class="form-select" id="language" required>
            <option value="">Select…</option>
    """ + options_html + """
          </select>
        </div>
        <div class="col-md-6">
          <label class="form-label">Contact email</label>
          <input type="email" class="form-control" id="email" required>
        </div>
        <div class="col-md-6">
          <label class="form-label">Username</label>
          <input type="text" class="form-control" id="username" required>
        </div>
        <div class="col-md-6">
          <label class="form-label">Password</label>
          <div class="input-group">
            <input type="password" class="form-control" id="password" minlength="6" required>
            <button type="button" class="btn btn-outline-secondary" id="togglePw">Show</button>
          </div>
          <div class="form-text">At least 6 characters.</div>
        </div>
        <div class="col-md-6">
          <label class="form-label">User type</label>
          <select class="form-select" id="user_type" required>
            <option value="">Select…</option>
            <option value="admin">Admin</option>
            <option value="standard">Standard user</option>
          </select>
        </div>
        <div class="col-12 d-grid d-sm-flex gap-2">
          <button type="submit" class="btn btn-primary">Create user</button>
          <button type="reset" class="btn btn-outline-secondary">Clear</button>
        </div>
      </form>
    </div>

    <div class="card p-3 mt-3">
      <div class="d-flex align-items-center justify-content-between">
        <h6 class="mb-0">Existing Users</h6>
        <button class="btn btn-sm btn-outline-secondary" id="refreshBtn">Refresh</button>
      </div>
      <div class="table-responsive mt-2">
        <table class="table table-sm table-hover align-middle mb-0">
          <thead class="table-light">
            <tr>
              <th>Name</th>
              <th>Username</th>
              <th>Email</th>
              <th>Language</th>
              <th>Type</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody id="usersTbody">
            <tr><td colspan="6" class="text-muted p-3">Loading…</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <script>
      const msg = document.getElementById('msg');
      function showMsg(kind, text){
        msg.className = 'alert alert-' + kind;
        msg.textContent = text;
        msg.classList.remove('d-none');
      }
      function hideMsg(){ msg.classList.add('d-none'); }

      // toggle password
      document.getElementById('togglePw').addEventListener('click', () => {
        const pw = document.getElementById('password');
        pw.type = pw.type === 'password' ? 'text' : 'password';
        document.getElementById('togglePw').textContent = pw.type === 'password' ? 'Show' : 'Hide';
      });

      // submit handler
      document.getElementById('userForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        hideMsg();
        const payload = {
          name: document.getElementById('name').value.trim(),
          language: document.getElementById('language').value,
          email: document.getElementById('email').value.trim(),
          username: document.getElementById('username').value.trim(),
          password: document.getElementById('password').value,
          user_type: document.getElementById('user_type').value
        };
        try{
          const r = await fetch('/dashboard/api/users', {
            method: 'POST',
            headers: {'Content-Type':'application/json','Accept':'application/json'},
            body: JSON.stringify(payload)
          });
          const j = await r.json();
          if(!r.ok || !j.ok) throw new Error(j.error || ('HTTP '+r.status));
          showMsg('success', 'User created successfully.');
          e.target.reset();
          loadUsers();
        }catch(err){
          showMsg('danger', err.message);
        }
      });

      document.getElementById('refreshBtn').addEventListener('click', () => loadUsers());

      function esc(s){ return String(s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]||c)); }
      function fmtTs(ts){ if(!ts) return ''; const d=new Date(ts*1000); return d.toLocaleString(); }

      async function loadUsers(){
        const tbody = document.getElementById('usersTbody');
        tbody.innerHTML = '<tr><td colspan="6" class="text-muted p-3">Loading…</td></tr>';
        try{
          const r = await fetch('/dashboard/api/users', {headers:{'Accept':'application/json'}});
          const j = await r.json();
          if(!r.ok || !j.ok) throw new Error(j.error || ('HTTP '+r.status));
          const rows = (j.users||[]).map(u => `
            <tr>
              <td>${esc(u.name)}</td>
              <td><code>${esc(u.username)}</code></td>
              <td>${esc(u.email)}</td>
              <td>${esc(u.language)}</td>
              <td>${esc(u.user_type)}</td>
              <td>${fmtTs(u.created_ts)}</td>
            </tr>
          `).join('');
          tbody.innerHTML = rows || '<tr><td colspan="6" class="text-muted p-3">No users yet.</td></tr>';
        }catch(e){
          tbody.innerHTML = '<tr><td colspan="6" class="text-danger p-3">Failed to load users.</td></tr>';
        }
      }

      loadUsers();
    </script>
    """

    return render_template(
        "dashboard.html",
        title="Users",
        subtitle="Create and view users",
        body_html=body,
    )


@dashboard_bp.route("/api/users", methods=["GET"])
@login_required
@roles_at_least("superadmin")   # keep your current rule
def api_users_list():
    try:
        # Read only safe columns; newest first
        res = supabase().table("app_users") \
            .select("id,name,language,email,username,user_type,created_at") \
            .order("created_at", desc=True) \
            .execute()

        rows = res.data or []
        def to_ts(iso):
            try:
                return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
            except Exception:
                return None

        safe = [{
            "id": r.get("id"),
            "name": r.get("name"),
            "language": r.get("language"),
            "email": r.get("email"),
            "username": r.get("username"),
            "user_type": r.get("user_type"),
            "created_ts": to_ts(r.get("created_at")) if r.get("created_at") else None,
        } for r in rows]

        return jsonify({"ok": True, "users": safe})
    except Exception as e:
        return jsonify({"ok": False, "error": "db_error", "details": str(e)}), 500


@dashboard_bp.route("/api/users", methods=["POST"])
@login_required
@roles_at_least("admin")  # optional but recommended; remove if you want anyone logged in to create
def api_users_create():
    data = request.get_json(force=True) or {}

    name      = (data.get("name") or "").strip()
    language  = (data.get("language") or "").strip()
    email     = (data.get("email") or "").strip()
    username  = (data.get("username") or "").strip()
    password  = (data.get("password") or "")
    user_type = (data.get("user_type") or "").strip().lower()

    # basic validation (unchanged semantics)
    if not all([name, language, email, username, password, user_type]):
        return jsonify({"ok": False, "error": "all_fields_required"}), 400
    if user_type not in {"admin", "standard"}:
        return jsonify({"ok": False, "error": "invalid_user_type"}), 400
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"ok": False, "error": "invalid_email"}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "password_too_short"}), 400

    try:
        # server-side hashing; store ONLY the hash
        pwd_hash = generate_password_hash(password)

        # Insert; unique (citext) and FK(language) enforced by DB
        res = supabase().table("app_users").insert({
            "name": name,
            "language": language,        # must exist in languages(code) if you created that table
            "email": email,
            "username": username,
            "password_hash": pwd_hash,
            "user_type": user_type,
        }).execute()

        # Handle PostgREST / Supabase errors (conflicts, FK, etc.)
        if getattr(res, "error", None):
            msg = str(res.error)
            if "duplicate key value" in msg and "username" in msg.lower():
                return jsonify({"ok": False, "error": "username_exists"}), 409
            if "duplicate key value" in msg and "email" in msg.lower():
                return jsonify({"ok": False, "error": "email_exists"}), 409
            if "foreign key constraint" in msg or "languages" in msg.lower():
                return jsonify({"ok": False, "error": "invalid_language"}), 400
            return jsonify({"ok": False, "error": "db_error", "details": msg}), 400

        row = (res.data or [{}])[0]
        return jsonify({"ok": True, "id": row.get("id")}), 201

    except Exception as e:
        # Some client versions raise exceptions for 409/400; catch and map them
        m = str(e)
        if "duplicate key value" in m and "username" in m.lower():
            return jsonify({"ok": False, "error": "username_exists"}), 409
        if "duplicate key value" in m and "email" in m.lower():
            return jsonify({"ok": False, "error": "email_exists"}), 409
        if "foreign key constraint" in m or "languages" in m.lower():
            return jsonify({"ok": False, "error": "invalid_language"}), 400
        return jsonify({"ok": False, "error": "db_error", "details": m}), 500


# --- History helpers (Supabase) ---
# --- History helpers (Supabase) ---
def _actor():
    return (
        session.get("username")
        or session.get("email")
        or session.get("name")
        or "anonymous"
    )

def _history_insert(permission_set: str, source_env: str, target_env: str, version_id: str, details: dict):
    """
    Inserts a history record into Supabase.ps_history.

    - If ps_history.version_id is UUID-typed, only store a valid UUID there.
      Otherwise store NULL and preserve the human code in details['version_code'].
    - Ensures details is JSON-serializable.
    """
    try:
        # 1) make details JSON-safe
        details = json.loads(json.dumps(details or {}, default=str))

        # 2) only write valid UUIDs into a uuid column
        try:
            v_uuid = str(_uuid.UUID(str(version_id))) if version_id else None
        except Exception:
            v_uuid = None
            if version_id:
                details = {**details, "version_code": str(version_id)}

        payload = {
            "permission_set": permission_set,
            "created_by": _actor(),
            "source_env": (source_env or None),
            "target_env": (target_env or None),
            "version_id": v_uuid,  # <-- safe
            "details": details,
        }

        res = supabase().table("ps_history").insert(payload).execute()
        if getattr(res, "error", None):
            current_app.logger.warning(f"ps_history insert error: {res.error}")
    except Exception as e:
        current_app.logger.warning(f"ps_history insert failed: {e}")


@dashboard_bp.route("/permission-set/history/<hid>")
@roles_at_least("admin")
@login_required
def dash_permission_history_detail(hid):
    import json
    body = """
    <div class="card p-3">
      <div class="d-flex align-items-center justify-content-between">
        <div>
          <h5 class="mb-0">History Detail</h5>
          <small class="text-muted">Snapshot of a permission set</small>
        </div>
        <a href="{{ url_for('dashboard.dash_permission_history') }}" class="btn btn-outline-secondary btn-sm">Back</a>
      </div>

      <div id="meta" class="mt-3"></div>
      <div id="sections" class="mt-3"></div>
    </div>

    <script>
      const hid = __HID__;
      function esc(s){ return String(s||'').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c] || c)); }
      function fmtIso(s){ try{ return new Date(s).toLocaleString(); }catch(e){ return s||''; } }

      function renderMeta(it){
        const m = document.getElementById('meta');
        m.innerHTML = `
          <div class="row g-3">
            <div class="col-md-4"><div class="p-2 border rounded">
              <div class="text-muted small">Permission Set</div>
              <div class="fw-semibold"><code>${esc(it.permission_set)}</code></div>
            </div></div>
            <div class="col-md-2"><div class="p-2 border rounded">
              <div class="text-muted small">Created by</div>
              <div class="fw-semibold">${esc(it.created_by||'')}</div>
            </div></div>
            <div class="col-md-3"><div class="p-2 border rounded">
              <div class="text-muted small">Created at</div>
              <div class="fw-semibold">${fmtIso(it.created_at)}</div>
            </div></div>
            <div class="col-md-3"><div class="p-2 border rounded">
              <div class="text-muted small">Version ID</div>
              <div class="fw-semibold"><code>${esc(it.version_id||'')}</code></div>
            </div></div>
          </div>
          <div class="row g-3 mt-1">
            <div class="col-md-2"><div class="p-2 border rounded">
              <div class="text-muted small">Source env</div>
              <div class="fw-semibold">${esc(it.source_env||'')}</div>
            </div></div>
            <div class="col-md-2"><div class="p-2 border rounded">
              <div class="text-muted small">Target env</div>
              <div class="fw-semibold">${esc(it.target_env||'')}</div>
            </div></div>
          </div>
        `;
      }

      function renderSection(title, items){
        const el = document.createElement('div');
        el.className = 'mb-3';
        el.innerHTML = `
          <div class="d-flex align-items-center justify-content-between">
            <h6 class="mb-1">${esc(title)}</h6>
          </div>
          <div class="table-responsive mt-2">
            <table class="table table-sm table-hover align-middle mb-0">
              <thead class="table-light"><tr><th>Name</th><th>Info</th></tr></thead>
              <tbody>${items.map(it => `
                <tr><td><code>${esc(it.name||it.projection||it.report||it.user||'')}</code></td>
                    <td>${esc(it.info||it.description||'')}</td></tr>`).join('')}
              </tbody>
            </table>
          </div>
        `;
        return el;
      }

      function renderDetails(details){
        const host = document.getElementById('sections');
        host.innerHTML = '';
        const roles = (details && details.roles) || [];
        const snapshots = (details && details.snapshots) || {};
        const roleKeys = Object.keys(snapshots);
        if(!roleKeys.length){
          const warn = document.createElement('div');
          warn.className = 'alert alert-warning';
          warn.textContent = 'No detailed grants captured for this snapshot.';
          host.appendChild(warn);
          if (roles.length){
            const p = document.createElement('p');
            p.className = 'subtle';
            p.textContent = 'Roles included: ' + roles.join(', ');
            host.appendChild(p);
          }
          return;
        }
        roleKeys.forEach(r => {
          const card = document.createElement('div');
          card.className = 'card p-3 mb-3';
          card.innerHTML = `<h6 class="mb-2">Role: <code>${esc(r)}</code></h6>`;
          const s = snapshots[r] || {};
          if (Array.isArray(s.projections) && s.projections.length) card.appendChild(renderSection('Projections', s.projections));
          if (Array.isArray(s.reports) && s.reports.length)       card.appendChild(renderSection('Reports', s.reports));
          if (Array.isArray(s.users) && s.users.length)           card.appendChild(renderSection('Users', s.users));
          if (Array.isArray(s.structures) && s.structures.length) card.appendChild(renderSection('Structures', s.structures));
          host.appendChild(card);
        });
      }

      (async function(){
        try{
          const r = await fetch('/dashboard/api/ps-history/' + hid, {headers:{'Accept':'application/json'}});
          const j = await r.json();
          if(!r.ok || !j.ok) throw new Error(j.error||('HTTP '+r.status));
          renderMeta(j.item);
          renderDetails(j.item.details||{});
        }catch(e){
          document.getElementById('meta').innerHTML =
            '<div class="alert alert-danger">Failed to load detail.</div>';
        }
      })();
    </script>
    """.replace("__HID__", json.dumps(hid))

    return render_template(
        "dashboard.html",
        title="Permission set • History detail",
        subtitle="Snapshot",
        body_html=body,
    )



@dashboard_bp.route("/api/ps-history/list")
@roles_at_least("admin")
@login_required
def api_ps_history_list():
    try:
        res = supabase().table("ps_history") \
            .select("id,permission_set,created_by,created_at,source_env,target_env,version_id") \
            .order("created_at", desc=True).execute()
        items = res.data or []
        return jsonify({"ok": True, "items": items})
    except Exception as e:
        return jsonify({"ok": False, "error": "db_error", "details": str(e)}), 500


@dashboard_bp.route("/api/ps-history/<hid>")
@roles_at_least("admin")
@login_required
def api_ps_history_get(hid):
    try:
        res = supabase().table("ps_history").select("*").eq("id", hid).limit(1).execute()
        data = res.data or []
        if not data:
            return jsonify({"ok": False, "error": "not_found"}), 404
        return jsonify({"ok": True, "item": data[0]})
    except Exception as e:
        return jsonify({"ok": False, "error": "db_error", "details": str(e)}), 500


@dashboard_bp.route("/api/ps-history/test-insert", methods=["GET", "POST"])
@login_required
def api_ps_history_test_insert():
    try:
        res = supabase().table("ps_history").insert({
            "permission_set": "TEST_ROLE",
            "created_by": session.get("username") or "tester",
            "source_env": "DEV",
            "target_env": "DEV",
            "version_id": str(_uuid.uuid4()),  # real UUID
            "details": {"ping": "pong", "note": "test route"}
        }).execute()
        return jsonify({"ok": True, "data": getattr(res, "data", None)})
    except Exception as e:
        return jsonify({"ok": False, "err": str(e)}), 500


# ======================= Templates =======================

@dashboard_bp.route("/api/templates", methods=["POST"])
@login_required
@roles_at_least("admin")
def api_templates_create():
    """
    Save a permission-set snapshot as a reusable Template.

    Expected JSON body:
    {
      "name": "OPS_FullOrderMgmt v1",
      "permission_set": "OPS_FullOrderMgmt",
      "projections": [...],   # list (strings or objects)
      "commands": [...],      # list or mapping: [{"projection":"X","commands":["Create","Modify"]}, ...] or any JSON
      "users": [...],         # list
      "structures": [...],    # list
      "source_env": "DEV",    # optional
      "version_id": "pw_241008_171522"   # optional human code or uuid; stored as text/json, not typed uuid
    }
    """
    data = request.get_json(force=True) or {}

    name            = (data.get("name") or "").strip()
    permission_set  = (data.get("permission_set") or "").strip()

    # normalize collections to JSON-friendly lists
    def _as_list(v):
        if v is None:
            return []
        return v if isinstance(v, list) else [v]

    projections = _as_list(data.get("projections"))
    commands    = data.get("commands") if data.get("commands") is not None else []  # can be list or dict
    users       = _as_list(data.get("users"))
    structures  = _as_list(data.get("structures"))

    source_env  = (data.get("source_env") or "").strip() or None
    version_id  = data.get("version_id")  # keep as-is (text/JSON), do NOT coerce to UUID

    if not permission_set:
        return jsonify({"ok": False, "error": "permission_set_required"}), 400

    # default name if none provided
    if not name:
        name = f"Template for {permission_set}"

    try:
        payload = {
            "name": name,
            "permission_set": permission_set,
            "projections": projections,
            "commands": commands,
            "users": users,
            "structures": structures,
            "source_env": source_env,
            "version_id": version_id,
            "created_by": _actor(),
        }
        # Ensure full JSON-serializability
        payload = json.loads(json.dumps(payload, default=str))

        res = supabase().table("templates").insert(payload).execute()
        if getattr(res, "error", None):
            return jsonify({"ok": False, "error": "db_error", "details": str(res.error)}), 400

        return jsonify({"ok": True, "template": (res.data or [{}])[0]})
    except Exception as e:
        return jsonify({"ok": False, "error": "db_error", "details": str(e)}), 500


@dashboard_bp.route("/api/templates", methods=["GET"])
@login_required
@roles_at_least("admin")
def api_templates_list():
    """
    List saved templates (basic columns).
    """
    try:
        res = supabase().table("templates") \
            .select("id,name,permission_set,created_by,created_at,source_env,version_id") \
            .order("created_at", desc=True) \
            .execute()
        return jsonify({"ok": True, "templates": res.data or []})
    except Exception as e:
        return jsonify({"ok": False, "error": "db_error", "details": str(e)}), 500


@dashboard_bp.route("/api/templates/<tid>", methods=["GET"])
@login_required
@roles_at_least("admin")
def api_templates_get(tid):
    """
    Get full template (including Projections/Commands/Users/Structures).
    """
    try:
        res = supabase().table("templates").select("*").eq("id", tid).limit(1).execute()
        rows = res.data or []
        if not rows:
            return jsonify({"ok": False, "error": "not_found"}), 404
        return jsonify({"ok": True, "template": rows[0]})
    except Exception as e:
        return jsonify({"ok": False, "error": "db_error", "details": str(e)}), 500

@dashboard_bp.route("/api/setup-ifs/envs/test", methods=["POST"])
@login_required
@roles_at_least("admin")  # or "superadmin" if you prefer
def test_env_connection():
    """Test token retrieval for the named environment (client_credentials)."""
    try:
        j = request.get_json(force=True) or {}
        name = (j.get("name") or "").strip()
        if not name:
            return jsonify({"ok": False, "error": "Missing env name"}), 400

        envs = list_envs_full() or {}
        env_map = envs.get("environments") or {}
        env = env_map.get(name)
        if not env:
            return jsonify({"ok": False, "error": f"Env '{name}' not found"}), 404

        # Pull config (support both generic keys and cfg_* mirrors)
        base_root = (env.get("base_root") or env.get("cfg_base_root") or "").rstrip("/")
        realm = (env.get("realm") or env.get("cfg_realm") or "").strip()
        client_id = (env.get("client_id") or env.get("cfg_client_id") or "").strip()
        client_secret = env.get("client_secret") or env.get("cfg_client_secret") or ""
        scope = (env.get("scope") or env.get("cfg_scope") or "openid microprofile-jwt").strip()
        ssl_verify = bool(env.get("ssl_verify", env.get("cfg_ssl_verify", True)))
        token_url = (env.get("token_url") or env.get("cfg_token_url") or "").strip()

        if not token_url:
            if not base_root or not realm:
                return jsonify({"ok": False, "error": "Missing base_root/realm/token_url"}), 400
            token_url = f"{base_root}/auth/realms/{realm}/protocol/openid-connect/token"

        if not client_id or not client_secret:
            return jsonify({"ok": False, "error": "Missing client_id/client_secret"}), 400

        # Client credentials grant
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if scope:
            data["scope"] = scope

        resp = requests.post(token_url, data=data, timeout=12, verify=ssl_verify)
        if resp.status_code != 200:
            return jsonify({
                "ok": False,
                "error": f"HTTP {resp.status_code}",
                "body": safe_tail(resp.text),
            }), 200  # 200 so UI can read JSON consistently

        try:
            jresp = resp.json()
        except Exception:
            return jsonify({"ok": False, "error": "Non-JSON token response"}), 200

        access_token = jresp.get("access_token")
        id_token = jresp.get("id_token")
        if access_token or id_token:
            # success; return minimal metadata for UI
            return jsonify({
                "ok": True,
                "token_kind": "access" if access_token else "id",
                "len": len(access_token or id_token or ""),
            }), 200

        return jsonify({"ok": False, "error": "No token in response"}), 200

    except requests.exceptions.SSLError:
        return jsonify({"ok": False, "error": "TLS verification failed"}), 200
    except requests.exceptions.Timeout:
        return jsonify({"ok": False, "error": "Timeout"}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200


def safe_tail(s: str, n: int = 256) -> str:
    """Return tail of a long error body for debug (avoid dumping secrets)."""
    s = s or ""
    return s[-n:] if len(s) > n else s