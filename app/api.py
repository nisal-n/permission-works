from flask import Blueprint, jsonify, request
from .auth import login_required
from .services.ifs import (
    get_access_token, fetch_permission_sets,
    export_permission_start, export_permission_update_list,
    export_permission_create_export, export_permission_get_zip
)

api_bp = Blueprint("api", __name__, url_prefix="/api")

@api_bp.route("/deploy/export/start", methods=["POST"])
@login_required
def api_export_start():
    token = get_access_token()
    if not token:
        return jsonify({"error":"token_failed"}), 500
    objkey, err = export_permission_start(token)
    if err or not objkey:
        return jsonify({"error":"export_start_failed", "details": err}), 502
    return jsonify({"objkey": objkey})

@api_bp.route("/deploy/export/roles")
@login_required
def api_export_roles():
    token = get_access_token()
    if not token:
        return jsonify({"error":"token_failed"}), 500
    roles = fetch_permission_sets(token, top=500)
    return jsonify({"roles": roles})

@api_bp.route("/deploy/export/update", methods=["POST"])
@login_required
def api_export_update():
    data = request.get_json(force=True) or {}
    objkey = data.get("objkey")
    roles = data.get("roles") or []
    if not objkey or not roles:
        return jsonify({"error":"missing_objkey_or_roles"}), 400
    token = get_access_token()
    if not token:
        return jsonify({"error":"token_failed"}), 500
    ok, err = export_permission_update_list(token, objkey, [r.strip() for r in roles if r and r.strip()])
    if not ok:
        return jsonify({"error":"update_failed", "details": err}), 502
    return jsonify({"status":"ok"})

@api_bp.route("/deploy/export/create", methods=["POST"])
@login_required
def api_export_create():
    data = request.get_json(force=True) or {}
    objkey = data.get("objkey")
    user_grants = bool(data.get("user_grants", True))
    user_group_grants = bool(data.get("user_group_grants", False))
    if not objkey:
        return jsonify({"error":"missing_objkey"}), 400
    token = get_access_token()
    if not token:
        return jsonify({"error":"token_failed"}), 500
    ok, err = export_permission_create_export(token, objkey, user_grants=user_grants, user_group_grants=user_group_grants)
    if not ok:
        return jsonify({"error":"create_export_failed", "details": err}), 502
    return jsonify({"status":"ok"})

@api_bp.route("/deploy/export/zip", methods=["POST"])
@login_required
def api_export_zip():
    data = request.get_json(force=True) or {}
    objkey = data.get("objkey")
    if not objkey:
        return jsonify({"error":"missing_objkey"}), 400
    token = get_access_token()
    if not token:
        return jsonify({"error":"token_failed"}), 500
    path, err = export_permission_get_zip(token, objkey)
    if err or not path:
        return jsonify({"error":"zip_failed", "details": err}), 502
    return jsonify({"download": f"sandbox:{path}"})
