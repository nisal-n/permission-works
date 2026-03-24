from flask import Flask, redirect, url_for
from .config import Config
from .auth import auth_bp, init_auth
from .dashboard import dashboard_bp
from .routes.tracing import tracing_bp
from .routes.permissions import permissions_bp
from .api import api_bp  # <-- ADD THIS

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Auth (login/logout + decorator)
    init_auth(app)
    app.register_blueprint(auth_bp)

    # Feature blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(tracing_bp)
    app.register_blueprint(permissions_bp)
    app.register_blueprint(api_bp)  # <-- now defined

    # --- FORCE-REGISTER the UI endpoint so url_for("permissions.create_permission_ui") always resolves ---
    from .routes.permissions import create_permission_ui as _create_permission_ui
    app.add_url_rule(
        f"{permissions_bp.url_prefix or ''}/create_permission_ui",
        endpoint="permissions.create_permission_ui",
        view_func=_create_permission_ui,
        methods=["GET"],
    )

    # default landing → dashboard
    @app.route("/")
    def home():
        return redirect(url_for("dashboard.dashboard_home"))

    return app
