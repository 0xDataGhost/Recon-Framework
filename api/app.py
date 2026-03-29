"""api/app.py — Flask application factory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, render_template


def create_app(config: dict[str, Any] | None = None) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config: Framework config dict. Dashboard sub-keys are read from
                config["dashboard"] if present.

    Returns:
        Configured :class:`flask.Flask` instance.
    """
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent.parent / "dashboard" / "templates"),
        static_folder=str(Path(__file__).parent.parent / "dashboard" / "static"),
        static_url_path="/static",
    )

    app.config["SECRET_KEY"] = (config or {}).get("secret_key", "recon-dev-secret")
    app.config["RECON_CONFIG"] = config or {}

    # ── Blueprints ─────────────────────────────────────────────────────────────
    from api.routes.scan import bp as scan_bp
    app.register_blueprint(scan_bp)

    # ── Dashboard index ────────────────────────────────────────────────────────
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/target/<target>")
    def target_detail(target: str):
        return render_template("target.html", target=target)

    return app
