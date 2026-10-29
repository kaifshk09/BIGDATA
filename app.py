"""
PhishGuard — Phishing URL Detection System
==========================================
Flask + SQLite college project. The analyzer only reads the URL string; it
never opens, resolves or downloads the submitted address.

Run locally:
    python -m pip install -r requirements.txt
    python app.py

Routes
------
GET  /                 Dashboard (stats, scanner, recent scans)
POST /scan             Analyse a URL, save the result, redirect to dashboard
GET  /history          Persistent scan history with search + risk filter
POST /history/clear    Delete all history (CSRF + confirmation phrase)
POST /history/<id>/delete  Delete one scan (CSRF)
GET  /about            How it works, scoring system, limitations
GET  /healthz          Small JSON health check used by the tests
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading

from flask import (
    Flask,
    abort,
    flash,
    get_flashed_messages,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from core import config
from core.analysis import analyze_url
from core import database as db
from core.security import csrf

log = logging.getLogger("phishguard")

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(database_path: str | None = None, testing: bool = False) -> Flask:
    """
    Build and configure the Flask application.

    `database_path` and `testing` exist so the automated tests can use a
    temporary SQLite file without touching the real phishguard.db.
    """
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config.load_secret_key(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=64 * 1024,  # 64 KB is plenty for one URL form
        TEMPLATES_AUTO_RELOAD=True,
        TESTING=testing,
    )

    if database_path:
        app.config["DATABASE_PATH"] = database_path
        config.DB_PATH = database_path
    else:
        app.config["DATABASE_PATH"] = config.DB_PATH

    csrf.init_app(app)

    # Template globals -------------------------------------------------------
    @app.context_processor
    def inject_globals():
        return {
            "disclaimer": config.DISCLAIMER,
            "verdict_meta": config.VERDICT_META,
            "allow_clear_history": config.ALLOW_CLEAR_HISTORY,
            "risk_slug": db.risk_slug,
            "format_time": db.format_time,
            "messages": get_flashed_messages(with_categories=True),
        }

    @app.template_filter("host_only")
    def host_only(value: str) -> str:
        """Short display form of a URL host (used in compact table cells)."""
        text = str(value or "")
        text = text.split("://", 1)[-1]
        return text.split("/", 1)[0] or text

    @app.template_filter("shorten")
    def shorten(value: str, length: int = 70) -> str:
        text = str(value or "")
        return text if len(text) <= length else text[: length - 1] + "…"

    # Initialise the database as soon as the app is created so the very first
    # request cannot fail on a missing table. The real phishguard.db is only
    # touched when the app is created normally (not when tests import this
    # module), which keeps test runs isolated.
    if not testing:
        db.init_db(app.config["DATABASE_PATH"])

    register_routes(app)
    register_error_handlers(app)

    log.info("PhishGuard ready · database=%s", app.config["DATABASE_PATH"])
    return app


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def register_routes(app: Flask) -> None:

    @app.get("/")
    def index():
        """Dashboard: statistics, the scanner form and the latest scans."""
        try:
            stats = db.get_stats()
            recent = db.get_recent_scans(limit=5)
        except sqlite3.DatabaseError:
            log.exception("Could not load dashboard data")
            abort(503, description="The scan history database is temporarily unavailable.")

        return render_template(
            "index.html",
            stats=stats,
            recent=recent,
            result=None,
            submitted_url="",
        )

    @app.post("/scan")
    def scan():
        """
        Analyse the submitted URL and redirect to the dashboard.

        Redirect-after-POST prevents duplicate rows when the user refreshes,
        while PRG keeps the UI simple and shareable.
        """
        raw_url = request.form.get("url", "")
        if not isinstance(raw_url, str):
            raw_url = ""
        raw_url = raw_url.strip()

        if not raw_url:
            flash("Please enter a URL to analyse.", "error")
            return redirect(url_for("index"))
        if len(raw_url) > config.MAX_URL_LENGTH:
            flash(
                f"That URL is longer than {config.MAX_URL_LENGTH} characters. "
                "Please shorten it and try again.",
                "error",
            )
            return redirect(url_for("index"))

        result = analyze_url(raw_url)

        # Re-render the dashboard with the result (instead of redirecting) so
        # the user immediately sees the breakdown and explanations.
        try:
            saved = db.save_scan(result)
        except sqlite3.DatabaseError:
            log.exception("Could not save scan")
            flash("Scan completed, but saving it to history failed.", "warning")
            saved = None

        try:
            stats = db.get_stats()
            recent = db.get_recent_scans(limit=5)
        except sqlite3.DatabaseError:
            stats = {"total": 0, "high": 0, "suspicious": 0, "lower": 0,
                     "average_score": 0, "top_score": 0}
            recent = []

        if result.is_valid:
            flash("Scan complete. Review the indicators below.", "success")
        else:
            flash(result.error or "The URL could not be analysed.", "error")

        http_status = 200 if result.is_valid else 400
        return render_template(
            "index.html",
            stats=stats,
            recent=recent,
            result=result,
            submitted_url=raw_url,
            saved_id=saved,
        ), http_status

    @app.get("/history")
    def history():
        """Scan history with server-side search and risk-level filtering."""
        search = (request.args.get("q") or "").strip()[: config.MAX_QUERY_LENGTH]
        mode = request.args.get("risk", "all")
        if mode not in db.MODES:
            mode = "all"

        page = request.args.get("page", 1, type=int) or 1
        page = max(1, page)
        per_page = 25

        try:
            rows = db.get_history(search=search, mode=mode, limit=per_page * page + 1)
            stats = db.get_stats()
        except sqlite3.DatabaseError:
            log.exception("Could not load history")
            abort(503, description="The scan history database is temporarily unavailable.")

        has_more = len(rows) > per_page * page
        visible = rows[(page - 1) * per_page: page * per_page]

        items = []
        for row in visible:
            items.append({
                "row": row,
                "findings": db.load_findings(row),
                "slug": db.risk_slug(row["verdict"]),
            })

        return render_template(
            "history.html",
            items=items,
            search=search,
            mode=mode,
            stats=stats,
            page=page,
            per_page=per_page,
            has_more=has_more,
            last_id=visible[-1]["id"] if visible else 0,
        )

    @app.post("/history/clear")
    def clear_history():
        """Delete all scans. Requires CSRF token + typed confirmation."""
        if not config.ALLOW_CLEAR_HISTORY:
            abort(403, description="Clearing history is disabled on this installation.")

        confirm = (request.form.get("confirm") or "").strip().upper()
        if confirm != "CLEAR":
            flash("History was not cleared. Type CLEAR to confirm.", "error")
            return redirect(url_for("history"))

        try:
            deleted = db.clear_history()
        except sqlite3.DatabaseError:
            log.exception("Could not clear history")
            abort(503, description="The scan history database is temporarily unavailable.")

        flash(f"Scan history cleared ({deleted} record{'s' if deleted != 1 else ''} removed).", "success")
        return redirect(url_for("history"))

    @app.post("/history/<int:scan_id>/delete")
    def delete_history_item(scan_id: int):
        """Delete one scan record."""
        try:
            removed = db.delete_scan(scan_id)
        except sqlite3.DatabaseError:
            log.exception("Could not delete scan %s", scan_id)
            abort(503, description="The scan could not be deleted right now.")

        if removed:
            flash("Scan record deleted.", "success")
        else:
            flash("That scan record does not exist.", "error")
        return redirect(url_for("history"))

    @app.get("/about")
    def about():
        return render_template("about.html", stats=_safe_stats())

    @app.get("/healthz")
    def healthz():
        """Tiny JSON endpoint: shows the app is alive and the DB is readable."""
        try:
            total = db.count_scans()
            ok = True
        except sqlite3.DatabaseError:
            total, ok = None, False
        return jsonify({"status": "ok" if ok else "degraded", "scans": total})


def _safe_stats() -> dict:
    try:
        return db.get_stats()
    except sqlite3.DatabaseError:
        return {"total": 0, "high": 0, "suspicious": 0, "lower": 0,
                "average_score": 0, "top_score": 0}


# ---------------------------------------------------------------------------
# Error handlers — friendly pages instead of Flask tracebacks
# ---------------------------------------------------------------------------

def register_error_handlers(app: Flask) -> None:

    @app.errorhandler(400)
    def bad_request(error):
        message = getattr(error, "description", None) or "The request could not be understood."
        return render_template("error.html", code=400, title="Request could not be verified",
                               message=message), 400

    @app.errorhandler(403)
    def forbidden(error):
        message = getattr(error, "description", None) or "You do not have permission to do that."
        return render_template("error.html", code=403, title="Not allowed",
                               message=message), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("error.html", code=404, title="Page not found",
                               message="The page you were looking for does not exist."), 404

    @app.errorhandler(413)
    def too_large(error):
        return render_template("error.html", code=413, title="Input too large",
                               message="The submitted form was too large. Please paste a single URL."), 413

    @app.errorhandler(500)
    def server_error(error):
        return render_template("error.html", code=500, title="Something went wrong",
                               message="An unexpected error occurred. Please try again."), 500

    @app.errorhandler(sqlite3.DatabaseError)
    def database_error(error):
        log.exception("Database error")
        return render_template("error.html", code=503, title="Database unavailable",
                               message="The scan history database could not be read. "
                                       "Restart the app and try again."), 503


# Module-level app so `flask run` and WSGI servers also work. Tests import
# `create_app` directly and build their own isolated instance instead.
app = None if "PYTEST_CURRENT_TEST" in os.environ else create_app()


if __name__ == "__main__":
    # debug=True gives auto-reload while developing, but the reloader spawns a
    # child thread, which breaks on some launchers (IDE consoles) with
    # "signal only works in main thread of the main interpreter".
    in_main_thread = threading.current_thread() is threading.main_thread()
    if in_main_thread:
        app.run(host="127.0.0.1", port=5000, debug=True)
    else:
        # Running in a non-main thread: the reloader cannot install signal
        # handlers here, so serve without it (the debugger still works).
        print(" * Debug reloader disabled (not in main thread)")
        app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
