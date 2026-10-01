"""
Регистрация middleware и глобальных перехватчиков запросов (пункт 3.4).
"""
from flask import abort, g, request, session
from werkzeug.middleware.proxy_fix import ProxyFix
from app.constants import CSP_POLICY, PERMISSIONS_POLICY, SERVER_HEADER
from app.db import get_db
from app.security import get_user_from_token, validate_csrf

def register_middleware(app):
    if app.config.get("BEHIND_PROXY"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=app.config.get("NUM_PROXIES", 1), x_proto=1, x_host=1)

    @app.before_request
    def check_trusted_hosts():
        trusted = app.config.get("TRUSTED_HOSTS")
        if trusted:
            host_header = request.host.split(":")[0]
            if host_header not in trusted and host_header not in ("127.0.0.1", "localhost", "testserver"):
                abort(400, description="Недопустимый заголовок Host.")

    @app.before_request
    def load_logged_in_user():
        token = session.get("sid")
        user_id = session.get("user_id")
        g.current_user = None

        if token or user_id:
            db = get_db()
            if token:
                g.current_user = get_user_from_token(db, token)
            if not g.current_user and user_id:
                cur = db.cursor()
                cur.execute("SELECT id, username, role, created_at, updated_at FROM users WHERE id = ?", (user_id,))
                row = cur.fetchone()
                if row:
                    g.current_user = dict(row)

    @app.before_request
    def csrf_protect():
        if not app.config.get("TESTING"):
            validate_csrf()

    @app.after_request
    def apply_security_headers(response):
        response.headers["Server"] = SERVER_HEADER
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = PERMISSIONS_POLICY
        response.headers["Content-Security-Policy"] = CSP_POLICY
        if app.config.get("COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
