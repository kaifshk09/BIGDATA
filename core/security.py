"""
Lightweight CSRF protection built only on the standard library + Flask.

How it works
------------
1. On every request `CSRFProtect.init_app` loads (or creates) a random token
   in the user's signed session cookie.
2. Templates print the token inside state-changing forms with `{{ csrf_token() }}`.
3. On POST/PUT/PATCH/DELETE the token in the form is compared with the session
   token (constant-time comparison). A mismatch is rejected with HTTP 400.

We keep it tiny on purpose: no extra dependency for a college project, while
still following the SameSite + synchroniser-token pattern.
"""
import hmac
import secrets

from flask import abort, request, session

TOKEN_SESSION_KEY = "_csrf_token"
FORM_FIELD = "csrf_token"
PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _current_token() -> str:
    token = session.get(TOKEN_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[TOKEN_SESSION_KEY] = token
    return token


class CSRFProtect:
    """Flask extension (very small) that verifies CSRF tokens on unsafe methods."""

    def __init__(self, app=None):
        self.app = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        app.jinja_env.globals["csrf_token"] = _current_token
        app.before_request(self._verify)

    def _verify(self):
        if request.method not in PROTECTED_METHODS:
            return None

        expected = session.get(TOKEN_SESSION_KEY)
        supplied = request.form.get(FORM_FIELD, "") or request.headers.get("X-CSRF-Token", "")

        if not expected or not supplied or not hmac.compare_digest(str(expected), str(supplied)):
            abort(400, description="Your form session expired or the request could not be verified. Please reload the page and try again.")
        return None


csrf = CSRFProtect()
