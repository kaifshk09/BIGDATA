"""
Application configuration.

Everything that a beginner might want to tweak (paths, limits, messages)
lives here so the rest of the code stays clean.
"""
import os
from pathlib import Path

# Absolute path to the project folder (the folder that contains app.py).
BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# PHISHGUARD_DB lets the automated tests use a temporary database file.
DB_PATH = os.environ.get("PHISHGUARD_DB", str(BASE_DIR / "phishguard.db"))

# ---------------------------------------------------------------------------
# Secrets / CSRF
# ---------------------------------------------------------------------------
# An environment variable can be supplied for a stable secret. If it is not
# set we create a random key file on first run so CSRF tokens stay valid
# across restarts (important on Windows, where the dev server restarts a lot).
SECRET_KEY_ENV = "PHISHGUARD_SECRET_KEY"
SECRET_KEY_FILE = BASE_DIR / ".flask_secret"


def load_secret_key() -> bytes:
    """Return the Flask secret key used to sign CSRF tokens."""
    env_key = os.environ.get(SECRET_KEY_ENV)
    if env_key:
        return env_key.encode("utf-8")

    try:
        if SECRET_KEY_FILE.exists():
            stored = SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
            if stored:
                return stored.encode("utf-8")
        new_key = os.urandom(32).hex()
        SECRET_KEY_FILE.write_text(new_key, encoding="utf-8")
        return new_key.encode("utf-8")
    except OSError:
        # Read-only folder? Fall back to an in-memory random key. The app still
        # works, but CSRF tokens expire whenever the server restarts.
        return os.urandom(32)


# ---------------------------------------------------------------------------
# Input limits (protect the app from absurdly large payloads)
# ---------------------------------------------------------------------------
MAX_URL_LENGTH = 2048      # Characters of URL accepted from the form
DB_URL_LENGTH = 1024       # URLs longer than this are truncated before saving
MAX_QUERY_LENGTH = 200     # Maximum length of the history search box

# ---------------------------------------------------------------------------
# Feature switches
# ---------------------------------------------------------------------------
# Set PHISHGUARD_ALLOW_CLEAR=0 to hide the "Clear history" button, for example
# on a shared demo laptop.
ALLOW_CLEAR_HISTORY = os.environ.get("PHISHGUARD_ALLOW_CLEAR", "1") not in ("0", "false", "False")

# ---------------------------------------------------------------------------
# Result labels mapped to CSS classes / icons in the templates
# ---------------------------------------------------------------------------
VERDICT_META = {
    "High Risk": {
        "slug": "high",
        "icon": "alert-triangle",
        "summary": "Several strong phishing indicators were found.",
    },
    "Suspicious": {
        "slug": "suspicious",
        "icon": "alert-circle",
        "summary": "Some warning signs are present. Verify before trusting it.",
    },
    "Lower Risk": {
        "slug": "low",
        "icon": "shield-check",
        "summary": "No major heuristic warning was triggered.",
    },
    "Invalid URL": {
        "slug": "invalid",
        "icon": "x-circle",
        "summary": "This input could not be analysed as a web address.",
    },
}

DISCLAIMER = (
    "Heuristic estimates only. PhishGuard checks URL structure — it does not "
    "open the link, inspect page content, or confirm that a site is safe. "
    "A low score is not a guarantee of safety."
)
