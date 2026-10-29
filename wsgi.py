"""
WSGI entry point for production servers (Gunicorn, Waitress, Render, Railway...).

    gunicorn wsgi:app
    waitress-serve --port=8000 wsgi:app

Kept separate from app.py because app.py starts Flask's *development* server
when run directly, which must never be used to serve real traffic.
"""
from app import create_app

# Gunicorn looks for a module-level variable named `app`.
app = create_app()
