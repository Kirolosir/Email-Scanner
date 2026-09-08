"""WSGI entry point for the authenticated hosted dashboard."""
import os

from hosted_dashboard import build_application


_app = None


def application(environ, start_response):
    global _app
    if _app is None:
        _app = build_application(os.environ)
    return _app(environ, start_response)
