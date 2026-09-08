"""WSGI entry point for the hosted status service.

Kept separate from hosted_status.py for the reason broker_wsgi.py is kept
separate from oauth_broker.py: importing the logic must never require a
configured environment. A test, a lint pass, or a container build step that
imports hosted_status gets an inert module; only this file constructs
anything, and only on the first request.

Configuration comes entirely from the environment; see hosted.env.example.
"""
import os

from hosted_status import HostedConfig, HostedStatusApp


_app = None


def build_application(env=None):
    """Construct the app from environment configuration.

    Raises HostedConfigError if the environment is not safely configured or
    the state volume cannot support atomic rename and advisory locking, which
    fails the deploy rather than serving an instance that will lose its
    connection record on the next recycle.
    """
    config = HostedConfig.from_environment(env if env is not None else os.environ)
    return HostedStatusApp(config)


def application(environ, start_response):
    """WSGI callable. Builds on first request, then reuses.

    Reused rather than rebuilt so the state-volume probe runs once per
    process instead of once per request.
    """
    global _app
    if _app is None:
        _app = build_application()
    return _app(environ, start_response)
