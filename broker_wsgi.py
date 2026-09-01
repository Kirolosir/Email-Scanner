"""WSGI entry point for the OAuth broker.

Kept separate from oauth_broker.py so that module stays inert and importable
with no configuration: importing the broker's logic must never require a
client secret to be present, and must never construct anything live.

A WSGI server (gunicorn) imports `application` from here. This module still
starts no listener of its own - the server provides that.

Configuration comes entirely from the environment; see broker.env.example.
Construction is lazy so that importing this module in a test, or during a
build step with no secrets available, does not raise.
"""
import os

from oauth_broker import BrokerConfig, OAuthBroker

_broker = None


def build_application(env=None):
    """Construct the broker from environment configuration.

    Raises BrokerConfigError if the environment is not safely configured,
    which fails the deploy rather than serving an insecure broker.
    """
    config = BrokerConfig.from_environment(env if env is not None else os.environ)
    return OAuthBroker(config)


def application(environ, start_response):
    """WSGI callable. Builds the broker on first request, then reuses it.

    Reused rather than rebuilt so the in-memory stores persist across
    requests - a fresh broker per request would lose every pending state and
    the flow could never complete.
    """
    global _broker
    if _broker is None:
        _broker = build_application()
    return _broker(environ, start_response)
