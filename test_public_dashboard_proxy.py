from pathlib import Path


ROOT = Path(__file__).parent
CADDY = (ROOT / "Caddyfile.example").read_text(encoding="utf-8")
ENVIRONMENT = (ROOT / "hosted.env.example").read_text(encoding="utf-8")


def test_public_proxy_exposes_only_the_loopback_dashboard_with_hsts():
    assert "reverse_proxy 127.0.0.1:8081" in CADDY
    assert "127.0.0.1:8080" not in CADDY
    assert "Strict-Transport-Security" in CADDY


def test_public_example_requires_https_and_an_exact_oauth_callback():
    assert "HOSTED_REQUIRE_FORWARDED_HTTPS=true" in ENVIRONMENT
    callback = next(
        line for line in ENVIRONMENT.splitlines()
        if line.startswith("DASHBOARD_OAUTH_REDIRECT_URI=")
    )
    assert callback.startswith("DASHBOARD_OAUTH_REDIRECT_URI=https://")
    assert callback.endswith("/oauth/callback")
