"""Offline Gemini reliability tests using a fake client only."""
from types import SimpleNamespace

import pytest

import gemini_client


def _response(text=None):
    part = SimpleNamespace(text=text)
    content = SimpleNamespace(parts=[part])
    return SimpleNamespace(candidates=[SimpleNamespace(content=content)])


def test_get_text_tolerates_missing_response_layers():
    assert gemini_client.get_text(SimpleNamespace()) == ""
    assert gemini_client.get_text(SimpleNamespace(candidates=[])) == ""
    assert gemini_client.get_text(
        SimpleNamespace(candidates=[SimpleNamespace(content=None)])
    ) == ""
    assert gemini_client.get_text(_response("ok")) == "ok"


def test_parse_result_validates_category_and_grad_year(caplog):
    valid = gemini_client.parse_result(
        "CATEGORY: recruit_intro\nGRAD_YEAR: 2027\n"
        "SENDER_TYPE: recruit\nCONFIDENCE: high\n"
        "EVIDENCE: class of 2027\nREASON: seeded"
    )
    assert valid["category"] == "recruit_intro"
    assert valid["grad_year"] == "2027"
    assert valid["sender_type"] == "recruit"
    assert valid["valid"] is True

    secret_echo = "DO-NOT-LOG-THIS-EMAIL-BODY"
    invalid = gemini_client.parse_result(
        f"CATEGORY: made_up\nGRAD_YEAR: 2099\n"
        f"SENDER_TYPE: unknown\nCONFIDENCE: low\n"
        f"EVIDENCE: none\nREASON: {secret_echo}"
    )
    assert invalid["category"] == "unknown"
    assert invalid["grad_year"] == "unknown"
    assert secret_echo not in caplog.text


@pytest.mark.parametrize("category,sender_type", [
    ("recruit_intro", "recruit"),
    ("recruit_update", "recruit"),
    ("video_update", "recruit"),
    ("parent", "parent"),
    ("other_coach", "coach"),
    ("camp_inquiry", "other"),
    ("administrative", "administrative"),
    ("other", "other"),
])
def test_complete_supported_taxonomy_parses(category, sender_type):
    result = gemini_client.parse_result(
        f"CATEGORY: {category}\nGRAD_YEAR: unknown\n"
        f"SENDER_TYPE: {sender_type}\nCONFIDENCE: high\n"
        f"EVIDENCE: offline fixture\nREASON: offline seeded"
    )
    assert result["category"] == category
    assert result["sender_type"] == sender_type
    assert result["valid"] is True


def test_missing_structured_field_is_invalid_without_echoing_output(caplog):
    sensitive = "SYNTHETIC-DO-NOT-LOG"
    result = gemini_client.parse_result(
        f"CATEGORY: parent\nGRAD_YEAR: 2027\nREASON: {sensitive}"
    )
    assert result["valid"] is False
    assert result["category"] == "unknown"
    assert sensitive not in caplog.text


def test_throttle_env_validation(monkeypatch):
    monkeypatch.delenv("TEST_THROTTLE", raising=False)
    assert gemini_client._validated_float_env("TEST_THROTTLE", 6.0) == 6.0
    monkeypatch.setenv("TEST_THROTTLE", "fast")
    with pytest.raises(ValueError):
        gemini_client._validated_float_env("TEST_THROTTLE", 6.0)
    monkeypatch.setenv("TEST_THROTTLE", "-1")
    with pytest.raises(ValueError):
        gemini_client._validated_float_env("TEST_THROTTLE", 6.0)


def test_graduation_year_config_rejects_malformed_values(monkeypatch):
    monkeypatch.setenv("GEMINI_GRAD_YEARS", "2027,not-a-year")
    with pytest.raises(ValueError):
        gemini_client._validated_years_env()


def test_dotenv_is_loaded_only_when_live_client_is_explicitly_requested(monkeypatch):
    calls = []
    fake_client = object()
    monkeypatch.setattr(gemini_client, "_client", None)
    monkeypatch.setattr(gemini_client, "_environment_loaded", False)
    monkeypatch.setattr(gemini_client, "load_dotenv", lambda: calls.append("loaded"))
    monkeypatch.setattr(gemini_client.genai, "Client", lambda api_key: fake_client)
    monkeypatch.setenv("GEMINI_API_KEY", "offline-test-key")

    assert calls == []
    assert gemini_client.get_client() is fake_client
    assert gemini_client.get_client() is fake_client
    assert calls == ["loaded"]


class _FakeModels:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def generate_content(self, **kwargs):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _ApiFailure(Exception):
    def __init__(self, status_code):
        self.status_code = status_code
        super().__init__("synthetic")


def test_transient_error_retries_with_backoff(monkeypatch):
    models = _FakeModels([
        _ApiFailure(429),
        _response(
            "CATEGORY: parent\nGRAD_YEAR: unknown\n"
            "SENDER_TYPE: parent\nCONFIDENCE: high\n"
            "EVIDENCE: offline fixture\nREASON: seeded"
        ),
    ])
    backoffs = []
    monkeypatch.setattr(gemini_client, "get_client", lambda: SimpleNamespace(models=models))
    monkeypatch.setattr(gemini_client, "_throttle", lambda: None)
    monkeypatch.setattr(gemini_client, "_backoff", lambda attempt: backoffs.append(attempt))
    result = gemini_client.classify(
        {"from": "fake@example.test", "subject": "seeded", "body": "offline"}
    )
    assert result["category"] == "parent"
    assert models.calls == 2
    assert backoffs == [1]


def test_permanent_error_is_not_retried(monkeypatch):
    models = _FakeModels([_ApiFailure(403), _response("unused")])
    monkeypatch.setattr(gemini_client, "get_client", lambda: SimpleNamespace(models=models))
    monkeypatch.setattr(gemini_client, "_throttle", lambda: None)
    with pytest.raises(RuntimeError, match="Permanent Gemini error"):
        gemini_client.classify(
            {"from": "fake@example.test", "subject": "seeded", "body": "offline"}
        )
    assert models.calls == 1
