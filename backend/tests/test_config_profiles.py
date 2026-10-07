"""Local/staging profile validation and fail-closed configuration tests."""
from __future__ import annotations

import json

import pytest

from app.config import Settings


def test_profiles_are_explicit_and_production_is_unsupported():
    assert {"sandbox", "staging", "production_unsupported"} >= {"sandbox", "staging", "production_unsupported"}
    unsupported = Settings(profile="production_unsupported", env="production_unsupported")
    assert "production_unsupported" in " ".join(unsupported.validation_errors())
    assert unsupported.is_production is True


def test_staging_rejects_defaults_and_memory_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("TRAIL_ENV", "staging")
    monkeypatch.setenv("TRAIL_PROFILE", "staging")
    monkeypatch.delenv("TRAIL_DISABLE_DEV_KEYS", raising=False)
    settings = Settings()
    errors = settings.validation_errors()
    assert any("master_secret" in error.lower() for error in errors)
    assert any("demo" in error for error in errors)
    assert any("durable" in error for error in errors)
    assert any("hashed users" in error for error in errors)
    with pytest.raises(RuntimeError, match="Unsafe Trail configuration"):
        settings.validate()


def test_valid_staging_requires_explicit_local_inputs(tmp_path, monkeypatch):
    monkeypatch.setenv("TRAIL_ENV", "staging")
    monkeypatch.setenv("TRAIL_PROFILE", "staging")
    monkeypatch.setenv("TRAIL_DISABLE_DEV_KEYS", "1")
    monkeypatch.setenv(
        "TRAIL_USERS_JSON",
        json.dumps({"a" * 64: {"user_id": "analyst", "role": "l1_analyst", "institution": "BANK_A"}}),
    )
    lock = tmp_path / "requirements.lock"
    lock.write_text("fastapi==0\n", encoding="utf-8")
    settings = Settings(
        master_secret="s" * 64,
        cors_origins=("https://console.example.test",),
        audit_path=str(tmp_path / "audit.jsonl"),
        preauth_path=str(tmp_path / "preauth.sqlite"),
        dependency_lock_path=str(lock),
    )
    assert settings.validation_errors() == ()
    settings.validate()
    assert settings.storage_mode == "sqlite_wal"
    assert settings.live_integrations is False


def test_live_integrations_and_non_synthetic_data_are_never_valid(monkeypatch):
    monkeypatch.setenv("TRAIL_LIVE_INTEGRATIONS", "true")
    monkeypatch.setenv("TRAIL_DATA_STATUS", "real")
    settings = Settings()
    errors = settings.validation_errors()
    assert any("live_integrations" in error.lower() for error in errors)
    assert any("synthetic" in error for error in errors)
