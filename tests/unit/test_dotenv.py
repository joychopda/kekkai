"""Dotenv loading: local secrets without a third-party dependency."""

from __future__ import annotations

import os
from pathlib import Path

from kekkai.config import KekkaiConfig, load_dotenv


def test_load_dotenv_sets_missing_keys(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\n"
        "TYPESAFE_API_KEY=secret-from-file\n"
        "KEKKAI_BACKEND=jev\n"
        "QUOTED='quoted-value'\n"
        "\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.delenv("KEKKAI_BACKEND", raising=False)
    monkeypatch.delenv("QUOTED", raising=False)

    assert load_dotenv(env_file) == env_file
    assert os.environ["TYPESAFE_API_KEY"] == "secret-from-file"
    assert os.environ["KEKKAI_BACKEND"] == "jev"
    assert os.environ["QUOTED"] == "quoted-value"


def test_load_dotenv_does_not_override_existing_env(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("TYPESAFE_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setenv("TYPESAFE_API_KEY", "from-shell")

    load_dotenv(env_file)
    assert os.environ["TYPESAFE_API_KEY"] == "from-shell"


def test_load_dotenv_returns_none_when_absent(tmp_path: Path):
    assert load_dotenv(tmp_path / "missing.env") is None


def test_config_load_picks_up_backend_from_dotenv(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("KEKKAI_BACKEND=jev\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KEKKAI_BACKEND", raising=False)

    config = KekkaiConfig.load()
    assert config.backend == "jev"
