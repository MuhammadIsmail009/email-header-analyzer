"""Session-wide test isolation.

``Settings`` (``app/config.py``) reads ``.env`` from the current working directory by
pydantic-settings default (``env_file=".env"``). Without this fixture, a developer's own
local ``.env`` — enrichment keys, feature flags, timeouts — silently leaks into every test
that builds a bare ``Settings()``/``Settings(**overrides)``, and only the fields a test
explicitly overrides are protected. Tests must be hermetic regardless of what's sitting in
the repo root; this disables the dotenv source for the whole test session so every
``Settings`` instance is built from explicit kwargs and code defaults only.
"""

from __future__ import annotations

import pytest

from app.config import Settings


@pytest.fixture(autouse=True, scope="session")
def _no_dotenv_in_tests():
    Settings.model_config["env_file"] = None
