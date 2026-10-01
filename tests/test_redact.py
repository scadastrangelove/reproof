# SPDX-License-Identifier: Apache-2.0
"""Tests for reproof.redact — live credential scrubbing."""
from __future__ import annotations

import pytest

from reproof import redact

LONG = "sk-kimi-" + "a" * 40
SHORT = "short"


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    for k in redact._SECRET_ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    redact.reset_cache()
    yield
    redact.reset_cache()


def test_live_value_scrubbed(monkeypatch):
    monkeypatch.setenv("KIMI_MODEL_API_KEY", LONG)
    redact.reset_cache()
    out = redact.scrub(f'{{"content":"env dump: KIMI_MODEL_API_KEY={LONG}"}}')
    assert LONG not in out
    assert redact.PLACEHOLDER in out


def test_short_values_ignored(monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", SHORT)
    redact.reset_cache()
    assert redact.scrub(f"value {SHORT} stays") == f"value {SHORT} stays"


def test_no_secrets_is_noop():
    assert redact.scrub("plain text") == "plain text"


def test_longest_first_nested_tokens(monkeypatch):
    monkeypatch.setenv("KIMI_MODEL_API_KEY", LONG)
    monkeypatch.setenv("KIMI_API_KEY", LONG + ".suffix")
    redact.reset_cache()
    out = redact.scrub(LONG + ".suffix")
    assert LONG not in out.replace(redact.PLACEHOLDER, "")
    assert out.count(redact.PLACEHOLDER) == 1
