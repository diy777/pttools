"""Tests for SecureCredential — refuses to leak via repr/str/json/pickle."""

from __future__ import annotations

import json
import logging
import pickle

import pytest

from cli.secure_credential import SecureCredential

SENTINEL = "supersecretpassword12345"


def test_reveal_returns_value():
    sc = SecureCredential(SENTINEL, source="env", ref="MY_VAR")
    assert sc.reveal() == SENTINEL


def test_repr_redacts():
    sc = SecureCredential(SENTINEL, source="env", ref="MY_VAR")
    r = repr(sc)
    assert "[REDACTED]" in r
    assert SENTINEL not in r


def test_str_redacts():
    sc = SecureCredential(SENTINEL)
    assert str(sc) == "[REDACTED]"
    assert SENTINEL not in str(sc)


def test_format_redacts():
    sc = SecureCredential(SENTINEL)
    assert f"{sc}" == "[REDACTED]"
    assert f"{sc:>20}" == "[REDACTED]"


def test_json_dumps_refuses():
    sc = SecureCredential(SENTINEL)
    with pytest.raises(TypeError):
        json.dumps(sc)


def test_pickle_refuses():
    sc = SecureCredential(SENTINEL)
    with pytest.raises(TypeError):
        pickle.dumps(sc)


def test_logging_redacts(caplog):
    sc = SecureCredential(SENTINEL)
    logger = logging.getLogger("test")
    with caplog.at_level(logging.INFO, logger="test"):
        logger.info("creds=%s", sc)
        logger.info("creds=%r", sc)
    for record in caplog.records:
        assert SENTINEL not in record.getMessage()


def test_bool_truthiness():
    assert bool(SecureCredential("x"))
    assert not bool(SecureCredential(""))


def test_equality_by_value():
    a = SecureCredential("same")
    b = SecureCredential("same")
    c = SecureCredential("different")
    assert a == b
    assert a != c


def test_source_and_ref_metadata():
    sc = SecureCredential(SENTINEL, source="env", ref="MY_VAR")
    assert sc.source == "env"
    assert sc.ref == "MY_VAR"


def test_rejects_non_str_value():
    with pytest.raises(TypeError):
        SecureCredential(12345)  # type: ignore[arg-type]
