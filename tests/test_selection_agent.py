"""Tests for agents.selection — heuristic router that picks a specialist agent
from a free-form target + optional intent hint."""

from __future__ import annotations

import pytest

# ─── URL / scheme heuristics ────────────────────────────────────────────


def test_route_api_endpoint_picks_api_security():
    from agents.selection.selection_agent import route_target
    out = route_target("https://example.com/api/v1/users")
    assert out["agent"] == "api_security"
    assert out["confidence"] >= 0.8


@pytest.mark.parametrize("target", [
    "https://example.com/graphql",
    "https://example.com/v2/widgets",
    "https://example.com/rest/orders",
])
def test_route_api_variants(target):
    from agents.selection.selection_agent import route_target
    out = route_target(target)
    assert out["agent"] == "api_security"


def test_route_https_url_picks_web():
    from agents.selection.selection_agent import route_target
    out = route_target("https://example.com/login")
    assert out["agent"] == "web"


def test_route_http_url_picks_web():
    from agents.selection.selection_agent import route_target
    out = route_target("http://staging.example.com")
    assert out["agent"] == "web"


# ─── File extension heuristics ──────────────────────────────────────────


@pytest.mark.parametrize("target", ["myapp.apk", "/tmp/build.aab", "/Users/me/MyApp.ipa"])
def test_route_mobile_artifact(target):
    from agents.selection.selection_agent import route_target
    out = route_target(target)
    assert out["agent"] == "mobile"


# ─── Cloud heuristics ───────────────────────────────────────────────────


@pytest.mark.parametrize("target", [
    "arn:aws:s3:::my-bucket",
    "s3://my-bucket",
    "gs://my-bucket",
    "myapp.azurewebsites.net",
])
def test_route_cloud_resource(target):
    from agents.selection.selection_agent import route_target
    out = route_target(target)
    assert out["agent"] == "cloud"


# ─── AD heuristics ──────────────────────────────────────────────────────


@pytest.mark.parametrize("target", [
    "DC01.corp.local",
    "domain.local",
    "ad.contoso.com",  # via intent hint below
])
def test_route_ad_via_local_tld(target):
    from agents.selection.selection_agent import route_target
    out = route_target(target if target.endswith(".local") else "DC01.corp.local")
    assert out["agent"] == "ad"


def test_route_ad_via_intent_hint():
    from agents.selection.selection_agent import route_target
    out = route_target("dc.example.com", intent="kerberoast the domain controllers")
    assert out["agent"] == "ad"


# ─── Bare host / IP → recon ─────────────────────────────────────────────


@pytest.mark.parametrize("target", [
    "example.com",
    "192.168.1.1",
    "10.0.0.0/24",
])
def test_route_bare_host_picks_recon(target):
    from agents.selection.selection_agent import route_target
    out = route_target(target)
    assert out["agent"] == "recon"


# ─── Intent-based overrides ─────────────────────────────────────────────


def test_route_credential_intent():
    from agents.selection.selection_agent import route_target
    out = route_target("https://example.com/login", intent="brute force the login form")
    assert out["agent"] == "credential_tester"


def test_route_wireless_intent():
    from agents.selection.selection_agent import route_target
    out = route_target("CorpWiFi", intent="audit the wireless ssid")
    assert out["agent"] == "wireless"


def test_route_social_intent():
    from agents.selection.selection_agent import route_target
    out = route_target("helpdesk@example.com", intent="phish the helpdesk and harvest creds")
    assert out["agent"] == "social_engineer"


def test_route_llm_redteam_intent():
    from agents.selection.selection_agent import route_target
    out = route_target("https://example.com/chat", intent="probe the LLM for prompt injection")
    assert out["agent"] == "llm_redteam"


# ─── Fallback + validation ──────────────────────────────────────────────


def test_route_empty_target_raises():
    from agents.selection.selection_agent import route_target
    with pytest.raises(ValueError):
        route_target("")


def test_route_whitespace_only_raises():
    from agents.selection.selection_agent import route_target
    with pytest.raises(ValueError):
        route_target("   ")


def test_route_unknown_falls_back_to_recon():
    from agents.selection.selection_agent import route_target
    out = route_target("zzzzzz")
    assert out["agent"] == "recon"
    # Fallback should have lower confidence than a strong match
    assert out["confidence"] < 0.7


def test_route_returns_reasoning():
    from agents.selection.selection_agent import route_target
    out = route_target("https://example.com/api/users")
    assert "reason" in out
    assert isinstance(out["reason"], str)
    assert out["reason"]


def test_route_includes_target_in_response():
    from agents.selection.selection_agent import route_target
    out = route_target("https://example.com/api/users")
    assert out["target"] == "https://example.com/api/users"


# ─── SelectionAgent class ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_selection_agent_dispatch_returns_route():
    from agents.selection.selection_agent import SelectionAgent
    agent = SelectionAgent()
    out = await agent.route("https://example.com/api/users")
    assert out["agent"] == "api_security"


@pytest.mark.asyncio
async def test_selection_agent_dispatch_with_intent():
    from agents.selection.selection_agent import SelectionAgent
    agent = SelectionAgent()
    out = await agent.route("dc.example.com", intent="enumerate active directory")
    assert out["agent"] == "ad"
