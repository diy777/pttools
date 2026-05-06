"""Quality guards on the exploit chainer.

These tests pin behaviour the chainer should have so it doesn't fabricate
chains from scanner-error findings or single-finding inputs. Background:
on 2026-04-29 the chainer turned two nikto error strings ("No web server
found" + "0 host(s) tested") into four "Web to Shell" / "SSRF to Cloud
Compromise" chains. The post-launch HN demo has to not do that.
"""

from __future__ import annotations

import pytest

from agents.exploit_chain.chain_agent import ExploitChainAgent
from engine.findings_db import FindingsDB


@pytest.fixture
def db():
    return FindingsDB(":memory:")


async def _add_finding(db: FindingsDB, eng_id: str, **fields):
    base = {
        "engagement_id": eng_id,
        "title": "default",
        "description": "",
        "severity": "info",
        "category": "discovery",
        "target": "x",
    }
    base.update(fields)
    return await db.add_finding(base)


# ---------- Fix 1: noise-filter on entry findings ----------


@pytest.mark.asyncio
async def test_nikto_no_web_server_does_not_seed_chain(db):
    eng = await db.create_engagement("dead.example", "full", "", "normal")
    await _add_finding(
        db,
        eng["id"],
        title="Nikto: No web server found on dead.example:80",
        severity="high",
        category="vulnerability",
    )
    await _add_finding(
        db,
        eng["id"],
        title="Nikto: 0 host(s) tested",
        severity="info",
        category="discovery",
    )
    agent = ExploitChainAgent(db)
    chains = await agent.discover_chains(eng["id"])
    assert chains == [], f"Chainer fabricated chains from nikto errors: {chains}"


@pytest.mark.asyncio
async def test_real_finding_still_seeds_chain(db):
    eng = await db.create_engagement("real.example", "full", "", "normal")
    await _add_finding(
        db,
        eng["id"],
        title="SQL Injection in /products?id=",
        severity="critical",
        category="injection",
        evidence='{"payload": "1 OR 1=1", "response_diff": true}',
    )
    await _add_finding(
        db,
        eng["id"],
        title="Open admin port 8080",
        severity="medium",
        category="discovery",
    )
    agent = ExploitChainAgent(db)
    chains = await agent.discover_chains(eng["id"])
    assert len(chains) >= 1


@pytest.mark.asyncio
async def test_mixed_real_plus_noise_only_uses_real(db):
    eng = await db.create_engagement("mixed.example", "full", "", "normal")
    await _add_finding(
        db,
        eng["id"],
        title="Nikto: No web server found on mixed.example:80",
        severity="high",
        category="vulnerability",
    )
    await _add_finding(
        db,
        eng["id"],
        title="Reflected XSS in /search",
        severity="high",
        category="injection",
        evidence='{"payload": "<svg/onload>", "reflected": true}',
    )
    await _add_finding(
        db,
        eng["id"],
        title="Open admin port 8080",
        severity="medium",
        category="discovery",
    )
    agent = ExploitChainAgent(db)
    chains = await agent.discover_chains(eng["id"])
    assert len(chains) >= 1
    for chain in chains:
        for step in chain["steps"]:
            assert "No web server found" not in step["action"]
            assert "0 host(s)" not in step["action"]


# ---------- Fix 3: minimum eligible findings ----------


@pytest.mark.asyncio
async def test_single_finding_does_not_chain(db):
    eng = await db.create_engagement("solo.example", "full", "", "normal")
    await _add_finding(
        db,
        eng["id"],
        title="SQL Injection in /products?id=",
        severity="critical",
        category="injection",
        evidence='{"payload": "1 OR 1=1"}',
    )
    agent = ExploitChainAgent(db)
    chains = await agent.discover_chains(eng["id"])
    assert chains == []


@pytest.mark.asyncio
async def test_low_only_findings_do_not_chain(db):
    eng = await db.create_engagement("low.example", "full", "", "normal")
    for i in range(5):
        await _add_finding(
            db,
            eng["id"],
            title=f"Banner leak #{i}",
            severity="low",
            category="discovery",
        )
    agent = ExploitChainAgent(db)
    chains = await agent.discover_chains(eng["id"])
    assert chains == []
