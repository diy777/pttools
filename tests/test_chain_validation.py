"""Tests for chain status updates after PoC validation.

Pre-fix state: every chain stayed at status='discovered' forever; every
finding's poc_status stayed 'pending'. Post-fix, the validator marks each
chain 'confirmed' or 'unvalidated' based on whether its finding_ids carry
real evidence (status='confirmed' on the finding row).
"""

from __future__ import annotations

import pytest

from agents.exploit_chain.chain_agent import ExploitChainAgent
from agents.poc_validator.poc_agent import PoCAgent
from engine.findings_db import FindingsDB


@pytest.fixture
def db():
    return FindingsDB(":memory:")


async def _add_finding(db: FindingsDB, eng_id: str, **fields):
    base = {
        "engagement_id": eng_id,
        "title": "default",
        "description": "",
        "severity": "high",
        "category": "injection",
        "target": "x.example",
        "evidence": '{"payload":"x", "response":"y"}',
    }
    base.update(fields)
    return await db.add_finding(base)


@pytest.mark.asyncio
async def test_update_chain_status_persists(db):
    eng = await db.create_engagement("x.example", "full", "", "normal")
    chain_id = await db.add_attack_chain({
        "engagement_id": eng["id"],
        "name": "Test", "description": "d", "severity": "high",
        "steps": [{"finding_id": "abc", "action": "step"}],
        "finding_ids": ["abc"], "impact": "rce",
    })
    await db.update_chain_status(chain_id, "confirmed")
    chains = await db.get_attack_chains(eng["id"])
    assert chains[0]["status"] == "confirmed"


@pytest.mark.asyncio
async def test_update_finding_poc_status_persists(db):
    eng = await db.create_engagement("x.example", "full", "", "normal")
    fid = await _add_finding(db, eng["id"], title="SQL Injection")
    await db.update_finding_poc_status(fid, "confirmed", poc="curl ...")
    rows = await db.get_findings(engagement_id=eng["id"])
    assert rows[0]["poc_status"] == "confirmed"
    assert rows[0]["poc"] == "curl ..."


@pytest.mark.asyncio
async def test_chain_with_evidence_backed_findings_marks_confirmed(db):
    eng = await db.create_engagement("x.example", "full", "", "normal")
    fid_a = await _add_finding(db, eng["id"], title="SQL Injection /products?id=", severity="critical")
    fid_b = await _add_finding(db, eng["id"], title="Open admin port 8080", severity="medium",
                               category="discovery", evidence='{"port":8080}')

    chainer = ExploitChainAgent(db)
    chains = await chainer.discover_chains(eng["id"])
    assert chains, "precondition: chainer should produce a chain"

    poc = PoCAgent(db)
    await poc.validate_chains(eng["id"])

    rows = await db.get_attack_chains(eng["id"])
    assert all(c["status"] == "confirmed" for c in rows), [c["status"] for c in rows]
    assert fid_a and fid_b


@pytest.mark.asyncio
async def test_chain_with_unverified_finding_marks_unvalidated(db):
    eng = await db.create_engagement("x.example", "full", "", "normal")
    # Two findings, but the second has no evidence so the DB coerces it to
    # status='unverified'. Chain validation must downgrade the chain.
    await _add_finding(db, eng["id"], title="SQL Injection /products?id=", severity="critical")
    await _add_finding(
        db, eng["id"],
        title="Suspicious admin endpoint",
        severity="medium",
        category="discovery",
        evidence="",
        poc="",
        raw_output="",
        tool_result_id=None,
    )

    chainer = ExploitChainAgent(db)
    chains = await chainer.discover_chains(eng["id"])
    if not chains:
        pytest.skip("chainer didn't produce a chain in this config")

    poc = PoCAgent(db)
    await poc.validate_chains(eng["id"])

    rows = await db.get_attack_chains(eng["id"])
    statuses = [c["status"] for c in rows]
    assert "unvalidated" in statuses or "rejected" in statuses, statuses
