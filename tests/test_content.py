"""Structural checks on the analytics rules. These don't run KQL; they check that
every rule is a valid Sentinel scheduled rule and keeps the TI safeguards."""

import re
import uuid
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = sorted((ROOT / "analytics").glob("*.yaml"))
TI_RULES = [r for r in RULES if r.name.startswith("ti-")]

REQUIRED = ["id", "name", "description", "severity", "requiredDataConnectors", "queryFrequency",
            "queryPeriod", "triggerOperator", "triggerThreshold", "tactics", "relevantTechniques",
            "query", "entityMappings", "version", "kind"]
TACTICS = {"Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
           "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery",
           "LateralMovement", "Collection", "CommandAndControl", "Exfiltration", "Impact"}
IP_KEYS = ["ipv4-addr:value", "ipv6-addr:value",
           "network-traffic:src_ref.value", "network-traffic:dst_ref.value"]


def load(p):
    return yaml.safe_load(p.read_text())


def test_there_are_rules():
    assert len(RULES) == 6 and len(TI_RULES) == 4


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.name)
def test_rule_shape(path):
    r = load(path)
    for key in REQUIRED:
        assert key in r, f"{path.name} missing {key}"
    uuid.UUID(r["id"])
    assert r["kind"] == "Scheduled"
    assert r["severity"] in {"Informational", "Low", "Medium", "High"}
    assert set(r["tactics"]) <= TACTICS
    for t in r["relevantTechniques"]:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", t)
    assert re.fullmatch(r"\d+\.\d+\.\d+", r["version"])
    for m in r["entityMappings"]:
        assert m["fieldMappings"]


def test_ids_unique():
    ids = [load(p)["id"] for p in RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.name)
def test_entity_columns_exist_in_query(path):
    r = load(path)
    for m in r["entityMappings"]:
        for f in m["fieldMappings"]:
            assert re.search(rf"\b{f['columnName']}\b", r["query"]), f["columnName"]


@pytest.mark.parametrize("path", TI_RULES, ids=lambda p: p.name)
def test_ti_rules_keep_the_safeguards(path):
    r = load(path)
    q = r["query"]
    assert "summarize arg_max(TimeGenerated, *) by Id" in q
    assert "coalesce(IsDeleted, false) == false" in q
    assert "coalesce(Revoked, false) == false" in q
    assert "isnull(ValidUntil) or ValidUntil > now()" in q
    assert "ConfidenceMissing" in q
    assert all(k in q for k in IP_KEYS)
    assert {c["connectorId"] for c in r["requiredDataConnectors"]} >= {
        "ThreatIntelligence", "ThreatIntelligenceTaxii", "MicrosoftDefenderThreatIntelligence"}


@pytest.mark.parametrize("path", TI_RULES, ids=lambda p: p.name)
def test_ti_lookback_fits_query_period(path):
    r = load(path)
    look = re.search(r"let ioc_lookBack = (\d+)d;", r["query"]).group(1)
    assert r["queryPeriod"] == f"{look}d"


def test_ti_block_matches_the_function():
    """The inline TI block in every rule applies the same filters as functions/TIActiveIndicators.kql."""
    fn = (ROOT / "functions" / "TIActiveIndicators.kql").read_text()
    for line in ["summarize arg_max(TimeGenerated, *) by Id",
                 "coalesce(IsDeleted, false) == false",
                 "coalesce(Revoked, false) == false",
                 "IsActive == true",
                 "isnull(ValidUntil) or ValidUntil > now()",
                 "EffectiveConfidence >= min_confidence"]:
        assert line in fn
        for p in TI_RULES:
            assert line in load(p)["query"], f"{p.name}: {line}"
