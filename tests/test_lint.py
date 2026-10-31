import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import ti_lint  # noqa: E402


def rules(kql):
    return sorted({f.rule for f in ti_lint.lint_query(kql)})


GOOD = """
ThreatIntelIndicators
| summarize arg_max(TimeGenerated, *) by Id
| where coalesce(IsDeleted, false) == false and coalesce(Revoked, false) == false
| where IsActive == true
| where ObservableKey in ("ipv4-addr:value", "ipv6-addr:value",
                          "network-traffic:src_ref.value", "network-traffic:dst_ref.value")
"""


def test_good_query_is_clean():
    assert rules(GOOD) == []


def test_legacy_table_from_the_lab_manual():
    assert "TI001" in rules("ThreatIntelligenceIndicator | where TimeGenerated > ago(24h) | take 50")


def test_legacy_description_column_from_the_lab_manual():
    kql = GOOD + "| project ObservableValue, Description"
    assert "TI002" in rules(kql)


def test_recreated_legacy_column_is_fine():
    kql = GOOD + "| extend Description = tostring(Data.description) | project Description"
    assert "TI002" not in rules(kql)


def test_telemetry_column_with_legacy_name_is_not_flagged():
    kql = ("let TI = " + GOOD + ";\n"
           "TI | join (WebSession | extend RequestedUrl = tolower(Url)) on $left.ObservableValue == $right.RequestedUrl")
    assert "TI002" not in rules(kql)


def test_no_dedupe():
    kql = GOOD.replace("| summarize arg_max(TimeGenerated, *) by Id", "")
    assert "TI003" in rules(kql)


def test_dedupe_on_indicator_id_copy_counts():
    kql = GOOD.replace("by Id", "by IndicatorId, ObservableValue").replace(
        "ThreatIntelIndicators", "ThreatIntelIndicators | extend IndicatorId = tostring(Data.id)", 1)
    assert "TI003" not in rules(kql)


def test_microsoft_migration_example_has_no_dedupe():
    # Shortened from Microsoft's "update your queries" example.
    kql = """ThreatIntelIndicators
    | extend NetworkIP = iff(ObservableKey == 'ipv4-addr:value', ObservableValue, ''),
             DomainName = iff(ObservableKey == 'domain-name:value', ObservableValue, ''),
             Description = tostring(Data.description)
    | project-reorder TimeGenerated, ObservableKey, ObservableValue, Description"""
    found = rules(kql)
    assert "TI003" in found and "TI006" in found and "TI002" not in found


def test_ipv4_only():
    kql = GOOD.replace('"ipv6-addr:value",', "").replace(
        '"network-traffic:src_ref.value", "network-traffic:dst_ref.value"', '"x"')
    assert "TI004" in rules(kql)


def test_confidence_threshold_without_null_handling():
    assert "TI005" in rules(GOOD + "| where Confidence >= 75")
    assert "TI005" not in rules(GOOD + "| where coalesce(Confidence, 50) >= 75")
    assert "TI005" not in rules(GOOD + "| where isnull(Confidence) or Confidence >= 75")


def test_missing_deleted_filter():
    kql = GOOD.replace("| where coalesce(IsDeleted, false) == false and coalesce(Revoked, false) == false", "")
    assert "TI006" in rules(kql)


def test_comments_and_strings_are_ignored():
    kql = GOOD + '// ThreatIntelligenceIndicator is the old table\n| extend Note = "Confidence > 5"'
    assert rules(kql) == []


def test_this_repo_is_clean():
    found = ti_lint.lint_paths([ROOT / "functions", ROOT / "analytics", ROOT / "hunting"])
    assert found == [], "\n".join(map(str, found))


def test_cli_exit_codes(tmp_path):
    bad = tmp_path / "bad.kql"
    bad.write_text("ThreatIntelligenceIndicator | take 5")
    assert ti_lint.main([str(bad)]) == 1
    good = tmp_path / "good.kql"
    good.write_text(GOOD)
    assert ti_lint.main([str(good)]) == 0
