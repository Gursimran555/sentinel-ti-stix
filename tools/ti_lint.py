#!/usr/bin/env python3
"""ti_lint: find threat intelligence KQL that still targets the legacy table, or
that queries ThreatIntelIndicators in a way that quietly drops or invents matches.

    python tools/ti_lint.py path/to/rules [more paths]     # .kql, .yaml, .yml, .json

Exit code 1 if anything is reported. Rules:

  TI001  legacy table ThreatIntelligenceIndicator (no new data since July 31, 2025)
  TI002  legacy column used on ThreatIntelIndicators without being re-created
  TI003  ThreatIntelIndicators without `arg_max(...) by Id` (old versions still match)
         (deduplicating on a copy of the id, e.g. IndicatorId, also counts)
  TI004  IP match on ipv4-addr:value only (misses network-traffic:* and ipv6 keys)
  TI005  Confidence threshold with no handling for null confidence
  TI006  no IsDeleted / Revoked filter
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ImportError:          # yaml is only needed for .yaml rule files
    yaml = None

# From Microsoft's migration guidance: legacy column -> how to get it from the new table.
LEGACY_COLUMNS = {
    "NetworkIP": "ObservableValue where ObservableKey == 'ipv4-addr:value'",
    "NetworkSourceIP": "ObservableValue where ObservableKey == 'network-traffic:src_ref.value'",
    "NetworkDestinationIP": "ObservableValue where ObservableKey == 'network-traffic:dst_ref.value'",
    "DomainName": "ObservableValue where ObservableKey == 'domain-name:value'",
    "Url": "ObservableValue where ObservableKey == 'url:value'",
    "EmailSenderAddress": "ObservableValue where ObservableKey == 'email-addr:value'",
    "FileHashValue": "ObservableValue where ObservableKey has 'file:hashes'",
    "Description": "tostring(Data.description)",
    "ThreatType": "tostring(Data.indicator_types[0])",
    "ExpirationDateTime": "ValidUntil",
    "ConfidenceScore": "Confidence",
    "Active": "IsActive",
    "IndicatorId": "Id (or tostring(Data.id))",
}

IP_KEYS = ("ipv4-addr:value", "ipv6-addr:value",
           "network-traffic:src_ref.value", "network-traffic:dst_ref.value")


@dataclass
class Finding:
    path: str
    rule: str
    message: str
    query: str = ""

    def __str__(self):
        where = f"{self.path}" + (f" [{self.query}]" if self.query else "")
        return f"{where}: {self.rule} {self.message}"


def strip_comments(kql: str) -> str:
    out = []
    for line in kql.splitlines():
        in_str = None
        for i, ch in enumerate(line):
            if ch in "\"'" and in_str is None:
                in_str = ch
            elif ch == in_str:
                in_str = None
            elif ch == "/" and in_str is None and line[i:i + 2] == "//":
                line = line[:i]
                break
        out.append(line)
    return "\n".join(out)


def strip_strings(kql: str) -> str:
    return re.sub(r"\"[^\"]*\"|'[^']*'", '""', kql)


def ti_segments(bare: str) -> list[str]:
    """Text from each ThreatIntelIndicators reference up to the next join/union/lookup or `;`."""
    segs = []
    for m in re.finditer(r"\bThreatIntelIndicators\b", bare):
        rest = bare[m.end():]
        stop = re.search(r"\b(join|union|lookup)\b|;", rest)
        segs.append(rest[:stop.start()] if stop else rest)
    return segs


def lint_query(kql: str, path: str = "<query>", name: str = "") -> list[Finding]:
    code = strip_comments(kql)
    bare = strip_strings(code)
    found: list[Finding] = []

    def add(rule, msg):
        found.append(Finding(path, rule, msg, name))

    if re.search(r"\bThreatIntelligenceIndicator\b", bare):
        add("TI001", "uses the legacy ThreatIntelligenceIndicator table, which stopped "
                     "receiving data on July 31, 2025. Use ThreatIntelIndicators.")

    if not re.search(r"\bThreatIntelIndicators\b", bare):
        return found

    # Only look at the TI pipeline itself, so a telemetry column that happens to be
    # called Url or Description isn't reported.
    segments = ti_segments(bare)
    for col, replacement in LEGACY_COLUMNS.items():
        defined = re.search(rf"(?<![\w.]){col}\s*=(?!=)", bare)
        used = any(re.search(rf"(?<![\w.]){col}\b(?!\s*=(?!=))", seg) for seg in segments)
        if used and not defined:
            add("TI002", f"column {col} does not exist in ThreatIntelIndicators; use {replacement}")

    # Id, or a copy of it such as IndicatorId = tostring(Data.id)
    if not re.search(r"arg_max\s*\(\s*TimeGenerated\b[^)]*\)\s*by\s+[^|;]*\b(Id|IndicatorId)\b",
                     bare):
        add("TI003", "no `summarize arg_max(TimeGenerated, *) by Id`: every update adds a row, "
                     "so older versions of deleted or revoked indicators can still match")

    keys = set(re.findall(r"[a-z0-9-]+:[a-z_.]+", code))
    if "ipv4-addr:value" in keys and not keys & {"network-traffic:src_ref.value",
                                                  "network-traffic:dst_ref.value"}:
        if not re.search(r"network-traffic", code):
            add("TI004", "matches IPs on ipv4-addr:value only. Microsoft Threat Intelligence "
                         "publishes most IPs as network-traffic:src_ref.value; include "
                         + ", ".join(IP_KEYS))

    if re.search(r"\bConfidence\s*(>=|>|<|<=)", bare) and not re.search(
            r"(isnull|isnotnull|isempty|isnotempty|coalesce)\s*\(\s*Confidence\b", bare):
        add("TI005", "filters on Confidence without handling null. Feeds that send no "
                     "confidence (e.g. Pulsedive URLs/IPv6) are silently dropped")

    if not re.search(r"\bIsDeleted\b", bare) or not re.search(r"\bRevoked\b", bare):
        add("TI006", "doesn't exclude IsDeleted and Revoked indicators")

    return found


def queries_in(path: Path) -> list[tuple[str, str]]:
    """(name, kql) pairs found in a file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".kql":
        return [("", text)]
    if path.suffix in (".yaml", ".yml"):
        if yaml is None:
            raise SystemExit("pip install pyyaml to lint YAML rules")
        doc = yaml.safe_load(text) or {}
        if isinstance(doc, dict) and "query" in doc:
            return [(str(doc.get("name", "")), doc["query"])]
        return []
    if path.suffix == ".json":
        out = []

        def walk(node):
            if isinstance(node, dict):
                if isinstance(node.get("query"), str):
                    out.append((str(node.get("displayName", node.get("name", ""))), node["query"]))
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        walk(json.loads(text))
        return out
    return []


def lint_paths(paths) -> list[Finding]:
    findings = []
    for root in map(Path, paths):
        files = [root] if root.is_file() else sorted(
            p for p in root.rglob("*") if p.suffix in (".kql", ".yaml", ".yml", ".json"))
        for f in files:
            for name, kql in queries_in(f):
                findings.extend(lint_query(kql, str(f), name))
    return findings


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__)
        return 2
    findings = lint_paths(argv)
    for f in findings:
        print(f)
    print(f"\n{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
