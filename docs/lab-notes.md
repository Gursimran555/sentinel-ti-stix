# Lab notes

Workspace: a fresh Log Analytics workspace with Microsoft Sentinel (free trial), Canada Central, October 2026. Most Sentinel pages had already moved to the Defender portal, so TI work happened under *Intel management* and *Advanced hunting* there.

## Sources

| Source | How | Notes |
|---|---|---|
| Pulsedive | TAXII 2.1 connector, hourly | The *Indicator* collection failed with "Transient error verifying TAXII server" twice. The *Test* collection connected first time. |
| Microsoft Threat Intelligence | Data connector | Searching "Microsoft Defender Threat Intelligence" finds nothing; it was renamed. |
| Manual | Intel management → New → TI object | One IPv4 (documentation range), one domain (example.com), an attack pattern related to the IP, and a fictional threat actor. |

## What broke from the manual

1. `ThreatIntelligenceIndicator | where TimeGenerated > ago(24h) | take 50` returned **no results**. The same query on `ThreatIntelIndicators` returned the Pulsedive records, with `LastUpdateMethod = TAXIIConnector`.
2. The manual's verification query failed with **Failed to resolve scalar expression named Description**. Working version:

```kql
ThreatIntelIndicators
| where TimeGenerated > ago(1h)
| extend Description = tostring(Data.description)
| where SourceSystem != "Pulsedive-TAXII"
| project TimeGenerated, ObservableValue, ObservableKey, Description, SourceSystem
| order by TimeGenerated desc
```

## Where the numbers come from

Active indicators by type, with average confidence:

| Type (ObservableKey) | Active | Avg confidence |
|---|---|---|
| network-traffic:src_ref.value | 216 | ~99.9 |
| domain-name:value | 214 | 60 |
| url:value | 141 | none (NaN) |
| ipv4-addr:value | 34 | 75 |
| ipv6-addr:value | 15 | none (NaN) |
| file:hashes | 5 | 66.6 |

627 active indicators in total. Indicators by source: Pulsedive-TAXII 402, Microsoft Defender Threat Intelligence 192, Premium MDTI 2, manual 2.

- **IPs:** 216 + 34 + 15 = 265. An `ipv4-addr:value`-only match sees 34 of them.
- **No confidence:** the average is NaN when every row in the group is null, so all 141 URLs and all 15 IPv6 (156) have no confidence. `Confidence >= 50` drops all of them.
- An example MDTI record: pattern `[network-traffic:src_ref.value = '66.132.195.66']`, name *Microsoft Identified IOC*, confidence 100, tag `honeypot`.

## ATT&CK coverage (active rules only)

- **Covered:** T1078 Valid Accounts (18 rules), T1098 and T1136 (4 each), T1562 and T1041 (2 each), T1046 (1, the built-in *Anomalous scanning activity* anomaly rule).
- **Not covered:** every Lateral Movement technique (including T1021), T1566 Phishing, T1204 User Execution, T1003 OS Credential Dumping, T1496 Resource Hijacking.
- **Brute Force:** 5 rules, none specific to Password Spraying.

The two `gap-` rules in `analytics/` target T1021.001 and T1110.003. T1021 needs logon telemetry (Defender for Endpoint `DeviceLogonEvents`, or Windows Security Events 4624 via the Azure Monitor Agent). The lab workspace had neither, so these rules are untested here.

## Other platform differences

- **Severity:** automation rules can't set *Critical*. The options are Informational, Low, Medium and High.
- **Automation conditions:** the *Analytic rule name* condition only offers rules that already exist, so "contains AWS" can't be typed. *Title contains* works instead, because incident titles default to the rule name.
