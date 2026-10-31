# sentinel-ti-stix

KQL for Microsoft Sentinel's STIX-based threat intelligence tables (`ThreatIntelIndicators`), plus a linter that finds TI queries that silently miss indicators or match ones that shouldn't count any more.

## Why this exists

I set up a Sentinel workspace with three threat intel sources: Pulsedive over TAXII, the Microsoft Threat Intelligence connector, and indicators I created by hand. Then I followed a lab manual written for the old setup. Three things broke straight away:

- `ThreatIntelligenceIndicator | take 50` returned nothing. Microsoft stopped writing to that table on July 31, 2025. Everything now goes to `ThreatIntelIndicators`.
- The manual's next query failed with *Failed to resolve scalar expression named Description*. The new table has no `Description` column. It's inside the STIX `Data` field: `tostring(Data.description)`.
- The "Microsoft Defender Threat Intelligence" connector didn't exist under that name. It's now called *Microsoft Threat Intelligence*.

Those all fail loudly, which is the easy kind. The hard ones were in queries that *ran fine*. With 627 active indicators in the workspace:

| Shortcut that looks reasonable | What it did to my data |
|---|---|
| Match IPs on `ObservableKey == "ipv4-addr:value"` | Found **34 of 265** IP indicators. Microsoft Threat Intelligence published 216 of them as `network-traffic:src_ref.value`, and 15 were IPv6. |
| "Active, high-confidence only": `where Confidence >= 50` | Dropped **156 indicators** (all 141 URLs and all 15 IPv6 from Pulsedive), because they arrive with no confidence at all, and `null >= 50` is false. Nothing warns you. |
| Filter `IsActive == true` without deduplicating | Every update writes a new row. An indicator that was later deleted, revoked or expired still has older rows where `IsActive` is true, and those keep matching. |

Microsoft's migration guide shows how to rebuild the old columns (`NetworkIP`, `DomainName`, ...) from the new table, but its example doesn't deduplicate. Their own published TI rules do handle the first and third points. The table above is about the custom queries people write or port themselves.

## What's in here

```
functions/TIActiveIndicators.kql   one row per usable indicator: latest version, not deleted/revoked/expired,
                                   all four IP keys, explicit handling of missing confidence
analytics/                         Sentinel scheduled rules (YAML, same format as Azure-Sentinel)
  ti-ip-signinlogs.yaml              TI IP in Entra ID sign-ins (interactive + non-interactive)
  ti-ip-commonsecuritylog.yaml       TI IP as source or destination in CEF firewall logs
  ti-ip-devicenetworkevents.yaml     endpoint connections to TI IPs
  ti-domain-url-devicenetworkevents.yaml  endpoint connections to TI domains / URLs
  gap-t1110-003-password-spray-signinlogs.yaml   coverage gap: Password Spraying
  gap-t1021-001-rdp-fanout-devicelogonevents.yaml  coverage gap: RDP lateral movement
hunting/
  indicator-health.kql             counts, missing confidence, expiring soon, by type and source
  what-naive-queries-miss.kql      the table above, computed for your own workspace
tools/ti_lint.py                   linter for .kql / rule YAML / ARM JSON
docs/legacy-to-new.md              column mapping, old table -> new table
docs/lab-notes.md                  what the workspace looked like and where the numbers come from
```

The two `gap-` rules come from the same workspace's MITRE ATT&CK page. With only active rules shown, every Lateral Movement technique was unshaded (T1021 Remote Services had 0 detections), and T1110.003 Password Spraying had no rule of its own.

## The linter

```bash
pip install pyyaml
python tools/ti_lint.py path/to/your/rules
```

| Rule | Flags |
|---|---|
| TI001 | uses the legacy `ThreatIntelligenceIndicator` table |
| TI002 | uses a legacy column (`Description`, `NetworkIP`, `ConfidenceScore`, ...) on the new table |
| TI003 | no `arg_max(TimeGenerated, *) by Id` |
| TI004 | IP matching on `ipv4-addr:value` only |
| TI005 | `Confidence` threshold with no null handling |
| TI006 | no `IsDeleted` / `Revoked` filter |

It strips comments and string literals first. TI002 only looks at the TI part of a query, so a telemetry column that happens to be called `Url` doesn't trigger it.

As a calibration run, I pointed it at the 52 rules in Microsoft's *Threat Intelligence (NEW)* solution (Azure-Sentinel @ `2985095`). All of them deduplicate and include the network-traffic keys, so TI001–TI004 come back clean. 50 get TI006, because they rely on `IsActive` and `ValidUntil` rather than also checking `IsDeleted`/`Revoked`. That's a design choice, not necessarily a bug. One rule (`IPEntity_AppServiceHTTPLogs`) gets TI005 for `where Confidence > 50`.

## Status, honestly

- The numbers in the tables above come from my lab workspace (October 2026), from the queries in `docs/lab-notes.md`.
- `TIActiveIndicators`, the hunting queries and the TI rules are written against the documented `ThreatIntelIndicators` schema and Microsoft's own rule patterns. They have **not** yet been run against production telemetry: the lab workspace had no sign-in, firewall or endpoint data to match against.
- CI checks what can be checked offline: every rule has the fields Sentinel needs, valid MITRE IDs and tactics, entity columns that exist in the query, a TI block that matches the function, and a clean lint.

## Deploying

- **Function:** Logs → paste `functions/TIActiveIndicators.kql` → Save as function `TIActiveIndicators`, then remove the two `let` lines and add them as parameters if you want to call it with a different threshold.
- **Rules:** Analytics → Create → Scheduled query rule, and copy the query, frequency, period, tactics and entity mappings. They're in the same YAML format as the Azure-Sentinel repo, so they also work with repositories / CI deployment.
- **Thresholds:** `missing_confidence_as` (default 50) decides what an indicator with no confidence is worth. Set `min_confidence` above it to exclude those on purpose, not by accident.

## License

MIT
