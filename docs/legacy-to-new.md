# ThreatIntelligenceIndicator → ThreatIntelIndicators

Microsoft's migration guidance (*Work with STIX objects and indicators*): the new tables were previewed on April 3, 2025, and Sentinel stopped ingesting into the legacy `ThreatIntelligenceIndicator` table after **July 31, 2025**.

| Legacy column | In ThreatIntelIndicators |
|---|---|
| NetworkIP | `ObservableValue` where `ObservableKey == "ipv4-addr:value"` |
| NetworkSourceIP | `ObservableValue` where `ObservableKey == "network-traffic:src_ref.value"` |
| NetworkDestinationIP | `ObservableValue` where `ObservableKey == "network-traffic:dst_ref.value"` |
| *(IPv6)* | `ObservableValue` where `ObservableKey == "ipv6-addr:value"` |
| DomainName | `ObservableValue` where `ObservableKey == "domain-name:value"` |
| Url | `ObservableValue` where `ObservableKey == "url:value"` |
| EmailSenderAddress | `ObservableValue` where `ObservableKey == "email-addr:value"` |
| FileHashValue / FileHashType | `ObservableValue` where `ObservableKey has "file:hashes"` (type is in the key: MD5, SHA-1, SHA-256) |
| Description | `tostring(Data.description)` |
| ThreatType | `tostring(Data.indicator_types[0])` |
| IndicatorId | `Id`, or `tostring(Data.id)` |
| ConfidenceScore | `Confidence` (may be null) |
| ExpirationDateTime | `ValidUntil` |
| Active | `IsActive`, plus `IsDeleted` and `Revoked` |
| TrafficLightProtocolLevel | `tostring(AdditionalFields.TLPLevel)` |
| KillChainPhases, Labels, ExternalReferences | `Data.kill_chain_phases`, `Data.labels`, `Data.external_references` |

## Three rules of thumb

1. **Deduplicate first:** `summarize arg_max(TimeGenerated, *) by Id`. The table keeps every version of an indicator.
2. **Match IPs on all four keys:** `ipv4-addr:value`, `ipv6-addr:value`, `network-traffic:src_ref.value` and `network-traffic:dst_ref.value`.
3. **Decide what a missing `Confidence` means** before you filter on it.

Non-indicator STIX objects (threat actors, attack patterns, relationships) live in `ThreatIntelObjects`, filtered by `StixType`.
