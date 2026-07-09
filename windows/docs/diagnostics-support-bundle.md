# Windows Diagnostics Support Bundle

The Windows `exportDiagnostics` IPC command returns a bounded, structured,
default-safe support bundle. The same contract is used by the WinUI dashboard;
the dashboard displays the JSON and does not add an unverifiable file-picker or
filesystem export path.

## Default-safe contract

Every export contains these top-level fields in deterministic order:

- `schemaVersion`: support-bundle schema version, currently `1`.
- `service` and `qlinkCoreSuite`: compatibility fields retained from the
  original IPC v1 diagnostics document.
- `redactionPolicy`: `default-safe-v1`, the byte and peer-entry limits, and
  `rawExportAvailable: false`.
- `generatedAt`: generation time as Unix seconds.
- `exportState`: `complete` or `bounded_fallback`.
- `status`: connection, path, route/DNS mode, kill-switch, packet-session
  readiness, bounded peer summaries, allowlisted counters, trust state, and
  stable error categories.
- `diagnostics`: peer truncation counts and explicit exclusion flags.

The serialized JSON is capped at 64 KiB. At most 32 peer summaries are
included. `peerTotalCount`, `peerIncludedCount`, and `peerEntriesTruncated`
make truncation
visible. Peer entries use export-local labels (`peer_1`, `peer_2`, and so on)
and contain only path type, endpoint count, address-presence state, timing, and
traffic counters. Repeating the same snapshot with the same generation time
produces the same field order and content.

The service constructs this schema from support-only DTO allowlists. Shared
runtime metric structs are copied field by field, so adding a runtime field
cannot silently add it to support output. Arbitrary configuration,
status-error, trust-warning, and log strings are not serialized. Errors are
reduced to stable categories such as `dns`, `identity_registry`, `adapter`,
`kill_switch`, `routing`, `transport`, `configuration`, or `internal`.
Serialization or size-limit failure returns a valid `bounded_fallback` document
instead of panicking or emitting an oversized response.

The default bundle never contains:

- Raw peer IDs, aliases, public-key fingerprints, wallet addresses, wallet
  names, registry values, or chain identifiers.
- Secrets, keys, key material, keystore paths, tokens, or credentials.
- Endpoint addresses or ports, overlay addresses, routes or prefixes, DNS
  servers or search domains, SSIDs, external IP addresses, or host paths.
- Packet or game payloads, raw frames, packet captures, or PCAP data.
- Service/Event Viewer logs or any other unbounded text collection.

`logsIncluded: false` and `packetCapturesIncluded: false` are part of every
bundle. Raw packet captures are never included.

## Operator workflow

1. Open the Windows dashboard and select **Generate redacted JSON** under
   **Redacted support export**.
2. Confirm `schemaVersion`, `redactionPolicy.name`, `generatedAt`, and the
   `rawExportAvailable: false` exclusion before sharing the displayed JSON.
3. Attach only that JSON to a normal support case. Treat any unexpected raw
   identifier, address, route, DNS value, SSID, payload, or secret as a release
   blocker and security incident.
4. Use Event Viewer or `%ProgramData%\QuantumLink\logs` only when aggregate
   diagnostics are insufficient. Those sources are outside the support-bundle
   contract and must not be pasted wholesale into a ticket.

## Audit boundary

`exportDiagnostics` has no supported request options and no raw mode. Supplying
a `raw` property is rejected with `raw diagnostics export is not supported`;
it is never treated as a successful raw collection. The unprivileged UI
therefore cannot request raw service state through this IPC path.

If a production investigation requires evidence outside the default bundle,
an operator must collect the minimum necessary source from an elevated Windows
session under the host's access controls. The case record must identify the
operator, approver, reason, collection time, source, retention deadline, and
artifact hash, and must document a sensitivity review before transfer. This is
an out-of-band audited evidence workflow, not a QuantumLink raw-export feature.
The current service and UI intentionally provide no raw support exporter.

Any future raw-export proposal requires a separate privileged command,
authorization design, immutable audit event, strict size/retention limits, and
security review. It must not weaken or add a mode flag to `exportDiagnostics`.
