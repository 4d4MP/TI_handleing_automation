# Architecture — Sentinel IP-Abuse Triage & Block Playbook

## Purpose

When a Microsoft Sentinel incident is created, this playbook:

1. Pulls IP entities from the incident.
2. Enriches each IP against AbuseIPDB.
3. Filters out IPs that are below the report threshold or owned by an ignored ISP.
4. Opens a Trackspace (Jira) approval ticket in project `CLOPSSEC` with a CSV report attached.
5. Polls the Jira ticket every five minutes until its status reaches `Approval` (case-insensitive), or until the configured timeout.
6. On approval, appends the surviving IPs (one per line, deduped) to a static-site blocklist blob.

The whole flow runs in a single Azure Logic App (Consumption). There is no Python — the filter loop lives entirely in the workflow.

## Sequence

```
Sentinel incident trigger
  │
  ├─► Entities - Get IPs          (Sentinel connector)
  │
  ├─► Get_Jira_password           (Key Vault, secureData)
  │   (AbuseIPDB auth is bound to the OMS-owned AbuseIPDBAPI connection — no KV fetch.)
  │
  ├─► AbuseIPDB_health_check (AbuseIPDBAPI GET /check?ipAddress=8.8.8.8)
  │       │
  │       └─(Failed/TimedOut)─► Comment + Terminate(Failed)
  │
  ├─► Foreach IP in body('Entities - Get IPs').IPs  (parallel, up to 50 at once)
  │       ├─ AbuseIPDBAPI GET /check?ipAddress=<ip>
  │       ├─ On success ─► Compose_Row (build one report row)
  │       └─ On failure  ─► Handle_Failed_Check catches the error (IP is skipped)
  │
  ├─► Build_Report_Rows = Select(outputs) over result('Foreach') where Compose_Row Succeeded
  ├─► Build_Kept_IPs    = Select(ip) over Build_Report_Rows kept by the filter below
  │
  └─► If length(Build_Kept_IPs) == 0
        ├─ True  ─► Comment "no actionable IPs" + Terminate(Succeeded)
        └─ Else  ─► Build_CSV (Table action, format=CSV, from=Build_Report_Rows)
                   ├─ Create_Jira_Task  (POST /rest/api/2/issue, Basic auth)
                   ├─ Attach_CSV_to_Jira (POST /rest/api/2/issue/{key}/attachments, multipart)
                   ├─ Comment Jira URL on the incident
                   ├─ Until toLower(status) == toLower(JiraApprovalStatusName)
                   │     ├─ Delay PT5M
                   │     ├─ HTTP GET /rest/api/2/issue/{key}?fields=status
                   │     └─ ParseJson → fields.status.name
                   └─ Switch on (approved | not_approved)
                         ├─ approved:
                         │    ├─ GET blob $web/index.html
                         │    ├─ Filter Build_Kept_IPs against existing content (dedupe)
                         │    ├─ If anything new: Compose new body + PUT blob
                         │    └─ Comment on incident with count appended/skipped
                         └─ default:
                              └─ Comment "approval not received"
```

## Resources

| Resource | Type | Purpose |
|---|---|---|
| `Microsoft.Logic/workflows` | Logic App (Consumption) | The playbook itself, with a system-assigned managed identity. |
| `Microsoft.Web/connections` (azuresentinel) | API connection — created by this template | Sentinel incident trigger + `entities/ip` + comments. Auth: managed identity. |
| `Microsoft.Web/connections` (keyvault) | API connection — created by this template | Reads the Jira service-account password. Auth: managed identity. |
| `Microsoft.Web/connections/abuseipdb-connection-AbuseIPDB-EnrichIncidentByIPInfo` | API connection — **OMS-owned, referenced not created** | Backs the `AbuseIPDBAPI` custom connector. Carries its own AbuseIPDB API key inside the connection resource. |
| Static-site storage account | External | Hosts the blocklist blob (`$web/index.html`). |

AbuseIPDB calls go through the OMS-owned `AbuseIPDBAPI` custom connector (cross-RG reference to `LSY_WEUR_ITCS_PRD_OMS_RG_001`). This playbook references the existing connection by resource ID; it does not create, modify, or rotate it.

Blob storage is intentionally **not** behind an API connection. The Logic App calls `https://<account>.blob.core.windows.net/$web/index.html` directly using the managed identity (`audience=https://storage.azure.com/`), avoiding the connector's double-URL-encoded path for the `$web` container.

## Required RBAC for the managed identity

Grant on the Logic App's system-assigned identity after first deploy (the ARM template outputs `managedIdentityPrincipalId`):

| Scope | Role | Why |
|---|---|---|
| Sentinel workspace | `Microsoft Sentinel Responder` | Read incident entities, add comments. |
| Key Vault holding the Jira secret | `Key Vault Secrets User` | Read the Jira service-account password. (No AbuseIPDB secret in KV — the OMS connection carries its own auth.) |
| Blocklist storage account | `Storage Blob Data Contributor` | GET + PUT on `$web/index.html`. |

The managed identity does **not** need any permission on the AbuseIPDB connection itself; the API key is baked into the OMS connection resource and used by the Logic Apps runtime when the action is invoked through it.

## Filter semantics

An IP **survives** the filter iff:

```
coalesce(totalReports, 0) >= MinReports
AND
toLower(coalesce(isp, '')) NOT IN ExcludedISPs
```

Defaults: `MinReports = 100`; `ExcludedISPs = ["akamai technologies", "google", "palo alto networks", "the shadowserver foundation", "censys"]` (lower-case match).

Every IP that AbuseIPDB successfully returns — kept or dropped — is recorded in `Build_Report_Rows`, which becomes the CSV attachment. The Jira ticket therefore shows the full enrichment, while only filtered IPs make it into the kept count and the eventual blocklist. IPs whose `/check` call fails (e.g. an HTTP 429 rate-limit, more likely under 50-way parallelism) are skipped by `Handle_Failed_Check` and appear in neither the report nor the kept set.

## Approval semantics

The Until loop's exit condition is:

```
toLower(coalesce(fields.status.name, '')) == toLower(JiraApprovalStatusName)
```

Default `JiraApprovalStatusName` is `"approval"`, compared case-insensitively. The Until's `limit.count` and `limit.timeout` are parameterised; with defaults of 576 iterations × 5 min, the playbook waits up to 48 hours. If the timeout fires before approval, the Until action ends in `Failed` / `TimedOut`; the downstream `Final_Switch` is wired to run on those statuses too, lands in the `default` branch, and adds a "approval not received" comment to the incident — the blocklist is **not** modified.

## Blocklist update semantics

1. `GET https://<acct>.blob.core.windows.net/$web/index.html` (managed identity).
2. Split the existing content on `\n` (after stripping `\r`) and filter `Build_Kept_IPs` against the resulting array via exact-equality membership. This is line-level dedupe — `1.1.1.1` is not considered "already present" just because `1.1.1.10` appears in the file.
3. If new IPs remain, build `<existing><\n if needed><newline-joined new>\n` and `PUT` it back as a `BlockBlob` with `x-ms-blob-content-type: text/html` (preserving the static-site MIME).
4. If nothing new, skip the PUT but still comment on the incident.

### Known race window — concurrent approvals

The PUT is unconditional (no `If-Match` / blob lease). If two approved playbook runs reach the blob-update step at the same moment, both will read the same baseline, both will compute and PUT new content, and the later writer wins — the earlier writer's IPs are lost. The window is the few seconds between `Get_blob_content` and `Update_blob` per run, so collisions require analysts to approve two tickets within roughly that window.

Mitigation is operational rather than in-workflow: after a burst of approvals, an analyst can re-run the playbook on each affected incident — the dedupe in step 2 means re-runs are idempotent, and any IPs lost to the race will be re-appended on the second attempt. The trade-off was taken deliberately to keep the workflow simple; if collisions are observed in practice, switch the `Update_blob` action to use an `If-Match` header (ETag from `Get_blob_content`) with a retry-on-412 Until loop.

## Decisions and trade-offs

- **No Function App.** Filtering is small and rare; keeping it inside the Logic App removes a deploy target.
- **Parallel enrichment (`concurrency.repetitions = 50`).** AbuseIPDB is called per IP, so a sequential loop made runtime scale linearly with the IP count. To parallelise we cannot mutate array variables inside the loop — `AppendToArrayVariable` returns unpredictable results under concurrency. Instead each iteration only does its HTTP call and a `Compose_Row`; after the loop, `result('Check_each_IP_in_AbuseIPDB')` exposes every iteration's outputs, which two `Select`/`Query` data operations reshape into `Build_Report_Rows` (the CSV) and `Build_Kept_IPs` (the filtered set). 50 is the documented maximum degree of parallelism for a Foreach. A side effect is that report/kept ordering is now completion order rather than input order; nothing downstream depends on order.
- **Resilient per-IP enrichment.** Because 50-way concurrency makes transient AbuseIPDB rate-limiting (HTTP 429) more likely, a failed `/check` is caught per iteration by `Handle_Failed_Check` (`runAfter HTTP_Check_IP: [Failed, TimedOut, Skipped]`) so a single failure skips that IP instead of aborting the run. A *total* AbuseIPDB outage is still caught up front by `AbuseIPDB_health_check`, which terminates the run before the loop.
- **Two HTTP calls to AbuseIPDB per IP would be wasteful**, so the script makes one call per IP and reuses the result for both the report row and the filter decision.
- **Multipart attachment via HTTP action.** Jira's `/attachments` endpoint requires `multipart/form-data` and `X-Atlassian-Token: no-check`; Logic Apps supports this natively via `body.$multipart`.
- **Blob via HTTP + managed identity** rather than the Azure Blob connector to avoid the `$web`-container double-encoding gotcha in the V2 connector path.
- **Secrets are flagged `secureData`** on the `Get_Jira_password` action (the only Key Vault retrieval left) and on the Jira HTTP calls that include the Basic auth header. AbuseIPDB has no `secureData` flag because the key never enters the workflow — it's bound to the OMS connection.
- **Shared OMS AbuseIPDB connection** rather than a per-playbook custom connector + KV-stored key. Saves a moving part (no key to rotate, no KV access policy) and matches how the existing `abuseipdb_enrichment.json` playbook already calls AbuseIPDB. Trade-off: an OMS-side rotation, rename, or deletion of `abuseipdb-connection-AbuseIPDB-EnrichIncidentByIPInfo` will break this playbook, since the connection is referenced by absolute resource ID.

## Reference workflows

Originals provided by the user, kept verbatim under `docs/references/`:

- `abuseipdb_enrichment.json` — Sentinel trigger + entities/ip + AbuseIPDB call shape.
- `trackspacejira_ticket_opener.json` — Key Vault secret pattern + Jira issue creation.
- `trackspacejira_ticket_close.json` — Jira polling + status parsing pattern.

These are the templates this playbook composes.
