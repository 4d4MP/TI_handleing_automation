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
  ├─► Get_AbuseIPDB_key           (Key Vault, secureData)
  ├─► Get_Jira_password           (Key Vault, secureData)
  │
  ├─► AbuseIPDB_health_check (GET /check?ipAddress=8.8.8.8)
  │       │
  │       └─(Failed/TimedOut)─► Comment + Terminate(Failed)
  │
  ├─► Initialize Kept_IPs, Report_Rows (arrays)
  │
  ├─► Foreach IP in body('Entities - Get IPs').IPs  (sequential)
  │       ├─ HTTP GET /api/v2/check?ipAddress=<ip>
  │       ├─ Append row to Report_Rows
  │       └─ If totalReports >= MinReports AND toLower(isp) NOT in ExcludedISPs:
  │             └─ Append ip to Kept_IPs
  │
  └─► If length(Kept_IPs) == 0
        ├─ True  ─► Comment "no actionable IPs" + Terminate(Succeeded)
        └─ Else  ─► Build_CSV (Table action, format=CSV, from=Report_Rows)
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
                         │    ├─ Filter Kept_IPs against existing content (dedupe)
                         │    ├─ If anything new: Compose new body + PUT blob
                         │    └─ Comment on incident with count appended/skipped
                         └─ default:
                              └─ Comment "approval not received"
```

## Resources

| Resource | Type | Purpose |
|---|---|---|
| `Microsoft.Logic/workflows` | Logic App (Consumption) | The playbook itself, with a system-assigned managed identity. |
| `Microsoft.Web/connections` (azuresentinel) | API connection | Sentinel incident trigger + `entities/ip` + comments. Auth: managed identity. |
| `Microsoft.Web/connections` (keyvault) | API connection | Reads two secrets (AbuseIPDB key and Jira password). Auth: managed identity. |
| Static-site storage account | External | Hosts the blocklist blob (`$web/index.html`). |

Blob storage is intentionally **not** behind an API connection. The Logic App calls `https://<account>.blob.core.windows.net/$web/index.html` directly using the managed identity (`audience=https://storage.azure.com/`), avoiding the connector's double-URL-encoded path for the `$web` container.

## Required RBAC for the managed identity

Grant on the Logic App's system-assigned identity after first deploy (the ARM template outputs `managedIdentityPrincipalId`):

| Scope | Role | Why |
|---|---|---|
| Sentinel workspace | `Microsoft Sentinel Responder` | Read incident entities, add comments. |
| Key Vault holding the secrets | `Key Vault Secrets User` | Read AbuseIPDB key and Jira password. |
| Blocklist storage account | `Storage Blob Data Contributor` | GET + PUT on `$web/index.html`. |

## Filter semantics

An IP **survives** the filter iff:

```
coalesce(totalReports, 0) >= MinReports
AND
toLower(coalesce(isp, '')) NOT IN ExcludedISPs
```

Defaults: `MinReports = 100`; `ExcludedISPs = ["akamai technologies", "google", "palo alto networks", "the shadowserver foundation", "censys"]` (lower-case match).

Every IP — kept or dropped — is recorded in `Report_Rows`, which becomes the CSV attachment. The Jira ticket therefore shows the full enrichment, while only filtered IPs make it into the description and the eventual blocklist.

## Approval semantics

The Until loop's exit condition is:

```
toLower(coalesce(fields.status.name, '')) == toLower(JiraApprovalStatusName)
```

Default `JiraApprovalStatusName` is `"approval"`, compared case-insensitively. The Until's `limit.count` and `limit.timeout` are parameterised; with defaults of 576 iterations × 5 min, the playbook waits up to 48 hours. If the timeout fires before approval, the Until action ends in `Failed` / `TimedOut`; the downstream `Final_Switch` is wired to run on those statuses too, lands in the `default` branch, and adds a "approval not received" comment to the incident — the blocklist is **not** modified.

## Blocklist update semantics

1. `GET https://<acct>.blob.core.windows.net/$web/index.html` (managed identity).
2. Filter `Kept_IPs` to those not already present as substrings in the existing content (cheap dedupe; sufficient because the file is newline-delimited IPs).
3. If new IPs remain, build `<existing><\n if needed><newline-joined new>\n` and `PUT` it back as a `BlockBlob` with `x-ms-blob-content-type: text/html` (preserving the static-site MIME).
4. If nothing new, skip the PUT but still comment on the incident.

## Decisions and trade-offs

- **No Function App.** Filtering is small and rare; keeping it inside the Logic App removes a deploy target. The Foreach is sequential (`concurrency.repetitions = 1`) because `AppendToArrayVariable` is not safe under parallel iterations.
- **Two HTTP calls to AbuseIPDB per IP would be wasteful**, so the script makes one call per IP and reuses the result for both the report row and the filter decision.
- **Multipart attachment via HTTP action.** Jira's `/attachments` endpoint requires `multipart/form-data` and `X-Atlassian-Token: no-check`; Logic Apps supports this natively via `body.$multipart`.
- **Blob via HTTP + managed identity** rather than the Azure Blob connector to avoid the `$web`-container double-encoding gotcha in the V2 connector path.
- **Secrets are flagged `secureData`** on all relevant Key Vault and Jira/AbuseIPDB HTTP actions, so values never appear in run history.

## Reference workflows

Originals provided by the user, kept verbatim under `docs/references/`:

- `abuseipdb_enrichment.json` — Sentinel trigger + entities/ip + AbuseIPDB call shape.
- `trackspacejira_ticket_opener.json` — Key Vault secret pattern + Jira issue creation.
- `trackspacejira_ticket_close.json` — Jira polling + status parsing pattern.

These are the templates this playbook composes.
