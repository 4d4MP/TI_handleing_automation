# Architecture — TI-handler playbook

## Purpose

When a Microsoft Sentinel incident is created, this playbook **autonomously**:

1. Pulls IP entities from the incident.
2. Raises an OPSLSY *Technical change* (a logical clone of the template `OPSLSY-75376`) and walks it to **Implementation** — at run start, before any enrichment.
3. Enriches each IP against AbuseIPDB and filters out IPs below the report threshold or owned by an ignored ISP (on an AbuseIPDB outage, falls back to the raw incident IPs).
4. Appends the surviving IPs (one per line, deduped) to a static-site blocklist blob — **ungated**; there is no approval.
5. Attaches the CSV report to the change.
6. Walks the change to **Closed** with resolution **Successful**.

The whole flow runs in a single Azure Logic App (Consumption). There is no Python — the filter loop lives entirely in the workflow. There is **no human approval** and **no CLOPSSEC ticket** (both removed); no comments are written back to the Sentinel incident.

## Sequence

```
Sentinel incident trigger
  │
  ├─► Entities - Get IPs          (Sentinel connector)
  ├─► Get_Jira_password           (Key Vault, secureData)
  ├─► Capture_Run_Start + Compute_Run_Times  (plannedStart, plannedEnd=+5m, dateStamp, summary)
  ├─► Initialize Excluded_IPs / Block_IPs / CSV_Rows / Clone_Key  (root-level variables)
  │
  ├─► Resolve_Template_Id          (GET issue/OPSLSY-75376?fields=id) → Parse_Template_Id
  ├─► Clone_OPSLSY_Change          (POST /secure/CloneIssueDetails.jspa, Basic + X-Atlassian-Token:no-check)
  ├─► Check_Clone_Status           (runAfter Succeeded|Failed; 302/2xx → continue, else Terminate)
  ├─► Find_Clone_Key (Until)       (poll GET /search jql=reporter+created>=-10m → set Clone_Key; exit on key presence)
  ├─► Verify_Clone_Found           (Clone_Key empty → Terminate CloneNotFound)
  ├─► Override_Clone_Fields        (PUT issue/{Clone_Key}: description + planned start/end)
  ├─► Walk_to_Planning            (re-probe transitions → POST → poll until landed)
  ├─► Walk_to_Implementation      (re-probe transitions → POST → poll until landed)
  │
  ├─► AbuseIPDB_health_check (AbuseIPDBAPI GET /check?ipAddress=8.8.8.8)
  │       ├─(Succeeded)─► Enrichment_Scope
  │       │                 ├─ Foreach IP (50-way): GET /check → Compose_Row / Handle_Failed_Check
  │       │                 ├─ Build_Report_Rows → Filter_Min_Reports → Collect_Excluded_IPs → Filter_Kept_Rows
  │       │                 ├─ Build_Kept_IPs
  │       │                 └─ Set Block_IPs = kept IPs ; CSV_Rows = kept rows
  │       └─(Failed/TimedOut/Skipped)─► Fallback_Build_Raw_IPs
  │                                       └─ Set Block_IPs = raw IPs ; CSV_Rows = raw rows
  │
  ├─► Build_CSV                    (Table/CSV from CSV_Rows ; runs after whichever branch ran)
  ├─► Write_Blocklist_Blob         (ungated: GET blob → dedupe Block_IPs → PUT if anything new)
  ├─► Attach_CSV_to_Jira           (POST /issue/{key}/attachments, multipart)
  ├─► Walk_to_Post_Implementation_Review  (POST resolution=Successful + actual start/finish, poll)
  └─► Walk_to_Closed               (POST resolution=Successful, poll until Closed / statusCategory done)
```

## Resources

| Resource | Type | Purpose |
|---|---|---|
| `Microsoft.Logic/workflows` | Logic App (Consumption) | The playbook itself, with a system-assigned managed identity. |
| `Microsoft.Web/connections` (azuresentinel) | API connection — created by this template | Sentinel incident trigger + `entities/ip`. Auth: managed identity. |
| `Microsoft.Web/connections` (keyvault) | API connection — created by this template | Reads the Trackspace service-account password. Auth: managed identity. |
| `Microsoft.Web/connections/abuseipdbapi-1` | API connection — **OMS-backed, referenced not created** | Backs the AbuseIPDB custom connector. Carries its own AbuseIPDB API key inside the connection resource. |
| Static-site storage account | External | Hosts the blocklist blob (`$web/index.html`). |

The Sentinel connection is now only used by the **trigger** and `entities/ip` — the playbook no longer posts incident comments.

AbuseIPDB calls go through the OMS-owned custom connector (cross-RG reference). This playbook references the existing connection by resource ID; it does not create, modify, or rotate it.

Blob storage is intentionally **not** behind an API connection. The Logic App calls `https://<account>.blob.core.windows.net/$web/index.html` directly using the managed identity (`audience=https://storage.azure.com/`), avoiding the connector's double-URL-encoded path for the `$web` container.

## Required RBAC for the managed identity

Grant on the Logic App's system-assigned identity after first deploy (the ARM template outputs `managedIdentityPrincipalId`):

| Scope | Role | Why |
|---|---|---|
| Sentinel workspace | `Microsoft Sentinel Responder` | Read incident entities. |
| Key Vault holding the Jira secret | `Key Vault Secrets User` | Read the Trackspace service-account password. |
| Blocklist storage account | `Storage Blob Data Contributor` | GET + PUT on `$web/index.html`. |

The managed identity does **not** need any permission on the AbuseIPDB connection itself; the API key is baked into the OMS connection resource.

## The change ticket — OPSLSY Technical change

The ticket is produced by a **server-side clone** of the template `OPSLSY-75376`, not by `POST /issue`. The reason is `customfield_24305` (**Affected item**): a Riada Insight/Assets object field whose Provider Service object (`LCJ-37462`) is outside the field's REST key-resolver scope, so it **cannot be set via any REST write shape** (`{"key":…}` → "Could not find"; id/string forms → silently ignored → "required") — yet it is required to pass `Start implementation`. A clone copies the Assets value (and every other change field) intact. Flow: `Resolve_Template_Id` (GET the template's numeric id) → `Clone_OPSLSY_Change` (`POST /secure/CloneIssueDetails.jspa`, form-encoded, Basic auth + `X-Atlassian-Token: no-check`, `cloneAttachments/SubTasks/Links=false`; the servlet answers `302`, which the HTTP action reports as `Failed`, so `Check_Clone_Status` runs on `Succeeded|Failed` and treats `2xx`/`3xx` as success — `4xx`/`5xx` terminate the run) → `Find_Clone_Key` (the clone is async, so poll `GET /search` with `reporter = sentinelsvc AND issuetype = "Technical change" AND created >= -10m ORDER BY created DESC`, capturing `issues[0].key` into `Clone_Key` whenever the search returns an issue — a reporter+time-window lookup, not a `summary ~ marker` text match — and exiting the loop on key presence) → `Verify_Clone_Found` (terminate `CloneNotFound` if still empty) → `Override_Clone_Fields` (`PUT` description + planned start/end while Open; summary was set by the clone). Full detail in `docs/07-ti-handler-playbook.md`.

Everything else — Category, Type, Reason, Impact, Risk, Owner, Change manager, Change tested, Rollback, Validation, and the **Affected item** — is inherited from the template clone and never set by the playbook.

### The walk (name-driven)

The transition ids are per-workflow and drift between test and prod, so the walk never hardcodes them. At each step it `GET`s `/issue/{key}/transitions?expand=transitions.fields`, filters to the transition whose `to.name` contains the desired status name (case-insensitive) **and** whose `name` does not contain `revoke / withdraw / re-plan / reject / cancel / update cmdb`, then `POST`s `{transition:{id}, fields:{…}}`. Because heavy Trackspace transitions often drop the HTTP connection but still commit, each step then **polls** `GET /issue/{key}?fields=status` in an `Until` (10 s × up to 60 / PT10M) until the status lands, and the poll runs even if the POST is reported `Failed`/`TimedOut`.

Each step is **hardened so a stuck transition fails loudly** rather than POSTing an empty id and limping on: `Guard_Transition_*` `Terminate`s with `TransitionNotFound` (+ current status) if the name filter is empty, and `Confirm_*_Landed` re-fetches the status after the poll and `Terminate`s with `TransitionDidNotLand` if the ticket isn't in the target status.

Per-transition `fields`: Planning sends none; **Implementation re-sends `customfield_22500`/`22501` (Planned start/end) = `plannedStart`/`plannedEnd`** so the *Start implementation* validator sees a non-past Planned start; Post implementation review sends `resolution=Successful` plus `customfield_23600`/`customfield_23601` (actuals) = the same `plannedStart`/`plannedEnd`; Closed sends `resolution=Successful`. All six date fields (description Accurate start/finish, Planned start/end, Actual start/finish) come from one source — `Compute_Run_Times` at **run start + 20 min / + 25 min** — so they are identical everywhere; the +20 min offset is the buffer that keeps Planned start in the future at the validator. (The Affected item and the other change fields are inherited from the clone.)

## Filter semantics

An IP **survives** the filter iff:

```
coalesce(totalReports, 0) >= MinReports
AND
no entry e in ExcludedISPs satisfies  toLower(e) is a substring of toLower(isp)
```

Defaults: `MinReports = 100`; `ExcludedISPs = ["akamai technologies", "google", "palo alto networks", "the shadowserver foundation", "censys"]` (lower-case **substring** match — AbuseIPDB appends legal suffixes like `"Palo Alto Networks, Inc"`, so an exact match would miss them). `Filter_Min_Reports` keeps the threshold survivors, `Collect_Excluded_IPs` loops the static `ExcludedISPs` list one sequential iteration at a time (`concurrency.repetitions = 1`, so the append is race-free) collecting matched IPs into `Excluded_IPs`, and `Filter_Kept_Rows` drops any survivor in `Excluded_IPs`. The CSV (`CSV_Rows`) and blocklist set (`Block_IPs`) are both built from the kept rows, so attachment and blocklist agree. IPs whose `/check` call fails are skipped by `Handle_Failed_Check`.

### AbuseIPDB outage → raw fallback

`AbuseIPDB_health_check` no longer terminates the run. If it fails, `Fallback_Build_Raw_IPs` runs instead of `Enrichment_Scope` and sets `Block_IPs` / `CSV_Rows` from the **raw** `Entities - Get IPs` list. There is no separate ticket and no early termination: the change created at run start is always attached-to and walked to Closed, so it is never stranded in Implementation. `Build_CSV` runs after whichever branch executed (`runAfter` accepts `Succeeded` or `Skipped` from both scopes).

## Blocklist update semantics (ungated)

1. `GET https://<acct>.blob.core.windows.net/$web/index.html` (managed identity).
2. Split the existing content on `\n` (after stripping `\r`) and filter `Block_IPs` against the resulting array via exact-equality membership (line-level dedupe — `1.1.1.1` is not "already present" because `1.1.1.10` exists).
3. If new IPs remain, build `<existing><\n if needed><newline-joined new>\n` and `PUT` it back as a `BlockBlob` with `x-ms-blob-content-type: text/html`.
4. If nothing new, skip the PUT.

The write happens on every run regardless of IP count and with no approval gate — it is the actual change being implemented while the ticket sits in Implementation.

### Known race window — concurrent runs

The PUT is unconditional (no `If-Match` / blob lease). Two runs reaching the blob-update step within a few seconds can have the later writer overwrite the earlier one's IPs. Mitigation is operational: re-run the playbook on the affected incidents — the dedupe in step 2 makes re-runs idempotent. If collisions are seen in practice, switch `Update_blob` to an `If-Match` (ETag) header with a retry-on-412 Until loop.

## Decisions and trade-offs

- **Fully autonomous, change-managed.** The approval gate and CLOPSSEC ticket were removed by management decision. The ticket of record is an OPSLSY Technical change that sits in **Implementation** while the work runs and closes when done — matching change-management semantics rather than an approval handshake.
- **Implementation-first ordering.** The change is created and advanced to Implementation *before* AbuseIPDB work so it is never stranded if enrichment fails; the close walk runs after the blob write + attachment.
- **Name-driven walk, not hardcoded ids.** Survives test↔prod transition-id drift; the skip-list avoids revoke/withdraw/reject/cancel edges.
- **Poll-until-landed after each transition.** Trackspace transitions can drop the connection while still committing; trusting the POST response would misreport state.
- **No Function App.** Filtering is small and rare; keeping it in the Logic App removes a deploy target.
- **Parallel enrichment (`concurrency.repetitions = 50`).** Each iteration only does its HTTP call + `Compose_Row`; `result()` is reshaped afterwards into report rows and the kept set. Ordering becomes completion order; nothing downstream depends on it.
- **Resilient per-IP enrichment + outage fallback.** A failed `/check` is caught per iteration; a total AbuseIPDB outage routes to the raw-IP fallback instead of aborting.
- **Multipart attachment via HTTP action** (`X-Atlassian-Token: no-check`, `body.$multipart`).
- **Blob via HTTP + managed identity** rather than the Azure Blob connector to avoid the `$web` double-encoding gotcha.
- **Secrets flagged `secureData`** on `Get_Jira_password` and every Trackspace HTTP call carrying the Basic auth header. AbuseIPDB has no `secureData` flag because the key never enters the workflow.

## Reference workflows

Originals provided by the user, kept verbatim under `docs/references/`:

- `abuseipdb_enrichment.json` — Sentinel trigger + entities/ip + AbuseIPDB call shape.
- `trackspacejira_ticket_opener.json` — Key Vault secret pattern + Jira issue creation.
- `trackspacejira_ticket_close.json` — Jira polling + status parsing + transition pattern.
