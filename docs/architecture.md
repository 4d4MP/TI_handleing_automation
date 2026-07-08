# Architecture — TI-handler playbook

## Purpose

When a Microsoft Sentinel automation rule launches this playbook on a **relay** incident, it **autonomously**:

0. **First:** activates the triggering (relay) incident (titled `AUTO_TI_correlated_IPs`, id taken straight from the trigger) **and** the two source incidents it finds by title — Incident A ("A network session Source address … matched an IoC.") and Incident B ("#TI Map IP Entity to CommonSecurityLog") — moving them all to **Active**. If the sources are absent the relay is still activated and the run proceeds normally.
1. Pulls IP entities from the (relay) incident, and creates a **run-record sub-task** (type `Operation sub-task`, priority `4 - Normal`, summary "Automatic response", assigned to the `sentinelsvc` service account) on the change — before any technical change.
2. Raises an OPSLSY *Technical change* (a logical clone of the template `OPSLSY-75376`) and walks it to **Planning**.
3. Health-checks AbuseIPDB. **If it is down, nothing is blocked**: a CSV of all incident IPs is attached, a "manual intervention required" comment is posted, the change is assigned to SecOps and **left in Planning**, the source incidents are commented (left Active), the run-record sub-task is moved to **On Hold**, and the run ends Succeeded. Otherwise the change is walked to **Implementation** and enrichment proceeds.
4. Enriches each IP against AbuseIPDB and filters out IPs below the report threshold or owned by an ignored ISP.
5. Appends the surviving IPs (one per line, deduped) to a static-site blocklist blob — **ungated**; there is no approval.
6. Attaches the CSV report to the change and walks it to **Post-implementation review**.
7. **Stops at Post-implementation review:** assigns the change to **SecOps**, moves the run-record sub-task to **Resolved**, closes the relay incident **and** the two source incidents as **Closed / TruePositive** (comment `Automatically handled in <OPSLSY change key>`), and terminates Succeeded — the change is **left in Post-implementation review** for a human to review and close (it is **not** auto-closed).
8. **On any failure** after the sub-task is created, the run-record sub-task is moved to **On Hold** and the run ends Failed.

The whole flow runs in a single Azure Logic App (Consumption). There is no Python — the filter loop lives entirely in the workflow. There is **no human approval gate** and **no CLOPSSEC ticket** (both removed), but the final Close is a **manual** step (the run stops at Post-implementation review). The change lifecycle is wrapped in a `Run_Change` scope whose Succeeded/Failed status (plus a `Run_Outcome` marker) drives the outcome handlers. The playbook manages the *relay* incident that fires the automation rule **and** the two *source* incidents — their status/classification, plus comments on the fallback path.

## Sequence

```
Sentinel incident trigger (relay incident)
  │
  ├─► Initialize_Incident_Arm_Ids  (root-level array variable)
  ├─► Find_And_Activate_Incidents  (runs FIRST; Entities waits on it)
  │       ├─ List_Sentinel_Incidents  (Http GET mgmt REST, MI; $filter status ne 'Closed', newest first)
  │       ├─ Filter_Target_Incidents  (title A prefix+suffix OR title B exact)
  │       ├─ Build_Incident_Ids / Set_Incident_Arm_Ids  (union relay id from trigger + matched source ARM ids)
  │       └─ Activate_Incidents (Foreach: relay + sources) → Update_Incident_Active (put /Incidents, status Active)
  │
  ├─► Entities - Get IPs          (Sentinel connector; runAfter Find_And_Activate_Incidents S/F/Skipped)
  ├─► Get_Jira_password           (Key Vault, secureData)
  ├─► Capture_Run_Start + Compute_Run_Times  (actualStart/Finish, dateStamp, fileStamp, displayStart/Finish in CET, summary; Planned start/end are computed fresh with utcNow() at the Override + Implementation writes)
  ├─► Initialize Excluded_IPs / Block_IPs / CSV_Rows / Clone_Key  (root-level variables)
  │
  ├─► Resolve_Template_Id          (GET issue/OPSLSY-75376?fields=id) → Parse_Template_Id
  ├─► Clone_OPSLSY_Change          (POST /secure/CloneIssueDetails.jspa, Basic + X-Atlassian-Token:no-check)
  ├─► Check_Clone_Status           (runAfter Succeeded|Failed; 302/2xx → continue, else Terminate)
  ├─► Find_Clone_Key (Until)       (poll GET /search jql=reporter+created>=-10m → Set_Clone_Key at loop top-level; exit on key presence)
  ├─► Verify_Clone_Found           (Clone_Key empty → Terminate CloneNotFound)
  ├─► Override_Clone_Fields        (PUT issue/{Clone_Key}: description + planned start/end)
  ├─► Create_Run_Subtask           (POST /issue: run-record sub-task, type={SubtaskIssueTypeName}=Operation sub-task, priority={SubtaskPriorityName}=4 - Normal, summary="Automatic response", assignee={SubtaskAssigneeName}=sentinelsvc)
  ├─► Set_Subtask_Key              (SetVariable Subtask_Key = body(Create_Run_Subtask).key)
  │
  ├─► Run_Change (Scope; runAfter Set_Subtask_Key) — any unhandled failure inside → scope Failed → On_Run_Failed
  │     ├─► Walk_to_Planning            (re-probe transitions → POST → poll; on fail: Set_Failure_Msg_* + Force_Fail_* @div(1,0))
  │     ├─► AbuseIPDB_health_check (AbuseIPDBAPI GET /check?ipAddress=8.8.8.8)
  │     │       ├─(Succeeded)─► Walk_to_Implementation → Enrichment_Scope → Build_CSV → Write_Blocklist_Blob
  │     │       │                 → Attach_CSV_to_Jira → Walk_to_Post_Implementation_Review → Set_Outcome_Success (Run_Outcome='success')
  │     │       └─(Failed/TimedOut)─► Fallback_Manual_Intervention (LEFT in Planning, nothing blocked)
  │     │                               ├─ Select_Fallback_Rows / Build_Fallback_CSV / Attach_Fallback_CSV
  │     │                               ├─ Comment_Manual_Intervention (POST /comment on Jira change)
  │     │                               └─ Assign_To_SecOps (PUT /assignee = {MainTicketAssigneeName}=secops)
  │     │                             → Comment_Source_Incidents (post /Incidents/Comment; incidents LEFT Active)
  │     │                             → Set_Outcome_Fallback (Run_Outcome='fallback')
  │     (NB: Fallback runAfter AbuseIPDB [Failed,TimedOut] — NOT Skipped: a Planning failure Skips AbuseIPDB and must route to failure, not fallback)
  │
  ├─► On_Run_Succeeded (If Run_Outcome=='success'), runAfter Run_Change [Succeeded]
  │       ├─ true:  Assign_Main_To_SecOps (PUT /assignee={MainTicketAssigneeName}) → Approve_Subtask (→{SubtaskSuccessStatusName})
  │       │          → Close_Source_Incidents (relay + sources; put /Incidents, Closed + TruePositive) → Terminate Succeeded  (STOP at PIR)
  │       └─ else:  Reject_Subtask (→{SubtaskFailureStatusName}) → Terminate Succeeded   (fallback)
  └─► On_Run_Failed (Scope), runAfter Run_Change [Failed]
          Reject_Subtask (→{SubtaskFailureStatusName})
          → Decide_Failure_Terminate: Run_Outcome=='fallback' ? Terminate Succeeded : Terminate Failed (Failure_Message)
```
The run **stops at Post-implementation review** — `Walk_to_Closed` was removed; the change is
left for a human to close. The six structured transition-guard Terminates were converted to
`Set_Failure_Msg_* + Force_Fail_*` so failures fail the `Run_Change` scope (rather than
hard-terminating the run) and route to `On_Run_Failed`, which Rejects the run-record sub-task.

## Resources

| Resource | Type | Purpose |
|---|---|---|
| `Microsoft.Logic/workflows` | Logic App (Consumption) | The playbook itself, with a system-assigned managed identity. |
| `Microsoft.Web/connections` (azuresentinel) | API connection — created by this template | Sentinel incident trigger, `entities/ip`, and incident lifecycle (`PUT /Incidents` status/classification, `POST /Incidents/Comment`). Auth: managed identity. |
| `Microsoft.Web/connections` (keyvault) | API connection — created by this template | Reads the Trackspace service-account password. Auth: managed identity. |
| `Microsoft.Web/connections/abuseipdbapi-1` | API connection — **OMS-backed, referenced not created** | Backs the AbuseIPDB custom connector. Carries its own AbuseIPDB API key inside the connection resource. |
| Static-site storage account | External | Hosts the blocklist blob (`$web/index.html`). |

The Sentinel connection is used by the **trigger**, `entities/ip`, and the incident lifecycle: a managed-identity `GET` to the SecurityInsights management REST API finds the two source incidents by title (the relay incident's id comes straight from the trigger), then the azuresentinel connector `PUT /Incidents` (status Active at start, status Closed + classification TruePositive at end) and `POST /Incidents/Comment` (fallback path) update the relay incident and both source incidents. The workspace is `LogAnalyticsResourceID` (default `lsy-prd-oms`).

AbuseIPDB calls go through the OMS-owned custom connector (cross-RG reference). This playbook references the existing connection by resource ID; it does not create, modify, or rotate it.

Blob storage is intentionally **not** behind an API connection. The Logic App calls `https://<account>.blob.core.windows.net/$web/index.html` directly using the managed identity (`audience=https://storage.azure.com/`), avoiding the connector's double-URL-encoded path for the `$web` container.

## Required RBAC for the managed identity

Grant on the Logic App's system-assigned identity after first deploy (the ARM template outputs `managedIdentityPrincipalId`):

| Scope | Role | Why |
|---|---|---|
| Sentinel workspace | `Microsoft Sentinel Responder` | Read incident entities; list/read incidents (mgmt REST) and update their status/classification + post comments. |
| Key Vault holding the Jira secret | `Key Vault Secrets User` | Read the Trackspace service-account password. |
| Blocklist storage account | `Storage Blob Data Contributor` | GET + PUT on `$web/index.html`. |

The managed identity does **not** need any permission on the AbuseIPDB connection itself; the API key is baked into the OMS connection resource.

## The change ticket — OPSLSY Technical change

The ticket is produced by a **server-side clone** of the template `OPSLSY-75376`, not by `POST /issue`. The reason is `customfield_24305` (**Affected item**): a Riada Insight/Assets object field whose Provider Service object (`LCJ-37462`) is outside the field's REST key-resolver scope, so it **cannot be set via any REST write shape** (`{"key":…}` → "Could not find"; id/string forms → silently ignored → "required") — yet it is required to pass `Start implementation`. A clone copies the Assets value (and every other change field) intact. Flow: `Resolve_Template_Id` (GET the template's numeric id) → `Clone_OPSLSY_Change` (`POST /secure/CloneIssueDetails.jspa`, form-encoded, Basic auth + `X-Atlassian-Token: no-check`, `cloneAttachments/SubTasks/Links=false`; the servlet answers `302`, which the HTTP action reports as `Failed`, so `Check_Clone_Status` runs on `Succeeded|Failed` and treats `2xx`/`3xx` as success — `4xx`/`5xx` terminate the run) → `Find_Clone_Key` (the clone is async, so poll `GET /search` with `reporter = sentinelsvc AND issuetype = "Technical change" AND created >= -10m ORDER BY created DESC`, capturing `issues[0].key` into `Clone_Key` whenever the search returns an issue — a reporter+time-window lookup, not a `summary ~ marker` text match — and exiting the loop on key presence) → `Verify_Clone_Found` (terminate `CloneNotFound` if still empty) → `Override_Clone_Fields` (`PUT` description + planned start/end while Open; summary was set by the clone). Full detail in `docs/07-ti-handler-playbook.md`.

Everything else — Category, Type, Reason, Impact, Risk, Owner, Change manager, Change tested, Rollback, Validation, and the **Affected item** — is inherited from the template clone and never set by the playbook.

### The walk (name-driven)

The transition ids are per-workflow and drift between test and prod, so the walk never hardcodes them. At each step it `GET`s `/issue/{key}/transitions?expand=transitions.fields`, filters to the transition whose `to.name` contains the desired status name (case-insensitive) **and** whose `name` does not contain `revoke / withdraw / re-plan / reject / cancel / update cmdb`, then `POST`s `{transition:{id}, fields:{…}}`. Because heavy Trackspace transitions often drop the HTTP connection but still commit, each step then **polls** `GET /issue/{key}?fields=status` in an `Until` (10 s × up to 60 / PT10M) until the status lands, and the poll runs even if the POST is reported `Failed`/`TimedOut`.

Each step is **hardened so a stuck transition fails loudly** rather than POSTing an empty id and limping on: `Guard_Transition_*` `Terminate`s with `TransitionNotFound` (+ current status) if the name filter is empty, and `Confirm_*_Landed` re-fetches the status after the poll and `Terminate`s with `TransitionDidNotLand` if the ticket isn't in the target status.

Per-transition `fields`: Planning sends none; **Implementation sets `customfield_22500`/`22501` (Planned start/end) = a fresh `utcNow()` / `utcNow()+30`, computed on the Post** — Planned start = current time, so it is the current minute and passes the *Start implementation* non-past-Planned-start validator (a value computed once at run start goes stale during the walk and is rejected, since Jira datetime fields are minute-granular). Post implementation review sends `resolution=Successful` plus `customfield_23600`/`customfield_23601` (Actual start/finish) = `Compute_Run_Times.actualStart`/`actualFinish` (real run start / +10). The description's *Accurate start/finish* also come from `Compute_Run_Times` (`displayStart`/`displayFinish`, real, in CET). (The Affected item and the other change fields are inherited from the clone.)

## Filter semantics

An IP **survives** the filter iff:

```
coalesce(totalReports, 0) >= MinReports
AND
no entry e in ExcludedISPs satisfies  toLower(e) is a substring of toLower(isp)
```

Defaults: `MinReports = 100`; `ExcludedISPs = ["akamai technologies", "google", "palo alto networks", "the shadowserver foundation", "censys"]` (lower-case **substring** match — AbuseIPDB appends legal suffixes like `"Palo Alto Networks, Inc"`, so an exact match would miss them). `Filter_Min_Reports` keeps the threshold survivors, `Collect_Excluded_IPs` loops the static `ExcludedISPs` list one sequential iteration at a time (`concurrency.repetitions = 1`, so the append is race-free) collecting matched IPs into `Excluded_IPs`, and `Filter_Kept_Rows` drops any survivor in `Excluded_IPs`. The CSV (`CSV_Rows`) and blocklist set (`Block_IPs`) are both built from the kept rows, so attachment and blocklist agree. IPs whose `/check` call fails are skipped by `Handle_Failed_Check`.

### AbuseIPDB outage → manual-intervention fallback

`AbuseIPDB_health_check` runs right after `Walk_to_Planning`, **before** the change is advanced to Implementation. If it fails (`Failed`/`TimedOut`), `Fallback_Manual_Intervention` runs instead of the Implementation walk + `Enrichment_Scope`. **Nothing is blocked** — the raw, un-enriched incident IPs are deliberately *not* pushed to the blocklist, because they bypass the report-threshold and ISP-exclusion filtering and could include IPs that must never be blocked. Instead the scope: builds a CSV of all incident IPs (`Select_Fallback_Rows` → `Build_Fallback_CSV`), attaches it (`Attach_Fallback_CSV`), posts a "manual intervention required" comment (`Comment_Manual_Intervention`), assigns the change to SecOps (`Assign_To_SecOps`, `PUT /assignee` = `MainTicketAssigneeName`), and **leaves the change in Planning** (no transition); then `Comment_Source_Incidents` comments the relay and source incidents and `Set_Outcome_Fallback` marks `Run_Outcome='fallback'`. The success handler's else-branch then moves the run-record sub-task to **On Hold** and ends the run `Succeeded` (handled outcome, no failure alert). **Fallback runs after `AbuseIPDB_health_check [Failed, TimedOut]` only — not `Skipped`:** a Planning-stage failure Skips the health check and must route to the failure handler (sub-task On Hold, run Failed), not be mislabeled an AbuseIPDB outage.

## Blocklist update semantics (ungated)

1. `GET https://<acct>.blob.core.windows.net/$web/index.html` (managed identity).
2. Split the existing content on `\n` (after stripping `\r`) and filter `Block_IPs` against the resulting array via exact-equality membership (line-level dedupe — `1.1.1.1` is not "already present" because `1.1.1.10` exists).
3. If new IPs remain, build `<existing><\n if needed><newline-joined new>\n` and `PUT` it back as a `BlockBlob` with `x-ms-blob-content-type: text/html`.
4. If nothing new, skip the PUT.

The write happens on every healthy-path run regardless of IP count and with no approval gate — it is the actual change being implemented while the ticket sits in Implementation. It does **not** run on the AbuseIPDB-outage fallback path.

### Known race window — concurrent runs

The PUT is unconditional (no `If-Match` / blob lease). Two runs reaching the blob-update step within a few seconds can have the later writer overwrite the earlier one's IPs. Mitigation is operational: re-run the playbook on the affected incidents — the dedupe in step 2 makes re-runs idempotent. If collisions are seen in practice, switch `Update_blob` to an `If-Match` (ETag) header with a retry-on-412 Until loop.

## Decisions and trade-offs

- **Change-managed, human-closed.** The approval gate and CLOPSSEC ticket were removed by management decision. The ticket of record is an OPSLSY Technical change that sits in **Implementation** while the work runs, then advances to **Post-implementation review** where the automation **stops** and assigns the change to SecOps — a human reviews and closes it. A **run-record sub-task** (assigned to the `sentinelsvc` service account) records the run outcome: **Approved** on success, **Rejected** on failure or fallback.
- **Health-check gates Implementation.** The change is advanced to Implementation *only after* `AbuseIPDB_health_check` succeeds. If AbuseIPDB is down the change is deliberately left in **Planning** and handed to SecOps (CSV + comment + assignee) rather than auto-blocking un-enriched IPs.
- **Reject-on-any-failure.** The whole change lifecycle is wrapped in a `Run_Change` scope. The structured transition-guard Terminates were converted to `Set_Failure_Msg_* + Force_Fail_* (@div(1,0))` so a failure fails the *scope* (not hard-terminates the run), letting the top-level `On_Run_Failed` handler move the run-record sub-task to **On Hold** and end the run Failed with the captured message. A `Run_Outcome` variable (`success`/`fallback`) disambiguates the success handler. **Note:** `Fallback_Manual_Intervention` runs after `AbuseIPDB_health_check [Failed, TimedOut]` only — **not** `Skipped` — because a Planning-stage failure Skips the health check and must route to the failure handler, not be mislabeled an AbuseIPDB outage.
- **Name-driven walk, not hardcoded ids.** Survives test↔prod transition-id drift; the skip-list avoids revoke/withdraw/reject/cancel edges.
- **Poll-until-landed after each transition.** Trackspace transitions can drop the connection while still committing; trusting the POST response would misreport state.
- **Gateway session-affinity cookie.** Trackspace can sit behind an Azure Application Gateway with cookie-based affinity that `307`-redirects the first cookieless request to plant `ApplicationGatewayAffinity`/`JSESSIONID` (observed on INT). A `Prime_Affinity_Cookie` GET (its `307` tolerated) captures that `Set-Cookie`; `Build_Cookie_Parts`/`Set_Affinity_Cookie` reduce it to a `name=value; …` string in the `Affinity_Cookie` variable; every Jira HTTP call then sends `Cookie: @variables('Affinity_Cookie')` so the gateway serves the pinned backend instead of looping on `307`. Empty/harmless where a gateway doesn't use affinity.
- **No Function App.** Filtering is small and rare; keeping it in the Logic App removes a deploy target.
- **Parallel enrichment (`concurrency.repetitions = 50`).** Each iteration only does its HTTP call + `Compose_Row`; `result()` is reshaped afterwards into report rows and the kept set. Ordering becomes completion order; nothing downstream depends on it.
- **Resilient per-IP enrichment + safe outage fallback.** A failed `/check` is caught per iteration; a total AbuseIPDB outage routes to the manual-intervention fallback (CSV + comment + SecOps assignment, left in Planning, nothing blocked) instead of auto-blocking un-enriched IPs or aborting.
- **Multipart attachment via HTTP action** (`X-Atlassian-Token: no-check`, `body.$multipart`).
- **Blob via HTTP + managed identity** rather than the Azure Blob connector to avoid the `$web` double-encoding gotcha.
- **Secrets flagged `secureData`** on `Get_Jira_password` and every Trackspace HTTP call carrying the Basic auth header. AbuseIPDB has no `secureData` flag because the key never enters the workflow.

## Reference workflows

Originals provided by the user, kept verbatim under `docs/references/`:

- `abuseipdb_enrichment.json` — Sentinel trigger + entities/ip + AbuseIPDB call shape.
- `trackspacejira_ticket_opener.json` — Key Vault secret pattern + Jira issue creation.
- `trackspacejira_ticket_close.json` — Jira polling + status parsing + transition pattern.
