# 07 — TI-handler playbook (Sentinel → OPSLSY Technical change → blocklist)

**Logic App:** `TI-handler` (Consumption) in `LSY_WEUR_ITCS_PRD_SEC_RG_002`.
**Source of truth:** `playbook/workflow.json` + `playbook/azuredeploy.json` in this repo.
**Trigger:** Microsoft Sentinel incident creation.

The playbook is **fully autonomous** — there is no human approval step. Launched by a
Sentinel automation rule on a **relay** incident, it **first** finds the two source
incidents by title and moves them to **Active**, then raises one OPSLSY *Technical change*
and drives it to **Planning**, then health-checks AbuseIPDB. If AbuseIPDB is healthy it walks
the change to **Implementation**, enriches the incident IPs, writes the Palo Alto blocklist
blob, attaches the CSV, walks the change to **Closed** with resolution **Successful**, and
**finally** closes the two source incidents as **TruePositive** (comment: `Automatically
handled in <OPSLSY change key>`). If AbuseIPDB is **down** it blocks nothing: it attaches a
CSV of all incident IPs, comments that manual intervention is required, assigns the change to
SecOps, leaves it in **Planning**, and posts a manual-intervention comment on the two source
incidents while leaving them **Active** (see *AbuseIPDB outage* and *Source incident
lifecycle* below).

> **History:** this playbook previously opened a **CLOPSSEC** approval Task, waited
> up to 48 h for an analyst to move it to an approval status, and only then wrote
> the blocklist. Per a management decision that approval gate was removed and the
> ticket of record moved to an OPSLSY Technical change. All CLOPSSEC actions, the
> `Wait_For_Approval` Until loop, and the approve/not-approved switch are gone. (The
> playbook again writes to Sentinel, but only to the two *source* incidents it owns —
> status + classification + a comment — never to the relay incident that triggers it.)

---

## Order of operations (health-check gates Implementation)

```
trigger
  → clone OPSLSY-75376          (CloneIssueDetails.jspa servlet) + find new key by search
  → override fields             (PUT description + planned start/end; summary set at clone)
  → walk to Planning            (Open → Planning)
  → AbuseIPDB health check
       ├─ healthy → walk to Implementation   (Planning → Implementation)
       │            → enrich + build CSV      (AbuseIPDB filter/dedupe → kept-IP rows)
       │            → write blocklist blob    (ungated — the actual change being implemented)
       │            → attach CSV              (POST /issue/{key}/attachments)
       │            → walk to Closed          (Post implementation review → Closed, resolution Successful)
       └─ down → attach CSV of ALL IPs + comment + assign SecOps, LEFT in Planning
                 → Terminate (runStatus Succeeded)
```

On the healthy path the change sits in **Implementation** for the duration of the real
work (enrichment + blocklist write), matching change-management semantics, then closes when
the work is done. The change is advanced to Implementation **only after** the AbuseIPDB
health check succeeds — so an AbuseIPDB outage leaves it safely in Planning for SecOps
instead of stranding it in Implementation or auto-blocking un-enriched IPs.

All Trackspace calls use **Basic auth** — service account `sentinelsvc` with the
Key Vault secret `sentinelsvc` (read via the `keyvault-TI-handler` connection,
flagged `secureData`). Base URL `https://trackspace.lhsystems.com/rest/api/2/` (production,
set via `JIRAHOST`; switch to `https://int-trackspace.lhsystems.com` for the INT environment).

### Gateway session affinity (the `Cookie` header)

INT Trackspace sits behind an Azure **Application Gateway with cookie-based session
affinity**: the first request without the affinity cookie gets a **`307` redirect to
itself** that plants `ApplicationGatewayAffinity`/`…CORS` (and `JSESSIONID`) cookies, and
the Logic App HTTP action does not transparently re-issue with them — so every Jira call
would otherwise fail with `307`. The playbook handles this itself:

1. `Prime_Affinity_Cookie` — a `GET /rest/api/2/serverInfo` that is *expected* to `307`
   (its failure is tolerated); it exists only to collect the gateway's `Set-Cookie`.
2. `Build_Cookie_Parts` + `Set_Affinity_Cookie` — split that `Set-Cookie` on `,`, take the
   `name=value` before the first `;` of each, and join them with `; ` into the
   `Affinity_Cookie` variable (e.g. `ApplicationGatewayAffinity=…; ApplicationGatewayAffinityCORS=…; JSESSIONID=…`).
3. **Every** Jira HTTP call (`Resolve_Template_Id` onward — clone, search, all transition
   GET/POST/status, attach) sends `Cookie: @{variables('Affinity_Cookie')}`, so the gateway
   serves it on the pinned backend instead of `307`-ing. (Storage/AbuseIPDB/KV calls do not
   get the cookie.)

If the live (prod) gateway doesn't do cookie affinity the cookie is simply empty/ignored
and the calls work unchanged.

---

## The ticket — clone of OPSLSY-75376 (do NOT `POST /issue`)

### Why clone instead of create

`customfield_24305` (**Affected item**) is a Riada **Insight/Assets** field
(`com.riadalabs.jira.plugins.insight:rlabs-customfield-default-object`) holding a Provider
Service object (`LCJ-37462`). That object type is **outside the field's REST key-resolver
scope**, so no REST write shape can set it:

- `{ "key": "LCJ-37462" }` → *"Could not find Assets object/s (LCJ-37462)"*
- `{ "id": … }` / `["LCJ-37462"]` → silently ignored → field stays empty → *"Affected item is required"*

The field is **required to pass `Start implementation`**, so a from-scratch `POST /issue`
can never produce a usable ticket. A **server-side clone copies the Assets value intact**
(verified), so the playbook clones the template `OPSLSY-75376` rather than building the
issue. Cloning also carries every other change field for free — no field whitelist, no
per-field ids to maintain. Computed/scripted template fields (time-in-status, SLA,
"Resolved by", rank, last-comment, the `customfield_18422` `<script>` "Label" hack, …) are
left as the clone produced them.

### Runtime values (computed once at run start)

`Capture_Run_Start` (Compose `@utcNow()`) pins a single instant; `Compute_Run_Times`
derives the rest so start/end are consistent. Timestamps are built with `concat` (not a
`formatDateTime` mask) to avoid the literal-`T`/`+0000` escaping trap:

| Value | Expression | Example |
|---|---|---|
| `dateStamp` | `formatDateTime(start,'yyyy.MM.dd')` (for the summary) | `2026.06.12` |
| `fileStamp` | `convertTimeZone(start,'UTC','Central European Standard Time','yyyyMMdd')` (for the attachment name) | `20260612` |
| `plannedStart` | `concat(... addMinutes(start,20) ...)` → full ISO, **start +20 min** | `2026-06-12T09:50:00.000+0000` |
| `plannedEnd` | same over `addMinutes(start,25)` → full ISO, **finish +25 min** | `2026-06-12T09:55:00.000+0000` |
| `displayStart` | `convertTimeZone(addMinutes(start,20),'UTC','Central European Standard Time','yyyy-MM-dd HH:mm')` | `2026-06-12 11:50` |
| `displayFinish` | `convertTimeZone(addMinutes(start,25),'UTC','Central European Standard Time','yyyy-MM-dd HH:mm')` | `2026-06-12 11:55` |
| `summary` | `Block malicious/suspicious IPs reported by Microsoft Sentinel Threat Intelligence - {dateStamp}` | |

The `+0000` offset is sent literally as Jira expects; `utcNow()` is UTC.

> **All time fields share one source — run start + 20 min (start) / + 25 min (finish).**
> `Compute_Run_Times` produces the start time in two forms: full ISO `+0000`
> (`plannedStart`/`plannedEnd`, for the Jira datetime fields) and a human-readable string
> (`displayStart`/`displayFinish`, for the description). The Jira datetime fields are stored
> as the UTC instant but **rendered in the instance's local zone** (Budapest, CET/CEST), so
> the description strings are also converted to `Central European Standard Time` via
> `convertTimeZone` (auto-DST: +2 in summer, +1 in winter). That way the description
> *Accurate start/finish* read **the same wall-clock time** Jira shows for Planned start/end
> (`customfield_22500`/`22501`, set on the Override PUT **and** re-affirmed on the
> Implementation transition) and Actual start/finish (`customfield_23600`/`23601`, on the
> PIR transition) — earlier they disagreed by the +2 h UTC↔CEST offset. The **+20 min**
> offset is the safety margin: the *Start implementation* validator rejects a past Planned
> start, and +20 from run start stays comfortably in the future by the time the walk reaches
> that hop (which is only a few minutes in). No
> per-hop recomputation and no `Planned_*` variables — one base instant, used everywhere,
> so planned, actual, and the human-readable description never disagree.

### Clone mechanism (headless, confirmed working)

1. **Resolve the template's numeric id** (env-portable): `Resolve_Template_Id` →
   `GET /rest/api/2/issue/{TemplateIssueKey}?fields=id` → `Parse_Template_Id` → `{id}`.
2. **Fire the clone via the servlet** (not REST): `Clone_OPSLSY_Change` →
   `POST {JIRAHOST}/secure/CloneIssueDetails.jspa` with the Logic App's **Basic auth** +
   `X-Atlassian-Token: no-check` (bypasses XSRF — no `atl_token` needed) +
   `Content-Type: application/x-www-form-urlencoded`, body
   `id={id}&summary={url-encoded summary}&cloneAttachments=false&cloneSubTasks=false&cloneLinks=false`.
   The clone is **async**; the response is a **`302` redirect** to `CloneIssueProgress.jspa?taskId=…`
   (which does **not** expose the new key — it is not scraped).
   - **The `302` is the success signal.** The Logic App HTTP action treats only `2xx` as
     success, so on `302` it reports the action **Failed** even though the clone committed.
     `Check_Clone_Status` therefore runs after the clone on **both `Succeeded` and `Failed`**
     and gates on the status code — `@less(coalesce(outputs('Clone_OPSLSY_Change').statusCode, 599), 400)`
     (i.e. any `2xx`/`3xx` is success; `4xx`/`5xx`/no-response terminates the run with
     `CloneFailed`). The continuation (`Find_Clone_Key`) runs after `Check_Clone_Status`,
     so a genuine clone error stops the run while the normal `302` flows straight through.
3. **Find the new key by search** (poll — the clone indexes a few seconds after the async
   commit): `Find_Clone_Key` is an `Until` that polls
   `GET /rest/api/2/search` with
   `jql = project = OPSLSY AND issuetype = "Technical change" AND reporter = {JIRAUserName} AND created >= -10m ORDER BY created DESC`,
   `maxResults=1`, `fields=key,created,summary`. The reporter is the `sentinelsvc` service
   account and one run creates exactly one clone, so this is reliable — unlike a
   `summary ~ "<marker>"` text match, which Jira tokenises unreliably and which suffers
   index lag. `Set_Clone_Key` runs at the **top level of the loop body** (after `Parse_Search`)
   and assigns `Clone_Key = coalesce(issues[0].key, '')` **every iteration** — the found key,
   or `''` when the poll was empty. This is deliberate: an earlier version nested the
   assignment inside an `If` (`Set_Clone_Key_If_Found`), and Logic Apps does **not** reliably
   surface a variable mutated inside a nested scope to the enclosing `Until` exit-condition
   evaluation, so the loop kept spinning to its hard limit (~11 min) even though the
   SetVariable had run with the correct value. Setting it at the loop's own scope makes the
   exit condition see it. The `Until` exit condition is pure key-presence —
   `@not(empty(variables('Clone_Key')))` — and the loop delays 10 s, caps at **18 attempts /
   PT4M**, then `Verify_Clone_Found` terminates the run with `CloneNotFound` if `Clone_Key`
   is still empty. All downstream steps reference `variables('Clone_Key')` (unchanged name).

   > `Search_For_Clone` is set to **`retryPolicy: none`**. With the default policy a single
   > slow or gateway-`307`'d search retries 4× with back-off (~2 min/try, ~10 min total),
   > which both wastes the run and makes the `Until` sail far past its `PT4M` cap (observed:
   > one iteration burning ~11 min). One-shot attempts keep each poll fast and bounded, so
   > the loop budget is the real ceiling. (The affinity `Cookie` header — see above — is what
   > stops the search `307`-ing in the first place; `retryPolicy: none` is the belt-and-braces
   > guard for a slow or transiently-failing attempt.)

   > There is **no** `created >= run start` guard in the exit condition. An earlier version
   > compared Jira's `created` against the run start time, but Jira DC returns `created` in
   > server-local time with an offset (`…+0200`) while `utcNow()` is `…Z`; that comparison
   > was both error-prone and redundant (the `created >= -10m` JQL already scopes the search),
   > and it kept the loop from ever exiting. It was removed.

### Override on the clone (PUT, while still Open)

The clone copies the template's old body/dates, so `Override_Clone_Fields`
(`PUT /rest/api/2/issue/{Clone_Key}`) overrides the `description` (body below, with the
Accurate start/finish lines from `displayStart`/`displayFinish`) and sets
`customfield_22500`/`22501` (Planned start/end) from `plannedStart`/`plannedEnd`
(run start +20/+25). The Implementation transition re-sends the **same** `plannedStart`/
`plannedEnd` (to satisfy the *Start implementation* non-past validator at transition time),
so the value is identical in both places. The **summary** is already correct from the
clone. Everything else — Category, Type, Reason, Impact, Risk, Owner, Change manager,
Change tested, Rollback, Validation, **Affected item** — is inherited from the template and
left untouched.

### Description body

```
*GOAL:* Block suspicious/malicious IPs maked by Microsoft Sentinel Threat Intelligence
*Root-cause:* Several Sentinel alert created indicating there are communication with these IPs.
*Time frame:* in optimal case approximately 5 minutes
*Accurate start time:* {displayStart}
*Accurate finish time:* {displayFinish}
*Affected Service:* Palo Alto Fws
*Impact:* Not expected.
*Tested:* OPSLSY-37786
*Communicate and contact:* LSYH, BUD NETOPS and LSYH, BUD SECOPS
*Rollback:* Remove IP(s) that cause problem from External dynamic deny rule named - Sentinel_Threat_Intelligence_IPs

Blocked IPs can be found in the attachment.
```

(The `Time frame` line was changed 30 → 5 minutes to match the planned window.)

### Approval sub-task (required before Implementation)

The *Start implementation* transition has a validator that rejects the move unless the
issue **has at least one sub-task** (`"Transition is allowed only if the issue has sub-task"`).
`Create_Approval_Subtask` runs after `Override_Clone_Fields` and before `Walk_to_Planning`.

`Create_Approval_Subtask` (`POST /rest/api/2/issue`) creates the sub-task on the clone:

| field | value |
| --- | --- |
| `project.key` | `{JiraProjectKey}` |
| `parent.key` | `{Clone_Key}` |
| `issuetype.name` | `{SubtaskIssueTypeName}` (default `Approval sub-task`) |
| `summary` | `Manual review of the automation workflow` |
| `assignee.name` | `{SubtaskAssigneeName}` — the Jira **login**, default `secops` |
| `description` | `Manually check the playbook {Clone_Key} runtime results.` (embeds the OPSLSY change key) |

Jira REST sets `assignee` by login `name`, **not** by display name or email, so
`SubtaskAssigneeName` must be the login (`secops` for "LSYH, BUD SECOPS"; the email
`lsyh.secops@lhsystems.com` is **not** accepted). We assign it **directly** — an earlier
version looked the login up at runtime via `user/assignable/search?username=`, but the
server-side filter makes Jira DC run a directory (LDAP) search that exceeds the Logic Apps
**fixed 120 s HTTP timeout** (it can't be raised on Consumption), so the action always timed
out. Using the literal login removes the lookup entirely. If the create fails (wrong login,
missing sub-task type), `Walk_to_Planning` won't run and the whole run fails — by design, so
the problem surfaces immediately. Reporter defaults to `sentinelsvc`; security level is
inherited from the parent.

---

## The walk (name-driven, id-agnostic)

Each step re-probes `GET /issue/{key}/transitions?expand=transitions.fields` and picks
the transition whose `to.name` (case-insensitive substring) matches the next desired
status, **skipping** any transition whose `name` contains `revoke / withdraw / re-plan
/ reject / cancel / update cmdb`. Driving by **target status name** rather than
hardcoded ids survives test↔prod id drift.

After each POST the playbook **polls** `GET /issue/{key}?fields=status` in an `Until`
(10 s delay, cap 60×/PT10M) until the status lands, rather than trusting the POST
response — heavy Trackspace transitions often drop the connection but still commit, so
each `Wait_Until_*_Landed` runs even when its POST is reported `Failed`/`TimedOut`.

Every step is **hardened against silent failure** (so a stuck transition fails the run
loudly instead of limping on and POSTing an empty id):

- **Empty-filter guard** (`Guard_Transition_*`): if the name filter returns no transition,
  the step fetches `?fields=status` and `Terminate`s the run with code `TransitionNotFound`
  and a message naming the target and the ticket's current status. An empty
  `transition.id` is never POSTed.
- **Landed confirmation** (`Confirm_*_Landed`): after the poll, a fresh `GET ?fields=status`
  is evaluated; if the ticket is **not** in the target status the run `Terminate`s with
  `TransitionDidNotLand` (current status + the transition POST's status code). Because the
  poll tolerates a dropped POST, "POST errored but the status landed" still counts as
  success.

Discovered ids on the test env (reference only — not hardcoded): Open→Planning `11`,
Planning→Implementation `171`, Implementation→Post implementation review `91`, Post
implementation review→Closed `111`. Standard Change skips the approval stages.

### Per-transition payloads

| Walk step | target status | POST body fields |
|---|---|---|
| 1. Planning | `Planning` | *(none — just `transition.id`)* |
| 2. Implementation | `Implementation` | `customfield_22500 = plannedStart`, `customfield_22501 = plannedEnd` (run start +20/+25) — re-sent on the transition so the *Start implementation* validator sees a non-past Planned start. The +20 min offset keeps it in the future even after the few minutes the walk takes to reach this hop. |
| 3. Post implementation review | `Post implementation review` | `resolution = { "name": "Successful" }`, `customfield_23600 = plannedStart`, `customfield_23601 = plannedEnd` (Actual start/finish = the **same** +20/+25 values; only settable on this transition screen) |
| 4. Closed | `Closed` | `resolution = { "name": "Successful" }` |

The close poll stops when the status name contains `Closed` **or** its
`statusCategory.key` is `done`.

---

## The implementation work (healthy path: ticket in Implementation)

The blocklist write is **ungated**. The AbuseIPDB health check forks the run: a healthy
check proceeds to Implementation + blocking, an outage diverts to manual intervention and
blocks nothing:

- **Healthy AbuseIPDB** (`AbuseIPDB_health_check` against `8.8.8.8` succeeds) → walk to
  Implementation, then `Enrichment_Scope`: per-IP `/check` (50-way Foreach), keep rows with
  `totalReports >= MinReports` whose ISP is not in `ExcludedISPs` (lower-case
  substring match), then set `Block_IPs` = kept IP list and `CSV_Rows` = the rich kept
  rows.
- **AbuseIPDB down** (`AbuseIPDB_health_check` Failed/TimedOut/Skipped) →
  `Fallback_Manual_Intervention`: the change is **never advanced to Implementation** and
  **nothing is blocked** — the raw, un-enriched IPs bypass the threshold/ISP filtering and
  could include addresses that must not be blocked. The scope attaches a CSV of **all**
  incident IPs (`Select_Fallback_Rows` → `Build_Fallback_CSV` → `Attach_Fallback_CSV`),
  posts a "manual intervention required" comment (`Comment_Manual_Intervention`), assigns
  the change to SecOps (`Assign_To_SecOps`, `PUT /assignee` = `SubtaskAssigneeName`), and
  leaves it in **Planning**. `Terminate_Manual_Intervention` ends the run `Succeeded`.
  `Write_Blocklist_Blob`, `Build_CSV`, and the Implementation/PIR/Closed walks are Skipped
  on this path.
- **Blocklist blob write is ungated** (`Write_Blocklist_Blob`): GET
  `$web/index.html`, line-level dedupe `Block_IPs` against existing content, and if
  anything is new, PUT the appended blob (managed identity, `text/html`). This is the
  actual change being implemented and happens regardless of approval (there is none).
- **CSV** (`Build_CSV`, Table/CSV from `CSV_Rows`) is attached to the change via
  `POST /issue/{key}/attachments` with `X-Atlassian-Token: no-check` and multipart
  `file=` — the same artifact the old flow built.

There is no longer an "empty result → terminate" branch: even with zero kept IPs the
change is attached-to and walked to Closed so it never stalls.

---

## Source incident lifecycle

The playbook is launched by an automation rule on a **relay** incident (whose
`relatedEntities` drive the IP extraction). It additionally owns two *source* incidents:

- **Incident A** — title starts with `IncidentTitleIoCPrefix` ("A network session Source address") and ends with `IncidentTitleIoCSuffix` ("matched an IoC."); the middle segment is the offending IP.
- **Incident B** — title equals `IncidentTitleMap` ("#TI Map IP Entity to CommonSecurityLog").

**Find (first action, before `Entities - Get IPs`).** `List_Sentinel_Incidents`
(`GET https://management.azure.com{LogAnalyticsResourceID}/providers/Microsoft.SecurityInsights/incidents?api-version={IncidentApiVersion}&$filter=(properties/status ne 'Closed')&$orderby=properties/createdTimeUtc desc`,
managed identity) lists open incidents; `Filter_Target_Incidents` keeps the two by title;
`Set_Incident_Arm_Ids` stores their ARM ids in the `Incident_Arm_Ids` variable. If neither is
present the array is empty and every incident step below is a graceful no-op —
`Entities - Get IPs` runs after this scope on `Succeeded`/`Failed`/`Skipped`, so a Sentinel
hiccup never blocks the blocking mission.

**Activate (still first).** `Activate_Incidents` (Foreach) → `Update_Incident_Active`
(azuresentinel `PUT /Incidents`, body `{incidentArmId:"https://management.azure.com{id}", status:"Active"}`).

**Close (last, success path only).** After `Walk_to_Closed`, `Close_Source_Incidents`
(Foreach over the stored ids) → `Update_Incident_Closed` (`PUT /Incidents`, `status: Closed`,
`classification.ClassificationAndReason = {IncidentClassificationAndReason}` (default
`TruePositive - SuspiciousActivity`), `ClassificationReasonText = "Automatically handled in {Clone_Key}"`).

**Fallback (AbuseIPDB down).** The incidents stay **Active**; `Comment_Source_Incidents`
(Foreach) → `Comment_Incident` (azuresentinel `POST /Incidents/Comment`) posts a
manual-intervention note referencing `{Clone_Key}`, then `Terminate_Manual_Intervention` ends
the run `Succeeded`.

The pattern (MI mgmt-REST find + azuresentinel `PUT /Incidents` / `POST /Incidents/Comment`)
mirrors the org's `trackspacejira_ticket_close.json`. The MI's *Microsoft Sentinel Responder*
role covers list/read/update/comment — no new RBAC. The **relay** incident is never modified.

---

## Parameters

Tunable workflow parameters (portal-editable without redeploy; ARM defaults in
`azuredeploy.json`):

| Parameter | Default |
|---|---|
| `JiraProjectKey` | `OPSLSY` (used in the find-clone-by-search JQL) |
| `TemplateIssueKey` | `OPSLSY-75376` (the change cloned each run) |
| `SubtaskIssueTypeName` | `Approval sub-task` (the required pre-Implementation sub-task) |
| `SubtaskAssigneeName` | `secops` (Jira **login** the approval sub-task is assigned to — not the email/display name) |
| `StatusPlanningName` | `Planning` |
| `StatusImplementationName` | `Implementation` |
| `StatusPostImplReviewName` | `Post implementation review` |
| `JiraClosedStatusName` | `Closed` |
| `MinReports` | `100` |
| `ExcludedISPs` | `["akamai technologies","google","palo alto networks","the shadowserver foundation","censys"]` |
| `StorageAccountName` / `BlocklistContainer` / `BlocklistBlobPath` | `lsyweuritcsprdmspalo001` / `$web` / `index.html` |
| `JIRAHOST` | `https://trackspace.lhsystems.com` (production; INT is `https://int-trackspace.lhsystems.com`) |
| `LogAnalyticsResourceID` | `…/resourcegroups/lsy_weur_itcs_prd_oms_rg_001/…/workspaces/lsy-prd-oms` (Sentinel workspace whose source incidents are managed) |
| `IncidentApiVersion` | `2023-07-01-preview` |
| `IncidentTitleIoCPrefix` / `IncidentTitleIoCSuffix` | `A network session Source address` / `matched an IoC.` |
| `IncidentTitleMap` | `#TI Map IP Entity to CommonSecurityLog` |
| `IncidentClassificationAndReason` | `TruePositive - SuspiciousActivity` |

---

## Deploy

The ARM deploy **must pass `PlaybookName=TI-handler` explicitly** (the
`azuredeploy.parameters.json` value), otherwise the stale template name
`Sentinel-IPAbuse-TriageAndBlock` would stand up a *parallel* Logic App with a fresh
managed identity instead of updating this one.

```bash
RG=LSY_WEUR_ITCS_PRD_SEC_RG_002
az deployment group create \
  --resource-group "$RG" \
  --template-file playbook/azuredeploy.json \
  --parameters @playbook/azuredeploy.parameters.json
```

Managed-identity RBAC (unchanged roles): **Microsoft Sentinel Responder** on the workspace
(now exercised for both reading incident entities **and** listing/updating the source
incidents' status/classification + posting comments — Responder already grants incident
write), Key Vault Secrets User on the Key Vault, Storage Blob Data Contributor on the
blocklist storage account. KV/Sentinel/AbuseIPDB connection wiring is unchanged. The MI must
have Responder on the `LogAnalyticsResourceID` workspace (default `lsy-prd-oms`).

Logic App runs are immutable: after a redeploy, cancel any stuck in-flight runs and
fire fresh ones — do not expect a redeploy to mutate a run already in progress.

### Sync / acceptance

- `jq -S` of `.definition.actions` and `.definition.triggers` matches between
  `workflow.json` and the `azuredeploy.json` definition. The remaining `jq -S` diff
  between the two files is only the parameter `defaultValue`s (literals in
  `workflow.json` vs `[parameters('…')]` in ARM) — benign and expected.
- A test run creates one OPSLSY Technical change, advances it to **Implementation at
  run start**, runs enrichment + the blob write, attaches the CSV, then walks it to
  **Closed** with resolution **Successful** — no CLOPSSEC artifacts, no Sentinel
  incident comments. On an AbuseIPDB outage the same change still reaches Closed with
  the raw-IP CSV attached.
