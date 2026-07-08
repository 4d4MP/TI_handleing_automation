# Runbook — TI-handler playbook

The playbook is **fully autonomous**: there is nothing for an analyst to approve. On
each Sentinel incident it raises one OPSLSY Technical change, blocks the qualifying
IPs, attaches the CSV, and closes the change. This runbook covers verifying a run and
rolling back a block.

## What happens on a run

0. **First, before anything else:** the two source Sentinel incidents are found by title
   (Incident A "A network session Source address … matched an IoC."; Incident B
   "#TI Map IP Entity to CommonSecurityLog") and moved to **Active**. If they aren't present,
   the run continues normally (they are optional).
1. A **run-record sub-task** (type `Operation sub-task`, priority `4 - Normal`, summary "Automatic response", assigned to `sentinelsvc`) is created on the
   change, then an OPSLSY *Technical change* (clone of `OPSLSY-75376`) is created and walked
   to **Planning**.
2. AbuseIPDB is health-checked. **If it is down, nothing is blocked** — see *AbuseIPDB
   down* below. Otherwise the change is walked to **Implementation** and the run continues.
3. The incident IPs are enriched against AbuseIPDB; those with `totalReports ≥
   MinReports` and a non-excluded ISP are appended to
   `lsyweuritcsprdmspalo001/$web/index.html` (line-level deduped).
4. The CSV of blocked IPs is attached to the change; the change is walked to
   **Post-implementation review**.
5. **On success the run STOPS at Post-implementation review:** the change is assigned to
   **SecOps** (`MainTicketAssigneeName`), the run-record sub-task is moved to **Resolved**,
   and the relay incident **and** the two source incidents are moved to **Closed / TruePositive** (comment
   `Automatically handled in <OPSLSY change key>`). The change is **left in Post-implementation
   review** for a human to review and close — the automation does **not** close it.
6. **On any failure** after the sub-task is created, the run-record sub-task is moved to
   **On Hold** and the run ends **Failed**.

### AbuseIPDB down (manual-intervention fallback)

When the health check fails the run does **not** block anything (the raw, un-enriched IPs
could include addresses that must never be blocked). Instead it attaches a CSV of **all**
incident IPs, posts a comment that AbuseIPDB failed and manual intervention is required,
assigns the change to **SecOps** (`MainTicketAssigneeName`), and **leaves it in Planning**. The
blocklist blob is untouched, the run-record sub-task is moved to **On Hold**, and the Logic
App run still ends **Succeeded**. A SecOps engineer must review the attached IPs and apply/close
the change by hand. On this path the relay and the two source Sentinel incidents are **left Active** and a
comment is posted on each noting AbuseIPDB was unavailable, nothing was blocked, and manual
intervention is required (referencing the OPSLSY change key) — they are **not** auto-closed.

The playbook drives the relay (trigger) incident **and** the two source Sentinel incidents'
lifecycle (Active at start; Closed / TruePositive on success, or a manual-intervention comment
on the fallback). To see what a run did, open the OPSLSY change (description, attachment,
history), those incidents, and/or the blocklist blob.

## Finding the change for an incident

The change summary is `Block malicious/suspicious IPs reported by Microsoft
Sentinel Threat Intelligence - {yyyy.MM.dd}`. The Logic App run history for `TI-handler`
shows the cloned issue key in the `Find_Clone_Key` step (the `Clone_Key` variable). Open
it in Trackspace:

```
https://trackspace.lhsystems.com/browse/OPSLSY-<n>
```
(Production — the current `JIRAHOST`; use `https://int-trackspace.lhsystems.com` for the INT environment.)

The attachment `RESULT_Check_MS_threat_Intelligence_IPs_against_AbuseIPDB-YYYYMMDD.csv` (date
in the Budapest zone, no separators) lists the IPs that were
pushed to the blocklist (enriched rows). On the AbuseIPDB-down fallback the same-named
attachment instead lists **all** incident IPs for manual review, and nothing was blocked.

## Verifying the blocklist

```bash
az storage blob download \
  --account-name lsyweuritcsprdmspalo001 \
  --container-name '$web' \
  --name index.html \
  --auth-mode login \
  --file /tmp/blocklist.html
grep -c '^[0-9]' /tmp/blocklist.html      # count IP-ish lines
grep '<the-ip>' /tmp/blocklist.html
```

The blob write is **idempotent**: IPs already present are skipped, so the appended
count can be smaller than the IP count in the CSV — that is expected, not an error.

## Rolling back a block

The playbook only appends; it never removes. To unblock an IP:

1. Pull the blob locally (see above).
2. Remove the offending line(s).
3. Upload back:
   ```bash
   az storage blob upload \
     --account-name lsyweuritcsprdmspalo001 \
     --container-name '$web' \
     --name index.html \
     --auth-mode login \
     --content-type text/html \
     --file /tmp/blocklist.html \
     --overwrite
   ```

This matches the change's documented rollback: *Remove IP(s) that cause problem from
the External dynamic deny rule named `Sentinel_Threat_Intelligence_IPs`.*

## Re-running the playbook

1. In the Sentinel incident, click **Actions → Run playbook**.
2. Select `TI-handler`.
3. Note: each re-run creates a **fresh OPSLSY change** and walks it to Closed. The
   blob dedupe makes re-runs safe — already-present IPs are skipped.

After an ARM redeploy, Logic App runs in flight are immutable: cancel any stuck runs
and fire fresh ones rather than expecting the redeploy to affect them.

## Reconciling concurrent runs

The blob update is read-modify-write without a lease or `If-Match`. If two runs hit
`Update_blob` within a few seconds, the later writer can overwrite the earlier one and
drop its IPs.

Symptoms: two changes closed at nearly the same time, but a `grep` against
`$web/index.html` only shows the second run's IPs.

Recovery: re-run the playbook on each affected incident — the line-level dedupe makes
re-runs idempotent. To avoid it entirely, switch `Update_blob` to use the `ETag` from
`Get_blob_content` as an `If-Match` header wrapped in an Until-retry on 412.

## On-call triage cheatsheet

| Symptom | Likely cause | Fix |
|---|---|---|
| `AbuseIPDB_health_check` Failed/TimedOut | AbuseIPDB down or OMS connection auth expired | The run **does not abort and blocks nothing** — it attaches a CSV of all incident IPs, comments "manual intervention required", assigns the change to SecOps, leaves it in **Planning**, and ends Succeeded. A SecOps engineer must review and apply/close by hand. If the connection auth expired, contact OMS to re-authorise the `abuseipdbapi` connector in `LSY_WEUR_ITCS_PRD_OMS_RG_001`. |
| `Resolve_Template_Id` / `Clone_OPSLSY_Change` 401 | Trackspace password rotated | Update the `sentinelsvc` secret in KV. |
| Jira calls return `307` (loop) | Gateway session-affinity cookie not applied | `Prime_Affinity_Cookie` failed to capture `Set-Cookie`, so `Affinity_Cookie` is empty. Check the primer's response headers; confirm the gateway still uses `ApplicationGatewayAffinity` cookies and the `Build_Cookie_Parts` split still matches their `Set-Cookie` shape. |
| `Clone_OPSLSY_Change` fails / `Find_Clone_Key` times out (`CloneNotFound`) | Template key wrong, clone servlet path/auth changed, or the clone didn't index within PT4M | Confirm `TemplateIssueKey=OPSLSY-75376` resolves, that `/secure/CloneIssueDetails.jspa` accepts Basic + `X-Atlassian-Token: no-check`, and that the lookup JQL (`project=OPSLSY AND issuetype="Technical change" AND reporter=sentinelsvc AND created >= -10m`) returns the clone. The loop exits on key presence (`@not(empty(variables('Clone_Key')))`), so a real timeout means the search never returned the clone within PT4M. |
| `Find_Clone_Key` runs for many minutes (well past its cap) | `Search_For_Clone` was retrying a slow/`307` response on the default policy (4× back-off ≈ 10 min) | Already mitigated: the search uses `retryPolicy: none` so each poll is one-shot. If it recurs, the gateway affinity `Cookie` is likely empty (see the `307`-loop row) — fix the priming so the search returns `200` fast. |
| `Find_Clone_Key` loops to its limit (~11 min) even though `Set_Clone_Key` shows the correct value | `Set_Clone_Key` was nested inside an `If` (`Set_Clone_Key_If_Found`); Logic Apps doesn't reliably surface a variable mutated in a nested scope to the enclosing `Until` exit check, so the loop never saw the value | Fixed: `Set_Clone_Key` now runs at the **top level of the loop body** (after `Parse_Search`), assigning `coalesce(issues[0].key, '')` every iteration, so `@not(empty(variables('Clone_Key')))` trips on the first poll that finds the clone. Runs are immutable — redeploy, cancel any stuck run, start a fresh one. |
| Implementation transition fails: `"Transition is allowed only if the issue has sub-task"` | The *Start implementation* validator requires a sub-task and none exists | Handled by `Create_Run_Subtask` (runs before `Run_Change`). If it recurs, check `Create_Run_Subtask` succeeded — most often `SubtaskIssueTypeName` isn't a valid sub-task type in the project, or `SubtaskAssigneeName` isn't a real login. |
| `Create_Run_Subtask` fails: `assignee: User '…' does not exist` | `SubtaskAssigneeName` isn't a valid Jira login | Jira sets `assignee` by login `name`, not email/display name. Set `SubtaskAssigneeName` to the login (e.g. `sentinelsvc`, found at `/secure/ViewProfile.jspa?name=sentinelsvc`), not an email. |
| Run-record sub-task never moves to Resolved/On Hold | The Operation sub-task workflow has no transition whose **name** or target status matches `SubtaskSuccessStatusName` / `SubtaskFailureStatusName` from its current state | The step is best-effort (a missing transition is a silent no-op — it never fails the run). Confirm the Operation sub-task workflow reaches `Resolved` (success) / `On Hold` (failure) directly from `Open` (or set the params to the actual names). |
| Sub-task stays **Open** on a **successful** run; `Approve_Subtask_Post` returns `400 BadRequest` (`errors.resolution = "The selected resolution cannot be chosen during this action."`, and/or required `customfield_22500`/`22501`) | The `Resolve issue` transition screen has **three mandatory fields** — Resolution, Planned start (`customfield_22500`), Planned end (`customfield_22501`) — that a bare transition POST doesn't supply | **Resolved:** the success POST now sends all three, built from the transition metadata (`expand=transitions.fields`): a resolution from `fields.resolution.allowedValues` (preferring `SubtaskSuccessResolutionName`, default `Successful`, else the first allowed value) plus Planned start/end set to `utcNow()` / +30 — each field is included **only if it's on that transition's screen**. If it recurs: `Successful` may not be offered → set `SubtaskSuccessResolutionName` to a valid one (e.g. `Done`); or the sub-task's Planned dates use different custom-field ids than `customfield_22500`/`22501` → check the `Resolve issue` transition's field metadata and adjust `Approve_Subtask_Planned_Fields`. |
| Run reports Succeeded but nothing was blocked | AbuseIPDB-down fallback (sub-task On Hold), OR the change didn't reach Implementation | Open the run-record sub-task (On Hold = fallback/failure) and the change status. On the fallback path the run intentionally ends Succeeded. |
| `Find_Assignee_Account` (older versions) times out (~2 min) | A runtime `user/assignable/search?username=` lookup made Jira DC run a directory (LDAP) search exceeding the Logic Apps **fixed 120 s HTTP timeout** (not raisable on Consumption) | Removed: the assignee is now set directly from the `SubtaskAssigneeName` login, so there is no lookup to time out. |
| Run fails `TransitionNotFound` | No transition to the target status was offered from the ticket's current status (board/workflow changed, or a prior hop didn't land) | The error message names the target and the current status. Check the change's available transitions for that status. |
| Run fails `TransitionDidNotLand` on Implementation with *"Planned start cannot be a past date"* | Planned start was in a past minute when the transition validated it | **Resolved:** Planned start/end (`customfield_22500`/`22501`) are now computed **fresh with `utcNow()` / +30 on the Implementation Post**, so Planned start is always the current minute. If it ever still trips at a sub-minute boundary, change the Post's `customfield_22500` to `addMinutes(utcNow(),1)`. (Actual start/finish and the description remain the real run-start time.) |
| `Get_blob_content` 403 | Managed identity missing `Storage Blob Data Contributor` | Grant the role on the storage account. |
| `Update_blob` 409 | Concurrent modification by another writer | Re-run the playbook; the dedupe skips already-present IPs. |

## Tuning

The Logic App's parameters can be edited in the Azure portal (`Logic app → Edit → ⚙
Parameters`) without redeploying ARM:

| Parameter | Default | Notes |
|---|---|---|
| `MinReports` | `100` | Lower to be more aggressive, raise to be more conservative. |
| `ExcludedISPs` | `["akamai technologies", "google", "palo alto networks", "the shadowserver foundation", "censys"]` | Lower-case, matched as a **substring** of `toLower(isp)`. |
| `StatusPlanningName` / `StatusImplementationName` / `StatusPostImplReviewName` / `JiraClosedStatusName` | `Planning` / `Implementation` / `Post implementation review` / `Closed` | Walk target status names, matched case-insensitively as a substring of a transition's target status. |
| `TemplateIssueKey` | `OPSLSY-75376` | The Technical change cloned each run. Carries the Insight/Assets Affected item and all other change fields. |
| `SubtaskIssueTypeName` | `Operation sub-task` | Issue type of the run-record sub-task created on the clone before any technical change (also satisfies the *Start implementation* "has sub-task" validator). |
| `SubtaskPriorityName` | `4 - Normal` | Jira priority (by name) set on the run-record sub-task (`priority.name` on `Create_Run_Subtask`). Must be a priority available on that issue type's create screen. |
| `SubtaskAssigneeName` | `sentinelsvc` | Jira **login** (username) the run-record sub-task is assigned to (the Sentinel service account) — **not** the email or display name. Used directly as `assignee.name` on `Create_Run_Subtask`; an invalid login fails the create and stops the run. |
| `SubtaskSuccessStatusName` / `SubtaskFailureStatusName` | `Resolved` / `On Hold` | Target status/transition the run-record sub-task moves to on success / on failure-or-fallback (matched against transition **name** OR target status `to.name`, case-insensitive substring). |
| `SubtaskSuccessResolutionName` | `Successful` | Resolution set on the sub-task's success (`Resolved`) transition. Matched case-insensitively against that transition's allowed resolutions (`fields.resolution.allowedValues`); if not offered, the **first allowed value** is used, so the id sent is always valid. Sent only when the transition exposes a resolution field — otherwise the POST stays bare. Set this if the `Resolve issue` transition needs a specific resolution (e.g. `Done`). |
| `MainTicketAssigneeName` | `secops` | Jira **login** the main OPSLSY change is assigned to (SecOps) at Post-implementation review (success path) and on the AbuseIPDB-down fallback. |
