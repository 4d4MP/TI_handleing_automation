# Runbook — TI-handler playbook

The playbook is **fully autonomous**: there is nothing for an analyst to approve. On
each Sentinel incident it raises one OPSLSY Technical change, blocks the qualifying
IPs, attaches the CSV, and closes the change. This runbook covers verifying a run and
rolling back a block.

## What happens on a run

1. An OPSLSY *Technical change* (clone of `OPSLSY-75376`) is created and walked to
   **Implementation** at run start.
2. The incident IPs are enriched against AbuseIPDB; those with `totalReports ≥
   MinReports` and a non-excluded ISP are appended to
   `lsyweuritcsprdmspalo001/$web/index.html` (line-level deduped). If AbuseIPDB is
   down, the **raw** incident IPs are used instead.
3. The CSV of blocked IPs is attached to the change.
4. The change is walked to **Closed** with resolution **Successful**.

**No comments are posted to the Sentinel incident.** To see what a run did, open the
OPSLSY change (description, attachment, history) and/or inspect the blocklist blob.

## Finding the change for an incident

The change summary is `[TEST] - Block malicious/suspicious IPs reported by Microsoft
Sentinel Threat Intelligence - {yyyy.MM.dd}`. The Logic App run history for `TI-handler`
shows the cloned issue key in the `Find_Clone_Key` step (the `Clone_Key` variable). Open
it in Trackspace:

```
https://trackspace.lhsystems.com/browse/OPSLSY-<n>
```

The attachment `sentinel_blocked_ips_<incident-number>.csv` lists the IPs that were
pushed to the blocklist (enriched rows on the normal path, plain IPs on the AbuseIPDB
fallback path).

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
| `AbuseIPDB_health_check` Failed/TimedOut | AbuseIPDB down or OMS connection auth expired | The run **does not abort** — it falls back to the raw incident IPs and still blocks + closes the change. If the connection auth expired, contact OMS to re-authorise the `abuseipdbapi` connector in `LSY_WEUR_ITCS_PRD_OMS_RG_001`. |
| `Resolve_Template_Id` / `Clone_OPSLSY_Change` 401 | Trackspace password rotated | Update the `sentinelsvc` secret in KV. |
| `Clone_OPSLSY_Change` fails / `Find_Clone_Key` times out (`CloneNotFound`) | Template key wrong, clone servlet path/auth changed, or the clone didn't index within PT2M | Confirm `TemplateIssueKey=OPSLSY-75376` resolves, that `/secure/CloneIssueDetails.jspa` accepts Basic + `X-Atlassian-Token: no-check`, and that the lookup JQL (`project=OPSLSY AND issuetype="Technical change" AND reporter=sentinelsvc AND created >= -10m`) returns the clone. The loop exits on key presence (`@not(empty(variables('Clone_Key')))`), so a real timeout means the search never returned the clone within PT2M. |
| Run fails `TransitionNotFound` | No transition to the target status was offered from the ticket's current status (board/workflow changed, or a prior hop didn't land) | The error message names the target and the current status. Check the change's available transitions for that status. |
| Run fails `TransitionDidNotLand` | The transition POST didn't move the ticket within the poll window (validator rejected it, or it genuinely failed) | The message includes the current status and the POST status code. Common cause was *"Planned start cannot be a past date"* on Start implementation — now avoided by setting Planned start to `utcNow()+20m` at the Implementation hop. |
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
