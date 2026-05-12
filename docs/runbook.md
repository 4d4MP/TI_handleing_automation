# Runbook — Sentinel IP-Abuse Triage & Block Playbook

## What an analyst sees

When a Sentinel incident fires and the playbook runs, the analyst will see one of five comment shapes on the incident:

1. **Trackspace (Jira) unreachable** — the `Jira_health_check` to `{JIRAHOST}/rest/api/2/myself` returned non-2xx. No ticket was opened (couldn't), blocklist untouched. Action: verify Trackspace is up, that the `sentinelsvc` password hasn't been rotated in KV, and re-run the playbook on the incident.
2. **MANUAL — AbuseIPDB was unreachable** — AbuseIPDB health check failed, so the playbook opened a Jira `Task` with the raw IP list (no enrichment) attached as `raw_ips_<incident-number>.csv`. The Jira summary starts with `MANUAL REVIEW REQUIRED`. The analyst must triage manually; **no automatic blocklist update happens from this branch**. Either push approved IPs to `$web/index.html` by hand, or re-run the playbook once AbuseIPDB is back.
3. **Playbook finished without action** — every IP either had fewer than `MinReports` AbuseIPDB reports or belonged to an excluded ISP. The Sentinel incident is auto-closed as `BenignPositive - SuspiciousButExpected`. No Jira ticket, no blocklist change. No action needed.
4. **Approval ticket opened** — comment contains a Trackspace URL (e.g. `https://trackspace.lhsystems.com/browse/CLOPSSEC-12345`). The playbook is now polling that ticket every 5 minutes for the configured approval status.
5. **Approval received** — the analyst transitioned the ticket to status `approval`; the playbook appended the surviving IPs to the blocklist and auto-closed the Jira ticket via `JiraCloseTransitionId` with a `"N IPs added to blob"` comment.

## Approving a block

1. Open the Trackspace ticket linked from the incident comment.
2. Open the attachment `abuseipdb_report_<incident-number>.csv` and review:
   - `ip`, `totalReports`, `abuseConfidenceScore`, `isp`, `country`, `usageType`, `lastReportedAt` for every IP that came out of the incident.
   - The ticket description lists only the **kept** IPs (those that survived filtering). Those are the ones that will hit the blocklist.
3. Decision:
   - **Approve** → transition the ticket to status `Approval` (case-insensitive match — `approval`, `Approval`, `APPROVAL` all work).
     - Within 5 minutes the playbook will add those IPs to `lsyweuritcsprdmspalo001/$web/index.html`, comment the result on the incident, and **auto-close the Jira ticket** (transition `JiraCloseTransitionId`, default `31`) with a `"N IPs added to blob"` comment. No further analyst action on the ticket needed.
   - **Reject / close without approving** → move the ticket to any other terminal status (do not use the `Approval` status). The playbook will eventually time out (default 48 h) and add a "approval not received" comment to the incident; the blocklist will not be modified and the playbook will not touch the ticket.

## After approval

The Sentinel incident gets a follow-up comment:

> Approval received on CLOPSSEC-12345. N new IP(s) appended to lsyweuritcsprdmspalo001/$web/index.html; M already present and skipped.

`N` may be smaller than the kept-IP count if some IPs were already in the blocklist — that's expected and not an error.

To confirm:

```bash
az storage blob download \
  --account-name lsyweuritcsprdmspalo001 \
  --container-name '$web' \
  --name index.html \
  --auth-mode login \
  --file /tmp/blocklist.html
grep -c '^[0-9]' /tmp/blocklist.html      # count IP-ish lines
grep '<the-ip-you-approved>' /tmp/blocklist.html
```

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

## Re-running the playbook

If the playbook needs to be re-triggered on an incident (e.g. after fixing a KV permission):

1. In the Sentinel incident, click **Actions → Run playbook**.
2. Select `Sentinel-IPAbuse-TriageAndBlock`.
3. Note: each re-run creates a fresh Jira ticket. Close the old ticket first to avoid duplicate approvals racing.

## Reconciling concurrent approvals

The blob update is read-modify-write without a lease or `If-Match` precondition. If two approved playbook runs hit `Update_blob` within a few seconds of each other, the later writer can overwrite the earlier one and silently drop the earlier run's IPs.

Symptoms:
- Two incident comments within ~10s of each other both say "N new IP(s) appended", but a `grep` against `$web/index.html` only shows the second run's IPs.

Recovery:
1. Identify the affected incidents (look for two "Approval received" comments close together).
2. Re-run the playbook on each affected incident via **Actions → Run playbook**. The line-level dedupe in the blob-update step makes re-runs idempotent — already-present IPs are skipped, missing ones are appended.

To avoid this entirely, switch `Update_blob` to use the `ETag` returned by `Get_blob_content` as an `If-Match` header and wrap it in an Until-retry on 412 Precondition Failed. The current workflow deliberately skips that to stay simple; flip the trade-off here if collisions are seen in practice.

## Tuning

The Logic App's parameters can be edited in the Azure portal (`Logic app → Edit → ⚙ Parameters`) without redeploying ARM:

| Parameter | Default | Notes |
|---|---|---|
| `MinReports` | `100` | Lower it to be more aggressive, raise it to be more conservative. |
| `ExcludedISPs` | `["akamai technologies", "google", "palo alto networks", "the shadowserver foundation", "censys"]` | Lower-case. Add new ISPs here; the comparison uses `toLower(isp)`. |
| `JiraApprovalStatusName` | `approval` | Must match the workflow's status string for CLOPSSEC, but casing doesn't matter. |
| `JiraCloseTransitionId` | `"31"` | The numeric id of the Jira workflow transition used to close the approval ticket. Discover the right value with `curl -u sentinelsvc:<pwd> {JIRAHOST}/rest/api/2/issue/<any-CLOPSSEC-key>/transitions` and look for the transition whose target status closes the ticket. If wrong, `Close_Jira_Ticket` returns 400 and the run ends Failed — but the blob update has already committed, so just fix the parameter and close the orphan ticket by hand. |
| `ApprovalPollIntervalMinutes` | `5` | Faster polling means more Jira API hits — watch rate limits. |
| `ApprovalMaxIterations` / `ApprovalTimeout` | `576` / `PT48H` | Keep them aligned: `count × poll-interval ≈ timeout`. |

## On-call triage cheatsheet

| Symptom | Likely cause | Fix |
|---|---|---|
| `Jira_health_check` 401 | Trackspace `sentinelsvc` password rotated and KV not updated. | Update the `sentinelsvc` secret in Key Vault. |
| `Jira_health_check` connection error / 5xx | Trackspace down or DNS issue. | Wait and re-trigger the playbook on the affected incident(s) via **Actions → Run playbook**. |
| `AbuseIPDB_health_check` 401/403 | OMS AbuseIPDB connection auth expired, or the API key bound to the connection was rotated. | Contact OMS to re-authorise `abuseipdb-connection-AbuseIPDB-EnrichIncidentByIPInfo` in `LSY_WEUR_ITCS_PRD_OMS_RG_001`. While AbuseIPDB is down, every incoming incident gets a manual-triage Jira ticket — drain those by hand or batch-re-run once AbuseIPDB is back. |
| `AbuseIPDB_health_check` 429 | Rate-limited | Wait it out; consider reducing playbook trigger volume or upgrading the AbuseIPDB plan. |
| `Create_Jira_Task` or `Create_Manual_Jira_Task` 401 | Trackspace password rotated after the `Jira_health_check` somehow succeeded (rare race). | Update `sentinelsvc` secret in KV. |
| `Create_Jira_Task` 400 with `issuetype` error | `JiraIssueTypeName` doesn't exist in CLOPSSEC | Adjust the parameter to a valid issue-type name. |
| `Close_Sentinel_no_actionable` fails | Managed identity missing `Microsoft Sentinel Responder` on the workspace | Grant the role on the Sentinel workspace. |
| `Get_blob_content` 403 | Managed identity missing `Storage Blob Data Contributor` | Grant the role on the storage account. |
| `Get_blob_content` 404 | Blob doesn't exist yet (first-time run on a fresh storage account). | No action needed — the workflow tolerates this and creates the blob on the first `Update_blob`. |
| `Update_blob` 409 | Concurrent modification by another writer | Re-run the playbook; the dedupe logic will skip already-present IPs on the retry. |
| `Close_Jira_Ticket` 400 with "transition does not exist" / similar | `JiraCloseTransitionId` is wrong for the CLOPSSEC workflow. | Discover the right id (see Tuning table); update the parameter; close the orphan ticket by hand. The blob was already updated, so no data is lost. |
| Playbook hangs at `Wait_For_Approval` longer than expected | Ticket status is anything other than `JiraApprovalStatusName` | Either approve the ticket or let it time out. |
