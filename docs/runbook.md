# Runbook — Sentinel IP-Abuse Triage & Block Playbook

## What an analyst sees

When a Sentinel incident fires and the playbook runs, the analyst will see one of three comment shapes on the incident:

1. **AbuseIPDB unreachable** — health-check failed. Nothing else happened; no Jira ticket exists, blocklist is untouched. Action: check AbuseIPDB status and that the OMS connection `abuseipdb-connection-AbuseIPDB-EnrichIncidentByIPInfo` is still authorised, then re-run the playbook manually on the incident.
2. **Playbook finished without action** — every IP either had fewer than `MinReports` AbuseIPDB reports or belonged to an excluded ISP. No Jira ticket, no blocklist change. No action needed.
3. **Approval ticket opened** — comment contains a Trackspace URL (e.g. `https://trackspace.lhsystems.com/browse/CLOPSSEC-12345`). The playbook is now polling that ticket every 5 minutes.

## Approving a block

1. Open the Trackspace ticket linked from the incident comment.
2. Open the attachment `abuseipdb_report_<incident-number>.csv` and review:
   - `ip`, `totalReports`, `abuseConfidenceScore`, `isp`, `country`, `usageType`, `lastReportedAt` for every IP that came out of the incident.
   - The ticket description lists only the **kept** IPs (those that survived filtering). Those are the ones that will hit the blocklist.
3. Decision:
   - **Approve** → transition the ticket to status `Approval` (case-insensitive match — `approval`, `Approval`, `APPROVAL` all work).
     - Within 5 minutes the playbook will add those IPs to `lsyweuritcsprdmspalo001/$web/index.html`, comment the result on the incident, and then auto-transition the ticket to `Closed` (controlled by `JiraClosedStatusName`). If the board offers no transition to `Closed` from the approval status, the playbook leaves the ticket where it is rather than erroring — close it by hand in that case.
   - **Reject / close without approving** → move the ticket to any other terminal status. The playbook will eventually time out (default 48 h) and add a "approval not received" comment to the incident; the blocklist will not be modified.

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
2. Select `TI-handler`.
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
| `ExcludedISPs` | `["akamai technologies", "google", "palo alto networks", "the shadowserver foundation", "censys"]` | Lower-case. Matched as a **substring** of `toLower(isp)`, so `palo alto networks` catches `"Palo Alto Networks, Inc"`. Keep entries specific enough not to catch unintended ISPs. |
| `JiraClosedStatusName` | `Closed` | Status the ticket is auto-transitioned to after approval. Case-insensitive substring of the transition's target status. |
| `JiraApprovalStatusName` | `approval` | Must match the workflow's status string for CLOPSSEC, but casing doesn't matter. |
| `ApprovalPollIntervalMinutes` | `5` | Faster polling means more Jira API hits — watch rate limits. |
| `ApprovalMaxIterations` / `ApprovalTimeout` | `576` / `PT48H` | Keep them aligned: `count × poll-interval ≈ timeout`. |

## On-call triage cheatsheet

| Symptom | Likely cause | Fix |
|---|---|---|
| `AbuseIPDB_health_check` 401/403 | OMS AbuseIPDB connection auth expired, or the API key bound to the connection was rotated. | Contact OMS to re-authorise `abuseipdb-connection-AbuseIPDB-EnrichIncidentByIPInfo` in `LSY_WEUR_ITCS_PRD_OMS_RG_001`. |
| `AbuseIPDB_health_check` 429 | Rate-limited | Wait it out; consider reducing playbook trigger volume or upgrading the AbuseIPDB plan. |
| `Create_Jira_Task` 401 | Trackspace password rotated | Update `sentinelsvc` secret in KV. |
| `Create_Jira_Task` 400 with `issuetype` error | `JiraIssueTypeName` doesn't exist in CLOPSSEC | Adjust the parameter to a valid issue-type name. |
| `Get_blob_content` 403 | Managed identity missing `Storage Blob Data Contributor` | Grant the role on the storage account. |
| `Update_blob` 409 | Concurrent modification by another writer | Re-run the playbook; the dedupe logic will skip already-present IPs on the retry. |
| Playbook hangs at `Wait_For_Approval` longer than expected | Ticket status is anything other than `JiraApprovalStatusName` | Either approve the ticket or let it time out. |
