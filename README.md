# TI_handleing_automation

Source of truth for the **Sentinel-IPAbuse-TriageAndBlock** playbook: a Microsoft Sentinel Logic App that enriches incident IPs against AbuseIPDB, opens a Trackspace (Jira) approval ticket in `CLOPSSEC` with a CSV report attached, polls until the ticket is approved, and then appends the approved IPs to the static-site blocklist at `lsyweuritcsprdmspalo001/$web/index.html`.

## Repository layout

```
.
├── playbook/
│   ├── workflow.json                  # Logic App definition only (importable in the Sentinel UI)
│   ├── azuredeploy.json               # ARM template: Logic App + API connections (preferred deploy)
│   └── azuredeploy.parameters.json    # Placeholders — fill KeyVaultName at minimum
├── docs/
│   ├── architecture.md                # Sequence, decisions, RBAC needed
│   ├── runbook.md                     # What an analyst sees and how to approve / roll back
│   └── references/                    # Original reference workflows (kept verbatim)
├── README.md
└── LICENSE
```

`workflow.json` and the `definition` block inside `azuredeploy.json` are kept in sync by hand. Edit `workflow.json` first, then mirror the `definition` block into the ARM template before deploying.

## Deploy

Prerequisites:

- A Key Vault holding one secret: the Trackspace service-account password (`JiraKeyVaultSecretName`, default `sentinelsvc`).
- A storage account with static website enabled and `$web/index.html` present (created empty if necessary).
- Permission to create Logic Apps + API connections in the target resource group.
- The OMS-owned AbuseIPDB custom connection `abuseipdb-connection-AbuseIPDB-EnrichIncidentByIPInfo` in resource group `LSY_WEUR_ITCS_PRD_OMS_RG_001` must already exist and be authorised. AbuseIPDB enrichment goes through that connection — this playbook does not store an AbuseIPDB API key of its own.

```bash
RG=LSY_WEUR_ITCS_PRD_SEC_RG_002
az deployment group create \
  --resource-group "$RG" \
  --template-file playbook/azuredeploy.json \
  --parameters @playbook/azuredeploy.parameters.json \
  --parameters KeyVaultName=<your-keyvault-name>
```

The deployment outputs `managedIdentityPrincipalId`. Grant it the three roles below; the playbook will not function without them:

| Scope | Role |
|---|---|
| Sentinel workspace | Microsoft Sentinel Responder |
| Key Vault | Key Vault Secrets User |
| Storage account (blocklist) | Storage Blob Data Contributor |

The API connections (`azuresentinel-<PlaybookName>`, `keyvault-<PlaybookName>`) are created by the template but their consent prompts must be approved in the portal on first use (open each connection → "Edit API connection" → Authorize). The third connection used by the playbook — `AbuseIPDBAPI` → `abuseipdb-connection-AbuseIPDB-EnrichIncidentByIPInfo` in `LSY_WEUR_ITCS_PRD_OMS_RG_001` — is OMS-owned and is **referenced**, not created, by this template; it should already be authorised in production.

## Configuration

All knobs are workflow parameters and can be tweaked in the portal without redeploying. See `docs/runbook.md` for the table; the most relevant ones:

| Parameter | Default |
|---|---|
| `MinReports` | `100` |
| `ExcludedISPs` | `["akamai technologies", "google", "palo alto networks", "the shadowserver foundation", "censys"]` |
| `JiraApprovalStatusName` | `approval` (case-insensitive) |
| `JiraCloseTransitionId` | `"31"` — Jira workflow transition id used to auto-close the approval ticket. Discover via `GET /rest/api/2/issue/<key>/transitions`. |
| `ApprovalPollIntervalMinutes` | `5` |
| `ApprovalTimeout` | `PT48H` |

## Workflow at a glance

1. Sentinel incident trigger → `Entities - Get IPs`.
2. Pull the Jira password from Key Vault (`secureData` so it doesn't appear in run history). AbuseIPDB auth is handled by the OMS-owned `AbuseIPDBAPI` connection — no secret retrieval needed.
3. Health-check Trackspace by calling `GET {JIRAHOST}/rest/api/2/myself` with Basic auth. Failure (unreachable / bad creds) → comment "Trackspace unreachable" + terminate.
4. Health-check AbuseIPDB by calling `/check?ipAddress=8.8.8.8` through the `AbuseIPDBAPI` connection.
5. **AbuseIPDB failure path**: build a one-column CSV of the raw IPs (no enrichment), open a Jira `Task` whose summary starts with `MANUAL REVIEW REQUIRED`, attach the CSV, comment the Jira URL on the incident, terminate. No approval polling, no blocklist change.
6. **AbuseIPDB success path** — Foreach IP: `AbuseIPDBAPI GET /check`, append a report row, and (if `totalReports >= MinReports` and ISP is not excluded) append to `Kept_IPs`.
7. Empty list → comment "no actionable IPs", close the Sentinel incident as `BenignPositive - SuspiciousButExpected`, terminate succeeded.
8. Otherwise: build CSV, open a `Task` in `CLOPSSEC`, attach the CSV, comment the Jira URL on the incident.
9. Poll the Jira ticket every 5 min until status (case-insensitive) equals `approval`, or timeout.
10. On approval: GET `$web/index.html` (404 tolerated → treat as empty), dedupe new IPs, PUT the updated blob (existing + new), comment the result on the incident, then auto-close the Jira ticket via `/transitions` with a `"N IPs added to blob"` comment.
11. On timeout / non-approval: comment "approval not received"; blocklist untouched, Jira ticket left as the analyst put it.

For the full picture see [`docs/architecture.md`](docs/architecture.md). For analyst-side operations see [`docs/runbook.md`](docs/runbook.md).
