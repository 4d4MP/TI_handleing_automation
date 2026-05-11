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

- A Key Vault holding two secrets: the AbuseIPDB API key and the Trackspace service-account password.
- A storage account with static website enabled and `$web/index.html` present (created empty if necessary).
- Permission to create Logic Apps + API connections in the target resource group.

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

The API connections (`azuresentinel-<PlaybookName>`, `keyvault-<PlaybookName>`) are created by the template but their consent prompts must be approved in the portal on first use (open each connection → "Edit API connection" → Authorize).

## Configuration

All knobs are workflow parameters and can be tweaked in the portal without redeploying. See `docs/runbook.md` for the table; the most relevant ones:

| Parameter | Default |
|---|---|
| `MinReports` | `100` |
| `ExcludedISPs` | `["akamai technologies", "google", "palo alto networks", "the shadowserver foundation", "censys"]` |
| `JiraApprovalStatusName` | `approval` (case-insensitive) |
| `ApprovalPollIntervalMinutes` | `5` |
| `ApprovalTimeout` | `PT48H` |

## Workflow at a glance

1. Sentinel incident trigger → `Entities - Get IPs`.
2. Pull AbuseIPDB key + Jira password from Key Vault (`secureData` so values don't appear in run history).
3. Health-check AbuseIPDB with `8.8.8.8`. Failure → comment + terminate.
4. Foreach IP: HTTP `GET /api/v2/check`, append a report row, and (if `totalReports >= MinReports` and ISP is not excluded) append to `Kept_IPs`.
5. Empty list → comment "no actionable IPs" + terminate succeeded.
6. Otherwise: build CSV, open a `Task` in `CLOPSSEC`, attach the CSV, comment the Jira URL on the incident.
7. Poll the Jira ticket every 5 min until status (case-insensitive) equals `approval`, or timeout.
8. On approval: GET `$web/index.html`, dedupe new IPs, PUT the updated blob; comment the result on the incident.
9. On timeout / non-approval: comment "approval not received"; blocklist untouched.

For the full picture see [`docs/architecture.md`](docs/architecture.md). For analyst-side operations see [`docs/runbook.md`](docs/runbook.md).
