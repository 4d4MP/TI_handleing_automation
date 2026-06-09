# TI_handleing_automation

Source of truth for the **Sentinel-IPAbuse-TriageAndBlock** playbook: a Microsoft Sentinel Logic App that enriches incident IPs against AbuseIPDB, opens a Trackspace (Jira) approval ticket in `CLOPSSEC` with a CSV report attached, polls until the ticket is approved, and then appends the approved IPs to the static-site blocklist at `lsyweuritcsprdmspalo001/$web/index.html`.

## Repository layout

```
.
├── playbook/
│   ├── workflow.json                  # Logic App definition only (importable in the Sentinel UI)
│   ├── azuredeploy.json               # ARM template: Logic App + API connections (preferred deploy)
│   └── azuredeploy.parameters.json    # Production values (PlaybookName=TI-handler, KeyVaultName=LSY-WEUR-ITCS-PRD-KV-02)
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
- The AbuseIPDB API connection `abuseipdbapi-1` in resource group `LSY_WEUR_ITCS_PRD_SEC_RG_002` must already exist and be authorised. It is built on the OMS-owned `abuseipdbapi` custom connector in `LSY_WEUR_ITCS_PRD_OMS_RG_001`. AbuseIPDB enrichment goes through that connection — this playbook does not store an AbuseIPDB API key of its own.

`azuredeploy.parameters.json` already carries the production values — `PlaybookName=TI-handler` (the deployed Logic App) and `KeyVaultName=LSY-WEUR-ITCS-PRD-KV-02`. **Keep `PlaybookName=TI-handler`**: deploying with the old `Sentinel-IPAbuse-TriageAndBlock` name would stand up a second parallel Logic App with a fresh managed identity and leave the real TI-handler untouched. The template defaults match these values, so an override is only needed to target a different environment.

```bash
RG=LSY_WEUR_ITCS_PRD_SEC_RG_002
az deployment group create \
  --resource-group "$RG" \
  --template-file playbook/azuredeploy.json \
  --parameters @playbook/azuredeploy.parameters.json
```

The Logic App and both API connections carry the governance tags `CostCenter=S60019`, `Owner=lsyh.sysops@lhsystems.com`, and `assessment-id=1` in the template, matching what is live so a deploy never strips them.

The deployment outputs `managedIdentityPrincipalId`. Grant it the three roles below; the playbook will not function without them:

| Scope | Role |
|---|---|
| Sentinel workspace | Microsoft Sentinel Responder |
| Key Vault | Key Vault Secrets User |
| Storage account (blocklist) | Storage Blob Data Contributor |

The API connections (`azuresentinel-<PlaybookName>`, `keyvault-<PlaybookName>`) are created by the template but their consent prompts must be approved in the portal on first use (open each connection → "Edit API connection" → Authorize). The third connection used by the playbook — `abuseipdbapi-1` in `LSY_WEUR_ITCS_PRD_SEC_RG_002`, built on the OMS-owned `abuseipdbapi` custom connector in `LSY_WEUR_ITCS_PRD_OMS_RG_001` — is **referenced**, not created, by this template; it should already be authorised in production.

## Configuration

All knobs are workflow parameters and can be tweaked in the portal without redeploying. See `docs/runbook.md` for the table; the most relevant ones:

| Parameter | Default |
|---|---|
| `MinReports` | `100` |
| `ExcludedISPs` | `["akamai technologies", "google", "palo alto networks", "the shadowserver foundation", "censys"]` (matched case-insensitively as a substring of the ISP name) |
| `JiraApprovalStatusName` | `Resolved` (matched case-insensitively as a substring of the Jira status) |
| `JiraClosedStatusName` | `Closed` (status the ticket is auto-transitioned to after approval) |
| `ApprovalPollIntervalMinutes` | `5` |
| `ApprovalTimeout` | `PT48H` |

## Workflow at a glance

1. Sentinel incident trigger → `Entities - Get IPs`.
2. Pull the Jira password from Key Vault (`secureData` so it doesn't appear in run history). AbuseIPDB auth is handled by the `abuseipdbapi-1` connection — no secret retrieval needed.
3. Health-check AbuseIPDB by calling `/check?ipAddress=8.8.8.8` through the `abuseipdbapi-1` connection. Failure → comment + terminate.
4. Foreach IP: `abuseipdbapi-1` → `GET /check`, append a report row, and (if `totalReports >= MinReports` and ISP is not excluded) append to `Kept_IPs`.
5. Empty list → comment "no actionable IPs" + terminate succeeded.
6. Otherwise: build a CSV of the **kept** IPs, open a `Task` in `CLOPSSEC` (description carries the kept-IP count; the per-IP detail for those kept IPs rides along as the attached CSV — individual IPs are not listed in the ticket body), attach the CSV, comment the Jira URL on the incident.
7. Poll the Jira ticket every 5 min until the status (case-insensitive) contains `Resolved`, or timeout.
8. On approval: GET `$web/index.html`, dedupe new IPs, PUT the updated blob; comment the result on the Trackspace ticket, then auto-transition the ticket to `Closed` (falls back to leaving it open if no such transition exists).
9. On timeout / non-approval: comment "approval not received" on the Trackspace ticket; blocklist untouched.

For the full picture see [`docs/architecture.md`](docs/architecture.md). For analyst-side operations see [`docs/runbook.md`](docs/runbook.md).
