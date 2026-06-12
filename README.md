# TI_handleing_automation

Source of truth for the **TI-handler** playbook: a Microsoft Sentinel Logic App that, on each incident, **autonomously** raises an OPSLSY *Technical change* (a clone of the template `OPSLSY-75376`), walks it to **Implementation**, enriches the incident IPs against AbuseIPDB, appends the kept IPs to the static-site blocklist at `lsyweuritcsprdmspalo001/$web/index.html`, attaches the CSV report to the change, then walks the change to **Closed** with resolution **Successful**.

There is **no human approval step** and **no CLOPSSEC ticket** — both were removed per a management decision making the flow fully autonomous. If AbuseIPDB is unreachable the same change is still driven to Closed, with the raw (un-enriched) incident IPs attached.

## Repository layout

```
.
├── playbook/
│   ├── workflow.json                  # Logic App definition only (importable in the Sentinel UI)
│   ├── azuredeploy.json               # ARM template: Logic App + API connections (preferred deploy)
│   └── azuredeploy.parameters.json    # Production values (PlaybookName=TI-handler, KeyVaultName=LSY-WEUR-ITCS-PRD-KV-02)
├── docs/
│   ├── 07-ti-handler-playbook.md      # Knowledge-base page: ticket model, walk, fields, fallback
│   ├── architecture.md                # Sequence, decisions, RBAC needed
│   ├── runbook.md                     # What an analyst sees and how to roll back
│   └── references/                    # Original reference workflows (kept verbatim)
├── README.md
└── LICENSE
```

`workflow.json` and the `definition` block inside `azuredeploy.json` are kept in sync by hand. Edit `workflow.json` first, then mirror the `definition` block into the ARM template before deploying. The `jq -S` diff between the two files is expected to be non-empty — only the parameter `defaultValue`s differ (literals in `workflow.json` vs `[parameters('…')]` in ARM); the `actions` and `triggers` must match exactly.

## Deploy

Prerequisites:

- A Key Vault holding one secret: the Trackspace service-account password (`JiraKeyVaultSecretName`, default `sentinelsvc`).
- A storage account with static website enabled and `$web/index.html` present (created empty if necessary).
- Permission to create Logic Apps + API connections in the target resource group.
- The AbuseIPDB API connection `abuseipdbapi-1` in resource group `LSY_WEUR_ITCS_PRD_SEC_RG_002` must already exist and be authorised. It is built on the OMS-owned `abuseipdbapi` custom connector in `LSY_WEUR_ITCS_PRD_OMS_RG_001`. AbuseIPDB enrichment goes through that connection — this playbook does not store an AbuseIPDB API key of its own.

`azuredeploy.parameters.json` already carries the production values — `PlaybookName=TI-handler` (the deployed Logic App) and `KeyVaultName=LSY-WEUR-ITCS-PRD-KV-02`. **Keep `PlaybookName=TI-handler`**: deploying with the old `Sentinel-IPAbuse-TriageAndBlock` template name would stand up a second parallel Logic App with a fresh managed identity and leave the real TI-handler untouched. The template defaults match these values, so an override is only needed to target a different environment.

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

Logic App runs are immutable: after a redeploy, cancel any stuck in-flight runs and fire fresh ones.

## Configuration

All knobs are workflow parameters and can be tweaked in the portal without redeploying. See `docs/07-ti-handler-playbook.md` for the full list; the most relevant ones:

| Parameter | Default |
|---|---|
| `JiraProjectKey` | `OPSLSY` (also used in the find-clone-by-search JQL) |
| `TemplateIssueKey` | `OPSLSY-75376` (the change cloned each run) |
| `StatusPlanningName` / `StatusImplementationName` / `StatusPostImplReviewName` / `JiraClosedStatusName` | `Planning` / `Implementation` / `Post implementation review` / `Closed` (each matched case-insensitively as a substring of a transition's target status) |
| `MinReports` | `100` |
| `ExcludedISPs` | `["akamai technologies", "google", "palo alto networks", "the shadowserver foundation", "censys"]` (matched case-insensitively as a substring of the ISP name) |

## Workflow at a glance

1. Sentinel incident trigger → `Entities - Get IPs`; pull the Jira password from Key Vault (`secureData`); compute the run timestamps (`plannedStart`, `plannedEnd = +5 min`, `dateStamp`).
2. **Clone** the template `OPSLSY-75376` (server-side `POST /secure/CloneIssueDetails.jspa` — a clone is the only way to carry the Insight/Assets *Affected item*, which can't be REST-set), find the new key by JQL search (reporter `sentinelsvc` + `created >= -10m`, guarded by `created >= run start`), **`PUT`** the description + planned dates, then **walk it to Implementation** (Open → Planning → Implementation) — all at run start, before any AbuseIPDB work.
3. Health-check AbuseIPDB (`/check?ipAddress=8.8.8.8`).
   - **Up** → per-IP `/check` (50-way), keep rows with `totalReports >= MinReports` and a non-excluded ISP → `Block_IPs` + rich `CSV_Rows`.
   - **Down** → fallback: build `Block_IPs` + `CSV_Rows` from the **raw** incident IP list. No separate ticket — the change already exists.
4. **Write the blocklist blob** (ungated): GET `$web/index.html`, line-level dedupe, PUT the appended content.
5. **Attach** the CSV to the change (`POST /issue/{key}/attachments`, multipart).
6. **Walk to Closed**: Post implementation review (`resolution=Successful`, actual start/finish) → Closed (`resolution=Successful`). The walk re-probes transitions each step, picks by target status **name** (skipping revoke/withdraw/re-plan/reject/cancel/update-cmdb), and polls status until it lands.

No comments are written back to the Sentinel incident at any stage.

For the full picture see [`docs/07-ti-handler-playbook.md`](docs/07-ti-handler-playbook.md) and [`docs/architecture.md`](docs/architecture.md). For analyst-side operations see [`docs/runbook.md`](docs/runbook.md).
