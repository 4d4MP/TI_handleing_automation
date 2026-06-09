#!/usr/bin/env bash
#
# verify-deployed-definition.sh
#
# Confirms that the *deployed* TI-handler Logic App matches the filtering logic
# in this repo. Use it whenever the Jira ticket CSV still lists excluded ISPs
# (Censys, Palo Alto Networks, ...) or IPs below MinReports.
#
# Why this exists: the CSV attachment is built from `Filter_Kept_Rows`, which is
# downstream of both the MinReports floor and the ISP exclusion. A correctly
# deployed definition therefore CANNOT emit an excluded ISP or a sub-MinReports
# IP into the report. If you see those, the live Logic App is running an older
# definition than the repo (the merged fix was never deployed, a duplicate/old-
# named app is the one wired to Sentinel, or someone edited the app in the
# portal). Editing parameters or merging to main fixes nothing until the running
# app is redeployed.
#
# Requires: az CLI (run `az login` first) and jq.
#
# Overridable via environment:
#   SUBSCRIPTION, RG, APP
#
set -euo pipefail

SUBSCRIPTION="${SUBSCRIPTION:-f12b729d-7c1e-4407-bb9d-2e7ec4aa1d29}"
RG="${RG:-LSY_WEUR_ITCS_PRD_SEC_RG_002}"
APP="${APP:-TI-handler}"
EXPECTED="@body('Filter_Kept_Rows')"

command -v az >/dev/null 2>&1 || { echo "ERROR: az CLI not found (install + 'az login')." >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found." >&2; exit 2; }

echo "Fetching live definition for Logic App '$APP' (rg=$RG)..."
if ! DEF="$(az rest --method get \
  --url "https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/${RG}/providers/Microsoft.Logic/workflows/${APP}?api-version=2019-05-01" \
  -o json 2>/tmp/verify_az_err)"; then
  echo "ERROR: could not fetch the Logic App definition:" >&2
  cat /tmp/verify_az_err >&2
  echo "Check you are logged in (az login), the subscription is selected, and APP/RG are correct." >&2
  exit 2
fi

from="$(jq -r '.properties.definition.actions.Empty_result_gate.else.actions.Build_CSV.inputs.from // "MISSING"' <<<"$DEF")"
minrep="$(jq -r '.properties.definition.actions.Filter_Min_Reports.inputs.where // "MISSING"' <<<"$DEF")"
kept="$(jq -r '.properties.definition.actions.Filter_Kept_Rows.inputs.where // "MISSING"' <<<"$DEF")"

echo
echo "Live Build_CSV.inputs.from    : ${from}"
echo "Live Filter_Min_Reports.where : ${minrep}"
echo "Live Filter_Kept_Rows.where   : ${kept}"
echo

if [[ "$from" == "$EXPECTED" ]]; then
  echo "PASS: the deployed CSV is built from the filtered set (${EXPECTED})."
  echo "      Excluded ISPs and sub-MinReports IPs will NOT appear in the ticket attachment."
  exit 0
fi

echo "STALE: the deployed CSV is built from '${from}', not '${EXPECTED}'."
echo "       The running Logic App predates the filtering fix. Redeploy the repo definition:"
echo
echo "         az deployment group create --resource-group \"${RG}\" \\"
echo "           --template-file playbook/azuredeploy.json \\"
echo "           --parameters @playbook/azuredeploy.parameters.json"
echo
echo "Then confirm the app you redeployed is the one Sentinel actually triggers."
echo "Logic Apps currently in ${RG} (watch for a duplicate / old 'Sentinel-IPAbuse-TriageAndBlock'):"
az resource list -g "$RG" --resource-type Microsoft.Logic/workflows --query "[].name" -o tsv 2>/dev/null | sed 's/^/  - /' || true
exit 1
