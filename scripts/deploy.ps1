<#
.SYNOPSIS
  Deploys CyberSentinel AI to Azure using ONLY free tiers / existing resources.

  Creates (idempotent):
    - Resource group
    - Cosmos DB account with FREE TIER (1000 RU/s + 25 GB free; one per subscription), database (400 RU/s shared) + container `items` (/type, TTL on)
    - Application Insights (workspace-based, 5 GB/month free) on an existing Log Analytics workspace
    - Function App on Flex Consumption (Python 3.12, 512 MB, no always-ready instances = monthly free grant)
    - Storage queues `security-events` and `mediflow-commands` on an EXISTING storage account
    - Managed-identity RBAC: Cosmos DB Built-in Data Contributor, Storage Queue Data Contributor
  Then zip-deploys the code with remote build.

.EXAMPLE
  az login
  ./scripts/deploy.ps1 -Suffix 7qhue -StorageAccount stexplore12 -StorageRg rg-azure-explorer -LawName law-foundry-explorer -LawRg rg-azure-explorer
#>
param(
  [string]$Suffix = "7qhue",
  [string]$ResourceGroup = "rg-cyberai",
  [string]$Location = "uaenorth",
  [string]$CosmosLocation = "koreacentral",
  [string]$CosmosName = "",
  [string]$StorageAccount = "stexplore12",
  [string]$StorageRg = "rg-azure-explorer",
  [string]$LawName = "law-foundry-explorer",
  [string]$LawRg = "rg-azure-explorer",
  [switch]$CodeOnly
)
# az writes WARNINGs to stderr; with "Stop" PowerShell would abort on them, so check $LASTEXITCODE instead.
$ErrorActionPreference = "Continue"
$App = "fn-cyberai-$Suffix"
if (-not $CosmosName) { $CosmosName = "cosmos-cyberai-$($CosmosLocation.Substring(0,3))$Suffix" }
$Root = Split-Path $PSScriptRoot -Parent
function Rand([int]$n) { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count $n | ForEach-Object { [char]$_ }) }

az account show --query "{subscription:name, user:user.name}" -o table

if (-not $CodeOnly) {
  az group create -n $ResourceGroup -l $Location -o none
  if (-not (az cosmosdb show -n $CosmosName -g $ResourceGroup --query name -o tsv 2>$null)) {
    az cosmosdb create -n $CosmosName -g $ResourceGroup --locations regionName=$CosmosLocation failoverPriority=0 isZoneRedundant=false `
      --enable-free-tier true --default-consistency-level Session --minimal-tls-version Tls12 -o none
  }
  az cosmosdb sql database create -a $CosmosName -g $ResourceGroup -n cybersentinel --throughput 400 -o none
  az cosmosdb sql container create -a $CosmosName -g $ResourceGroup -d cybersentinel -n items -p /type --ttl -1 -o none
  az resource update -g $ResourceGroup -n $CosmosName --resource-type Microsoft.DocumentDB/databaseAccounts --set properties.disableLocalAuth=true -o none

  $law = az monitor log-analytics workspace show -g $LawRg -n $LawName --query id -o tsv
  az monitor app-insights component create -a "appi-cyberai" -g $ResourceGroup -l $Location --kind web --application-type web --workspace $law -o none
  foreach ($q in "security-events", "mediflow-commands") { az storage queue create -n $q --account-name $StorageAccount --auth-mode login -o none }

  $st = az storage account show -n $StorageAccount -g $StorageRg --query id -o tsv
  if (-not (az functionapp show -g $ResourceGroup -n $App --query name -o tsv 2>$null)) {
    az functionapp create -g $ResourceGroup -n $App --storage-account $st --flexconsumption-location $Location --runtime python `
      --runtime-version 3.12 --instance-memory 512 --maximum-instance-count 10 --app-insights appi-cyberai --assign-identity "[system]" -o none
  }
  $mi = az functionapp identity show -g $ResourceGroup -n $App --query principalId -o tsv
  az role assignment create --assignee-object-id $mi --assignee-principal-type ServicePrincipal --role "Storage Queue Data Contributor" --scope $st -o none
  $cosmosId = az cosmosdb show -n $CosmosName -g $ResourceGroup --query id -o tsv
  az cosmosdb sql role assignment create -a $CosmosName -g $ResourceGroup --role-definition-id 00000000-0000-0000-0000-000000000002 `
    --principal-id $mi --scope $cosmosId -o none

  $endpoint = az cosmosdb show -n $CosmosName -g $ResourceGroup --query documentEndpoint -o tsv
  $existing = az functionapp config appsettings list -g $ResourceGroup -n $App --query "[?name=='JWT_SECRET'].value" -o tsv
  $settings = @(
    "ENVIRONMENT=dev", "STORE_PROVIDER=cosmos", "COSMOS_ENDPOINT=$endpoint", "COSMOS_DATABASE=cybersentinel",
    "BUS_PROVIDER=storage", "QUEUE_ACCOUNT_URL=https://$StorageAccount.queue.core.windows.net",
    "SecurityQueue__queueServiceUri=https://$StorageAccount.queue.core.windows.net", "VULN_FEED=osv"
  )
  if (-not $existing) {
    $seedPw = "Cs-" + (Rand 10) + "!9"
    $settings += @("JWT_SECRET=$(Rand 48)", "SEED_PASSWORD=$seedPw", "INGEST_API_KEY=$(Rand 40)")
    Write-Host "Demo user password (save it): $seedPw" -ForegroundColor Yellow
  }
  az functionapp config appsettings set -g $ResourceGroup -n $App --settings $settings -o none
}

# ---- package and deploy (remote build installs requirements.txt on Azure)
$zip = Join-Path $env:TEMP "cyberai-deploy.zip"
if (Test-Path $zip) { Remove-Item $zip }
$stage = Join-Path $env:TEMP "cyberai-stage"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory $stage | Out-Null
Copy-Item "$Root/function_app.py", "$Root/host.json", "$Root/requirements.txt" $stage
Copy-Item -Recurse "$Root/app" "$stage/app"
Get-ChildItem $stage -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force
# Windows PowerShell's Compress-Archive writes backslash paths, which break on Linux; use Python's zipfile instead.
python -c "import sys,zipfile,pathlib; s=pathlib.Path(sys.argv[1]); z=zipfile.ZipFile(sys.argv[2],'w',zipfile.ZIP_DEFLATED); [z.write(p,p.relative_to(s).as_posix()) for p in s.rglob('*') if p.is_file()]; z.close()" $stage $zip
az functionapp deployment source config-zip -g $ResourceGroup -n $App --src $zip --build-remote true -o none 2>&1 | Where-Object { $_ -notmatch "WARNING" }
if ($LASTEXITCODE -ne 0) { throw "Deployment failed (exit $LASTEXITCODE)" }
$hostName = az functionapp show -g $ResourceGroup -n $App --query "properties.defaultHostName" -o tsv
Write-Host "Deployed: https://$hostName" -ForegroundColor Green
