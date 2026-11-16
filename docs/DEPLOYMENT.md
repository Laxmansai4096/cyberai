# Deployment (Azure for Students, free tiers only)

## Resources

| Resource | Name | Tier / cost |
|---|---|---|
| Resource group | `rg-cyberai` (uaenorth) | free |
| Function App | `fn-cyberai-7qhue` – Flex Consumption, Python 3.12, 512 MB, max 10 instances, 0 always-ready | monthly free grant (100k GB-s, 250k executions) |
| Cosmos DB | `cosmos-cyberai-kor7qhue` (koreacentral – uaenorth had no capacity) – **free tier**, db `cybersentinel` 400 RU/s shared, container `items` | free (≤1000 RU/s, 25 GB) |
| App Insights | `appi-cyberai` → existing workspace `law-foundry-explorer` | first 5 GB/month free |
| Storage queues | `security-events`, `mediflow-commands` on **existing** `stexplore12` | fractions of a cent |
| Deployment package | blob container on existing `stexplore12` | fractions of a cent |

The subscription policy only allows koreacentral, indonesiacentral, polandcentral, uaenorth and indiasouthcentral.
Cosmos DB allows **one** free-tier account per subscription.

## Steps

```powershell
az login
az account show                              # Azure for Students
./scripts/deploy.ps1 -CosmosLocation koreacentral
```

The script is idempotent. On first run it generates `JWT_SECRET`, `SEED_PASSWORD` and `INGEST_API_KEY`, stores them as Function App settings (encrypted at rest), and prints the demo password once.

To read the password later, run:
`az functionapp config appsettings list -g rg-cyberai -n fn-cyberai-7qhue --query "[?name=='SEED_PASSWORD'].value" -o tsv`

## Smoke test

```powershell
$u = "https://fn-cyberai-7qhue.azurewebsites.net"
irm "$u/api/health"
$t = (irm "$u/api/auth/login" -Method Post -ContentType application/json -Body '{"username":"lead.sara","password":"<SEED_PASSWORD>"}').access_token
irm "$u/api/demo/simulate" -Method Post -Headers @{Authorization="Bearer $t"} -ContentType application/json -Body '{"scenario":"all"}'
irm "$u/api/dashboard" -Headers @{Authorization="Bearer $t"}
```

## Teardown

```powershell
az group delete -n rg-cyberai --yes
az storage queue delete -n security-events --account-name stexplore12 --auth-mode login
az storage queue delete -n mediflow-commands --account-name stexplore12 --auth-mode login
```

## CI

`.github/workflows/ci.yml` runs ruff, pytest and a JS syntax check on every push or PR. Deployment is done with `scripts/deploy.ps1 -CodeOnly`. A GitHub Actions deploy job would need an Entra app registration with a federated credential, which a student tenant may not allow.
