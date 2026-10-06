# Email Risk API

A FastAPI API for signup-abuse detection. It combines disposable-email intelligence, DNS signals, cached RDAP domain-age data, and deterministic risk scoring.

## What changed in v1.1

- Replaced `python-whois` with RDAP.
- Uses IANA RDAP bootstrap discovery so domains are routed to the appropriate authoritative RDAP service.
- Caches domain intelligence in PostgreSQL.
- Added an automated GitHub Actions workflow that refreshes the disposable-domain blocklist daily.
- Added request rate limiting.
- Added `/ready` with a SQLAlchemy 2.x-safe database probe.
- Keeps a small built-in disposable list as a fallback if the generated file is unavailable.

RDAP is the standardized replacement for WHOIS for gTLD registration data. The API does not require a paid WHOIS database.

## Run locally

1. Install Docker Desktop.
2. Open PowerShell in this folder.
3. Run:

```powershell
docker compose up --build
```

4. Open `http://localhost:8000/docs`.
5. Create a key with `POST /v1/keys`:

```json
{
  "email": "you@example.com",
  "name": "Development"
}
```

6. Copy the returned `rk_live_...` key.
7. Authorize Swagger with `Bearer YOUR_KEY`.
8. Test `POST /v1/check` with:

```json
{
  "email": "test@mailinator.com"
}
```

## PowerShell test

```powershell
$body = @{ email = "test@mailinator.com" } | ConvertTo-Json
Invoke-RestMethod `
  -Uri "http://localhost:8000/v1/check" `
  -Method Post `
  -Headers @{ Authorization = "Bearer rk_live_YOUR_KEY" } `
  -ContentType "application/json" `
  -Body $body
```

## Blocklist updater

The repository contains `.github/workflows/update-disposable-blocklist.yml`. GitHub Actions runs it daily and commits the refreshed blocklist into `backend/app/data/disposable_domains.txt`.

For a public GitHub repository, standard GitHub-hosted Actions runners are currently free and unlimited. Private repositories have plan-based quotas.

The upstream source used by the updater is the `disposable-email-domains` project. Review its license and source list before using the data commercially; the project currently publishes its list under a permissive license.

## Important RDAP limitation

RDAP is not an unlimited bulk-data feed. Cache domain results and avoid turning the service into a high-volume RDAP scanner. ICANN's published guidance restricts high-volume automated processes against registry/registrar systems. This API therefore uses PostgreSQL domain caching.

## Stop

```powershell
docker compose down
```

Remove database volumes too:

```powershell
docker compose down -v
```
