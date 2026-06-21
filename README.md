<div align="center">
  <img src="market.png" alt="xtesource" width="96" />

# xtesource — xyNasTools Plugin Registry

[![GitHub last commit](https://img.shields.io/github/last-commit/xyNasTools/xtesources?style=flat-square)](https://github.com/xyNasTools/xtesources/commits/main)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
![Python](https://img.shields.io/badge/python-3.13-blue?style=flat-square)
![Docker](https://img.shields.io/badge/docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)

Self-hosted registry server for distributing `.xte` plugin files to xyNasTools Core instances.

</div>

## Quick Start

```bash
# 1. Start the registry
docker compose up -d

# 2. Drop .xte files into plugins/ — catalog rebuilds automatically
cp your_plugin-1.0.0.xte plugins/

# 3. Force an immediate catalog rebuild (optional)
curl -X POST "http://localhost:12139/admin/refresh?key=<AUTH_TOKEN>"

# 4. In xyNasTools Management → Plugins → Sources, add:
#   URL:   http://<your-server>:12139
#   Token: <AUTH_TOKEN>
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SOURCE_NAME` | `xyNasTools Plugin Registry` | Human-readable name shown in the catalog |
| `SOURCE_URL` | `http://localhost:12139` | Public URL of this registry (used to build download URLs in catalog) |
| `AUTH_TOKEN` | _(empty)_ | **Recommended.** Simple password key — required for catalog and downloads when set. |
| `ALLOWED_ORIGIN` | _(empty)_ | CORS `Access-Control-Allow-Origin` value. Leave empty if Core calls this server-side only. |
| `CATALOG_TTL` | `60` | Seconds to cache the catalog before rebuilding from disk. |
| `PORT` | `12139` | Host port to bind. |

## Authentication

Set `AUTH_TOKEN` to any password string. When set, clients must supply it in one of two ways:

```bash
# Query parameter (simplest — just append to any URL)
curl "http://localhost:12139/catalog.json?key=mypassword"
curl "http://localhost:12139/plugins/foo-1.0.0.xte?key=mypassword"

# Authorization header (plain, no Bearer prefix required)
curl -H "Authorization: mypassword" http://localhost:12139/catalog.json
```

Leave `AUTH_TOKEN` empty to allow unauthenticated access (suitable for isolated internal networks only).

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | None | Homepage — catalog browser UI |
| `GET` | `/health` | None | Liveness check |
| `GET` | `/catalog.json` | Key (if set) | Full plugin catalog with SHA-256 checksums |
| `GET` | `/plugins/<file>` | Key (if set) | Download a `.xte` plugin file |
| `GET` | `/plugin-icons/<id>` | None | Serve a plugin's embedded icon (falls back to platform icon) |
| `POST` | `/admin/refresh` | Key | Force-rebuild the catalog cache immediately |

## Catalog Format

```json
{
  "schema_version": "1",
  "source_name": "My Registry",
  "source_url": "https://registry.example.com",
  "updated_at": "2026-06-21T12:00:00+00:00",
  "plugin_count": 1,
  "plugins": [
    {
      "id": "anime_tab",
      "name": "AnimeTab",
      "version": "1.0.0",
      "description": "Anime library management.",
      "plugin_type": "library",
      "dependencies": [],
      "filename": "anime_tab-1.0.0.xte",
      "download_path": "/plugins/anime_tab-1.0.0.xte",
      "icon_url": "/plugin-icons/anime_tab",
      "size_bytes": 14200,
      "sha256": "a3f1..."
    }
  ]
}
```

## Adding Plugins

Plugin files must follow the naming pattern `{id}-{version}.xte` (lowercase alphanumeric id, semver version):

```bash
# Copy built .xte file into the plugins volume
cp dist/anime_tab-1.0.0.xte plugins/

# Catalog auto-rebuilds within CATALOG_TTL seconds, or force it immediately:
curl -X POST "http://localhost:12139/admin/refresh?key=$AUTH_TOKEN"
```

## Security

Run behind a reverse proxy with TLS in production:

```nginx
server {
    listen 443 ssl;
    server_name registry.example.com;
    ssl_certificate     /etc/ssl/certs/registry.crt;
    ssl_certificate_key /etc/ssl/private/registry.key;
    location / {
        proxy_pass http://localhost:12139;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```
