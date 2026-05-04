# neon-errors — Cloudflare Worker

Receives opt-in error reports from the Neon CLI and writes them to a Cloudflare D1 SQLite database.

This Worker is **not** deployed yet. Phase 0 only scaffolds the code; deployment requires Nick's Cloudflare account auth (`wrangler login`).

## Endpoint

`POST /v1/report` — body must match the schema in `schema.sql`. Returns:

| Status | Meaning |
|---|---|
| `200` | Report stored. |
| `400` | Body fails schema validation. |
| `405` | Method other than POST. |
| `415` | Wrong `content-type`. |
| `429` | Rate limit exceeded (per source IP). |
| `500` | D1 insert failed. |

`GET /healthz` returns `200 ok` for liveness checks.

## Privacy

Schema and payload are intentionally narrow:

- `event_at`, `neon_version`, `os`, `arch`, `browser`, `browser_version`, `cdm_version`, `error_category`, `redacted_message`.
- No IP address (Cloudflare strips after rate-limit lookup), no install ID, no usage events.
- Client (`src/reporter.rs`) redacts user paths before sending.

## Deploy (Nick)

```bash
cd cloudflare-worker
npm install
wrangler login                            # one-time
wrangler d1 create neon-errors            # copy database_id into wrangler.toml
wrangler d1 execute neon-errors --file ./schema.sql --remote
wrangler deploy
```

After `wrangler deploy` prints the public URL, set it as the default in `src/reporter.rs` (or via `~/.config/neon/config.toml` `reporting.endpoint`).

## Local dev

```bash
wrangler dev                                                    # http://127.0.0.1:8787
wrangler d1 execute neon-errors --file ./schema.sql --local
curl -XPOST http://127.0.0.1:8787/v1/report \
  -H 'content-type: application/json' \
  -d '{"event_at":"2026-05-04T12:00:00Z","neon_version":"0.1.0","os":"linux","arch":"x86_64","error_category":"NetworkError"}'
```
