-- Neon error reporting — D1 SQLite schema.
--
-- Apply via:
--   wrangler d1 execute neon-errors --file ./schema.sql --remote
-- (or `--local` for local dev).
--
-- Designed to match the JSON payload accepted by POST /v1/report.
-- Schema is intentionally narrow: enough to spot failure-mode trends,
-- nothing that could identify an individual user. No IP, no install ID,
-- no usage events — only error reports.

CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- Client-supplied event timestamp (ISO 8601, UTC). Trusted for dedupe only.
    event_at        TEXT    NOT NULL,
    -- Identification of the Neon build that produced the error.
    neon_version    TEXT    NOT NULL,
    -- "darwin" / "linux".
    os              TEXT    NOT NULL,
    -- "x86_64" / "aarch64".
    arch            TEXT    NOT NULL,
    -- "Helium" / "Thorium" / etc., or NULL if the error is not browser-specific.
    browser         TEXT,
    -- Browser version string as the bundle reports it (e.g. "133.0.6943.99").
    browser_version TEXT,
    -- Widevine CDM version we tried to apply (e.g. "4.10.2710.0").
    cdm_version     TEXT,
    -- One of the spec's ErrorCategory enum variants (PermissionDenied, NetworkError, etc.).
    error_category  TEXT    NOT NULL,
    -- Free-form message with PII redacted by the client.
    redacted_message TEXT
);

-- Trend queries: "how many Permission Denied errors in the last 7 days?"
CREATE INDEX IF NOT EXISTS idx_reports_category_received
    ON reports (error_category, received_at);

-- "What versions are reporting errors?"
CREATE INDEX IF NOT EXISTS idx_reports_neon_version
    ON reports (neon_version, received_at);
