// Neon error reporting endpoint.
//
// One route: POST /v1/report
//   - Validates a tightly-scoped JSON schema.
//   - Rate-limits per source IP via Cloudflare's `ratelimit` binding.
//   - INSERTs into the `reports` table in the bound D1 database.
//
// Health check: GET /healthz returns 200 OK.
// Anything else: 404.
//
// No PII is logged or returned. The payload schema is documented in
// schema.sql; the matching client-side struct lives in src/reporter.rs.

interface Env {
    DB: D1Database;
    RATE_LIMITER: { limit: (key: { key: string }) => Promise<{ success: boolean }> };
}

// Allowed values constrain what the client can dump into our table.
const ALLOWED_OS = new Set(["darwin", "linux"]);
const ALLOWED_ARCH = new Set(["x86_64", "aarch64", "arm64"]);
const ALLOWED_CATEGORIES = new Set([
    "PermissionDenied",
    "BrowserRunning",
    "NetworkError",
    "ManifestFetchFailed",
    "HashMismatch",
    "DiskFull",
    "UnknownBundleStructure",
    "DaemonNotRunning",
    "StateCorrupted",
    "UnsupportedPlatform",
    "Other",
]);

// Bound max sizes so a malicious client can't push large strings into D1.
const MAX_FIELD_LEN = 256;
const MAX_MESSAGE_LEN = 2048;
const MAX_BODY_BYTES = 8 * 1024;

interface ReportPayload {
    event_at: string;
    neon_version: string;
    os: string;
    arch: string;
    browser?: string | null;
    browser_version?: string | null;
    cdm_version?: string | null;
    error_category: string;
    redacted_message?: string | null;
}

function jsonError(status: number, message: string): Response {
    return new Response(JSON.stringify({ ok: false, error: message }), {
        status,
        headers: { "content-type": "application/json" },
    });
}

function jsonOk(body: object = { ok: true }): Response {
    return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
    });
}

function isShortString(value: unknown, max = MAX_FIELD_LEN): value is string {
    return typeof value === "string" && value.length > 0 && value.length <= max;
}

function isOptionalShortString(
    value: unknown,
    max = MAX_FIELD_LEN,
): value is string | null | undefined {
    return value === undefined || value === null || isShortString(value, max);
}

function validate(body: unknown): { ok: true; payload: ReportPayload } | { ok: false; error: string } {
    if (typeof body !== "object" || body === null) {
        return { ok: false, error: "body must be a JSON object" };
    }
    const o = body as Record<string, unknown>;

    if (!isShortString(o.event_at)) return { ok: false, error: "event_at: required string" };
    // Cheap RFC3339-ish sanity check; Cloudflare doesn't ship a TZ-aware date parser.
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(o.event_at)) {
        return { ok: false, error: "event_at: not ISO-8601" };
    }
    if (!isShortString(o.neon_version)) return { ok: false, error: "neon_version: required string" };
    if (!isShortString(o.os) || !ALLOWED_OS.has(o.os)) return { ok: false, error: "os: must be darwin|linux" };
    if (!isShortString(o.arch) || !ALLOWED_ARCH.has(o.arch)) {
        return { ok: false, error: "arch: must be x86_64|aarch64|arm64" };
    }
    if (!isOptionalShortString(o.browser)) return { ok: false, error: "browser: invalid" };
    if (!isOptionalShortString(o.browser_version)) return { ok: false, error: "browser_version: invalid" };
    if (!isOptionalShortString(o.cdm_version)) return { ok: false, error: "cdm_version: invalid" };
    if (!isShortString(o.error_category) || !ALLOWED_CATEGORIES.has(o.error_category)) {
        return { ok: false, error: "error_category: not in allowed enum" };
    }
    if (!isOptionalShortString(o.redacted_message, MAX_MESSAGE_LEN)) {
        return { ok: false, error: "redacted_message: invalid (over 2048 chars or wrong type)" };
    }

    return {
        ok: true,
        payload: {
            event_at: o.event_at as string,
            neon_version: o.neon_version as string,
            os: o.os as string,
            arch: o.arch as string,
            browser: (o.browser as string | undefined) ?? null,
            browser_version: (o.browser_version as string | undefined) ?? null,
            cdm_version: (o.cdm_version as string | undefined) ?? null,
            error_category: o.error_category as string,
            redacted_message: (o.redacted_message as string | undefined) ?? null,
        },
    };
}

async function handleReport(req: Request, env: Env): Promise<Response> {
    if (req.method !== "POST") {
        return jsonError(405, "method not allowed");
    }

    const contentType = req.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
        return jsonError(415, "content-type must be application/json");
    }

    const contentLength = req.headers.get("content-length");
    if (contentLength !== null && Number(contentLength) > MAX_BODY_BYTES) {
        return jsonError(413, "payload too large");
    }

    // Per-IP rate limit. Cloudflare provides cf-connecting-ip on every request.
    const clientIp = req.headers.get("cf-connecting-ip") ?? "unknown";
    if (env.RATE_LIMITER) {
        const { success } = await env.RATE_LIMITER.limit({ key: clientIp });
        if (!success) {
            return jsonError(429, "rate limit exceeded");
        }
    }

    let body: unknown;
    try {
        // Cloudflare's req.json() reads up to 100MB by default; we already gated
        // on Content-Length above. If the client sends a chunked body without
        // Content-Length, parse and then re-check size implicitly via field-len caps.
        body = await req.json();
    } catch {
        return jsonError(400, "invalid JSON");
    }

    const v = validate(body);
    if (!v.ok) return jsonError(400, v.error);
    const p = v.payload;

    try {
        await env.DB.prepare(
            `INSERT INTO reports
                (event_at, neon_version, os, arch, browser, browser_version,
                 cdm_version, error_category, redacted_message)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
            .bind(
                p.event_at,
                p.neon_version,
                p.os,
                p.arch,
                p.browser,
                p.browser_version,
                p.cdm_version,
                p.error_category,
                p.redacted_message,
            )
            .run();
    } catch (err) {
        // Don't leak internal errors to clients; log for the operator instead.
        console.error("D1 insert failed:", err);
        return jsonError(500, "internal server error");
    }

    return jsonOk();
}

export default {
    async fetch(req: Request, env: Env): Promise<Response> {
        const url = new URL(req.url);

        if (url.pathname === "/v1/report") {
            return handleReport(req, env);
        }
        if (url.pathname === "/healthz" && req.method === "GET") {
            return new Response("ok", { status: 200 });
        }
        return jsonError(404, "not found");
    },
} satisfies ExportedHandler<Env>;
