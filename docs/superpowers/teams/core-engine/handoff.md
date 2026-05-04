# Core Engine Team Handoff

**Identity:** `core-engine`
**Mission:** Widevine acquisition + browser detection + atomic patching. Pure Rust logic, no platform-specific syscalls (those live in the Platform team's modules).

## Files owned

- `src/widevine/` — manifest, download, extract, cache management
- `src/browsers/` — known list, auto-discovery, custom-paths config
- `src/patch/mod.rs` — atomic patch protocol (calls into platform impls)
- `src/patch/backup.rs` — snapshot, rollback, atomic rename helpers
- `src/lockfile.rs` — flock-based concurrent-patch protection
- `src/error.rs` — categorized error type
- `src/lib.rs` — library entrypoint that re-exports the above
- `src/config.rs` — global TOML config schema (jointly with CLI team; CLI consumes it from Phase 4)

## Current focus

**Phase 1 complete.** All seven deliverables landed; awaiting Phase 2 kickoff (Widevine download/extract + atomic patch + Platform team's per-OS impls).

## Phase 1 deliverables — status

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | Manifest parsing module | done | `src/widevine/manifest.rs` + `src/widevine/mod.rs`. Parses real Mozilla schema; URL fallback chain (hg.mozilla.org → GitHub mirror → on-disk cache w/ 24h TTL); `Platform` enum for Linux/Darwin keys; alias chain resolution bounded to 8 hops; tested against committed fixture + in-process HTTP stub server. |
| 2 | Browser detection (known + auto-discovery + custom) | done | `src/browsers/{mod,known,discovery}.rs`. `Browser` struct + `BrowserKind` (Known/Detected/Custom) + `Os::current()`. Hardcoded list for Helium/Thorium/uChromium/Chromium per spec. Process-based discovery scaffold (returns empty `Vec` in Phase 1; Phase 2 wires sysinfo). Tested with synthesized `tempfile::TempDir` filesystems. |
| 3 | Custom-paths TOML config | done | `src/config.rs`. Schema matches spec verbatim; uses `serde(default, deny_unknown_fields)` so typos surface immediately; `~` expansion for hook paths. Round-trip tested. |
| 4 | Categorized error type | done | `src/error.rs`. All 11 categories from spec + `Other`; `From` impls for `io::Error`, `serde_json::Error`, `toml::de::Error`, `reqwest::Error`. `Display` renders as `"<Category>: <message>"`. `as_str()` is committed API for the Worker schema. |
| 5 | Lockfile module | done | `src/lockfile.rs`. `with_lock` (blocking) + `try_with_lock` (non-blocking) helpers. Concurrent-acquisition test spawns 8 threads and observes a max-in-flight of 1. |
| 6 | Test fixtures | done | `tests/fixtures/widevinecdm.json` (real Mozilla manifest, 78 lines). Synthesized Applications/opt trees built in tests via `tempfile`. |
| 7 | Tests passing at >=80% line coverage | done | **95.38%** line coverage on owned modules (tarpaulin output below). 78 unit tests + 4 integration tests + 1 doc-test, all passing. fmt + clippy `-D warnings` clean. cargo-deny + cargo-audit clean. |

## Public contracts owned

These are the interfaces Phase 2 (Platform team's `patch::linux` / `patch::macos`, plus the CLI team's command implementations) will consume. **Don't reach into module internals — these are the stable surface.**

```rust
// src/error.rs
pub type Result<T> = std::result::Result<T, Error>;
pub struct Error { pub category: ErrorCategory, pub message: String, pub source: Option<...> }
pub enum ErrorCategory {
    PermissionDenied, BrowserRunning, NetworkError, ManifestFetchFailed,
    HashMismatch, DiskFull, UnknownBundleStructure, DaemonNotRunning,
    StateCorrupted, UnsupportedPlatform, Other,
}
impl Error {
    pub fn new(category: ErrorCategory, message: impl Into<String>) -> Self;
    pub fn with_source<E>(self, source: E) -> Self;
    // + variant-specific helpers: permission_denied, browser_running,
    //   network, manifest_fetch_failed, hash_mismatch, disk_full,
    //   unknown_bundle_structure, daemon_not_running, state_corrupted,
    //   unsupported_platform, other.
}
impl ErrorCategory { pub fn as_str(self) -> &'static str; }

// src/widevine/manifest.rs (re-exported from src/widevine/mod.rs)
pub fn fetch_manifest() -> Result<Manifest>;
pub fn fetch_manifest_with(urls: &[Url], cache: Option<&Path>, ttl: Duration) -> Result<Manifest>;
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest>;
pub fn current_platform_key() -> Result<Platform>;
pub fn cached_manifest_path() -> Option<PathBuf>;
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub struct Manifest { pub vendors: HashMap<String, GmpVendor>, ... }
pub struct GmpVendor { pub platforms: HashMap<String, PlatformEntry>, pub version: String }
pub enum PlatformEntry {
    Concrete { file_url, mirror_urls, filesize, hash_value },
    Alias { alias },
}
pub enum Platform { LinuxX86_64, DarwinAarch64, DarwinX86_64 }
impl Manifest {
    pub fn widevine(&self) -> Result<&GmpVendor>;
    pub fn resolve_platform(&self, p: Platform) -> Result<&PlatformEntry>;
    pub fn resolve_platform_key(&self, key: &str) -> Result<&PlatformEntry>;
}

// src/browsers/mod.rs
pub fn detect_browsers() -> Result<Vec<Browser>>;
pub fn detect_browsers_with(os: Os, roots: &FilesystemRoots, cfg: &Config) -> Vec<Browser>;
pub struct Browser {
    pub name: String,
    pub install_path: PathBuf,
    pub kind: BrowserKind,
    pub framework_name: Option<String>, // macOS only
}
impl Browser {
    pub fn name(&self) -> &str;
    pub fn install_path(&self) -> &Path;
    pub fn is_patched(&self) -> bool; // Phase 1 stub: always false
}
pub enum BrowserKind { Known, Detected, Custom }
pub enum Os { Linux, Macos }
impl Os { pub fn current() -> Option<Self>; }
pub struct FilesystemRoots {
    pub macos_applications: Vec<PathBuf>,
    pub linux_search: Vec<PathBuf>,
    pub sandbox_root: Option<PathBuf>, // tests use this; production leaves None
}
impl FilesystemRoots { pub fn default_for(os: Os) -> Self; }

// src/browsers/known.rs
pub struct KnownBrowser {
    pub name: &'static str,
    pub macos_framework: &'static str,
    pub linux_paths: &'static [&'static str],
}
pub const KNOWN: &[KnownBrowser];
pub const KNOWN_LINUX: &[KnownBrowser]; // alias for KNOWN
pub const KNOWN_MACOS: &[KnownBrowser]; // alias for KNOWN
pub fn known_for_os(os: Os, roots: &FilesystemRoots) -> Vec<Browser>;

// src/browsers/discovery.rs
pub fn discover_filesystem(os: Os, roots: &FilesystemRoots) -> Vec<Browser>;
pub fn discover_processes() -> Vec<Browser>; // Phase 1 stub: empty Vec

// src/config.rs
pub fn load_config() -> Result<Config>;
pub fn load_config_from(path: &Path) -> Result<Config>;
pub fn default_config_path() -> Option<PathBuf>;
pub struct Config {
    pub notifications: NotificationsConfig,
    pub reporting: ReportingConfig,
    pub browsers: Vec<CustomBrowserConfig>,
    pub hooks: HooksConfig,
}
impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self>;
    pub fn to_toml_string(&self) -> Result<String>;
    pub fn post_patch_hook(&self) -> Option<PathBuf>;
    pub fn post_update_hook(&self) -> Option<PathBuf>;
}
pub struct NotificationsConfig { pub on_success: bool, pub on_failure: bool }  // both default true
pub struct ReportingConfig { pub opt_in_error_reporting: bool, pub endpoint: Option<String> }  // both default off/None
pub struct CustomBrowserConfig {
    pub name: String,
    pub bundle_path: Option<PathBuf>,    // macOS
    pub framework_name: Option<String>,  // macOS
    pub install_path: Option<PathBuf>,   // Linux
}
pub struct HooksConfig {
    pub post_patch: Option<String>,  // ~ expansion via Config::post_patch_hook
    pub post_update: Option<String>,
}

// src/lockfile.rs
pub fn with_lock<T, F>(path: &Path, f: F) -> Result<T>
where F: FnOnce() -> Result<T>;
pub fn try_with_lock<T, F>(path: &Path, f: F) -> Result<Option<T>>
where F: FnOnce() -> Result<T>;
```

## Decisions log

- **2026-05-04** — Library + binary split: phase 0 was binary-only, but phase 1 modules need to be testable (integration tests in `tests/`) and consumable by future binary entrypoints (the daemon mode in Phase 3 will likely be a separate `[[bin]]`). Added `[lib]` target alongside `[[bin]]`; no source-level changes to the existing `main.rs`.
- **2026-05-04** — `FilesystemRoots::sandbox_root` chroot-style prefix: tests need to assert against synthesized fixtures without the dev machine's real `/opt/helium-browser-bin` (which exists on Nick's machine) masking them. The known-list resolver consults `sandbox_root` when set, otherwise falls back to literal absolute paths. Production callers leave `sandbox_root: None`. The leaf-rebase trick from the first iteration was scrapped because it caused false positives (e.g. `/opt/chromium` matching an unrelated `chromium` dir under any walk root).
- **2026-05-04** — `Platform` enum vs. raw strings: the live Mozilla schema uses `Darwin_x86_64-gcc3-u-i386-x86_64` as the "real" key with `Darwin_x86_64-gcc3` as an alias. We expose `Platform::DarwinX86_64 = "Darwin_x86_64-gcc3-u-i386-x86_64"` to match the canonical form, but `Manifest::resolve_platform_key` follows aliases either direction transparently.
- **2026-05-04** — `current_platform_key()` uses `cfg!`-guarded early returns rather than `cfg!()` macros so each branch compiles in isolation. `clippy::needless_return` is `#[allow]`'d locally with a comment explaining why.
- **2026-05-04** — `process-based discovery` ships as a stub that returns an empty `Vec<Browser>`. Stable signature, zero behavior. Phase 2 will wire `sysinfo` here without breaking any caller.
- **2026-05-04** — `Browser::is_patched()` is a Phase 1 stub returning `false`. Phase 2 will replace this with a real check against the patched CDM directory.
- **2026-05-04** — `serde(deny_unknown_fields)` on the config schema so config typos fail loudly. Costs us slight forward-compat (old binaries reject configs from newer binaries) but the upside is "I typo'd `notifaction` and now nothing works" gets caught immediately.
- **2026-05-04** — `CDLA-Permissive-2.0` license added to `deny.toml`'s allow-list. Unavoidable transitive dep (`webpki-roots` via `reqwest` + `rustls-tls`), and the spec mandates rustls.
- **2026-05-04** — Manifest cache write-back is best-effort: a successful network fetch returns success even if writing the cache file fails. The user has the data they asked for; cache hygiene is a "next time" concern.

## Open questions

(none)

## Dependencies awaiting

### From Platform team (Phase 2)

- `src/patch/linux.rs` — Linux WidevineCdm placement under `<install_path>/WidevineCdm/`.
- `src/patch/macos.rs` — macOS bundle write into `<install_path>/Contents/Frameworks/<framework_name>.framework/Versions/<n>/Libraries/WidevineCdm/`, plus `xattr -cr` and ad-hoc codesign.

The Phase 2 patch protocol (defined in `src/patch/mod.rs`, owned by core-engine) will call these via a small trait, e.g.:

```rust
// Sketch — final shape decided in Phase 2.
pub trait PlatformPatcher {
    fn place_cdm(&self, browser: &Browser, cdm_source: &Path) -> Result<()>;
    fn finalize_bundle(&self, browser: &Browser) -> Result<()>;  // xattr + codesign on macOS, no-op on Linux
}
```

### From Infra team (already complete in Phase 0)

CI matrix runs on every push to `v2-rust-rewrite`. No outstanding asks.

## Verification (local, all green on Linux)

```bash
cargo fmt --all -- --check                                # clean
cargo clippy --all-targets --all-features -- -D warnings  # clean
cargo test                                                # 78 unit + 4 integration + 1 doc = 83 passing
cargo build --release                                     # binary built
cargo doc --no-deps --lib                                 # zero warnings
cargo deny check bans licenses sources                    # ok ok ok
cargo audit                                               # 0 vulnerabilities
cargo tarpaulin --exclude-files 'src/main.rs'             # 95.38% line coverage on owned modules
```

CI on `v2-rust-rewrite` runs the same matrix on macOS + Linux for every push.

## Coverage breakdown (cargo-tarpaulin, excluding `src/main.rs`)

```
src/browsers/discovery.rs : 65/66 lines
src/browsers/known.rs     : 35/35 lines
src/browsers/mod.rs       : 36/38 lines
src/config.rs             : 28/30 lines
src/error.rs              : 62/68 lines
src/lockfile.rs           : 28/30 lines
src/widevine/manifest.rs  : 76/79 lines
                          : 330/346 (95.38%)
```

Spec target: ≥80% in Phase 1, ≥90% on patch/manifest paths by ship time. We already hit the latter for manifest.

## Files most recently changed

- `src/error.rs` (new — categorized error type)
- `src/lockfile.rs` (new — flock helper)
- `src/config.rs` (new — TOML schema)
- `src/widevine/{mod,manifest}.rs` (new — manifest parse + URL chain)
- `src/browsers/{mod,known,discovery}.rs` (new — detection)
- `src/lib.rs` (new — library entrypoint re-exporting the above)
- `tests/fixtures/widevinecdm.json` (new — real Mozilla manifest)
- `tests/manifest_integration.rs`, `tests/browsers_integration.rs` (new — integration tests)
- `Cargo.toml` (added Phase 1 deps + `[lib]`)
- `Cargo.lock` (new lockfile after dep additions)
- `deny.toml` (added `CDLA-Permissive-2.0` for `webpki-roots`)

## Commits on `v2-rust-rewrite` from Phase 1

```
feat(crate): split into lib + bin and add Phase 1 dependencies
feat(error): categorized error type with stable variant names
feat(lockfile): flock-based exclusive lock helper
feat(config): TOML schema for ~/.config/neon/config.toml
feat(widevine): manifest parsing + URL fallback chain
feat(browsers): known list, auto-discovery, and custom-config detection
test(integration): manifest fixture + browser detection pipelines
```
