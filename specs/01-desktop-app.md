# Spec 01: Native desktop app (Pro/Team tier feature)

**Status:** deferred from 2026-04-28 sprint
**Effort:** multi-week (3-5 weeks for v1)
**Revenue impact:** high — desktop app is bundled into Pro $39/mo + Team $59/seat/mo per the marketing copy committed 2026-04-28

## Goal

Ship a native desktop app for macOS, Windows, and Linux that wraps the
existing pentest-tools dashboard plus the CLI plus a Pro/Team subscription
license check. Sold as part of Pro tier ($39/mo includes both the SaaS
web access AND the desktop app).

Done means:
- Signed installers for the three platforms downloadable from
  pentest-tools.local/download
- App auto-updates from a Cloudflare Worker release feed
- License check on launch against app.pentest-tools.local
- Bundled `pttools` CLI accessible from the user's PATH after install
- The dashboard at /dashboard/ runs against either local `pttools serve` or
  a configured remote app.pentest-tools.local tenant
- Privacy-first solos can run the app fully offline, never touching any
  cloud service except the license refresh ping (every 7 days)

## Tech choice

**Tauri** (not Electron). Reasons:
- 5-10MB final binary vs Electron's 80-150MB
- Native webview (WebKit on macOS, Edge WebView2 on Windows, WebKitGTK on
  Linux) so we use the same dashboard code that already ships in the OSS
- Rust shell gives us proper code signing, auto-update, system tray, and
  filesystem permissions without the Chromium tax
- Lower memory footprint for users running it as a daily driver

Alternative: Electron if the team prefers JS-only. Sacrifice 50-100MB
per install for development familiarity.

## Inputs (what already exists)

- `api/static/index.html`, `api/static/dashboard.css`, `api/static/dashboard.js` —
  the dashboard, ready to be loaded by Tauri's webview
- `api/server.py` — REST + WebSocket surface; runs as the embedded
  backend the desktop app talks to
- `cli/main.py` with `pttools serve` already wires the API up
- `engine/telemetry.py` — opt-in usage analytics primitive
- `engine/tracing.py` — observability hooks
- The marketing site already advertises "Native desktop app · macOS,
  Windows, Linux" as a Pro feature

## License model

**Subscription tied:** the desktop app calls
`https://api.pentest-tools.local/v1/license/check` on launch and every 7 days.
The endpoint:
- Authenticates with a long-lived per-install token issued at first login
- Returns 200 + `{plan: "pro" | "team", expires_at: <iso>}` if the
  subscription is active
- Returns 402 if expired
- Returns 451 if the account is suspended

Grace period: 14 days of cached license validity if the network is
unreachable. After that the app falls back to OSS-only mode (CLI works,
dashboard works, but cloud sync features are disabled).

**Privacy:** the license check sends only the per-install token. It does
NOT send engagement data, target URLs, findings, or hardware fingerprints.

## Steps

### Phase 1: Tauri scaffold (week 1)

1. `cargo install create-tauri-app`
2. Init project as `pentest-tools-desktop` with the Rust + HTML+JS template
3. Set `tauri.conf.json` to load `api/static/index.html` as the
   front-end. Bundle the static dashboard files into the resources dir.
4. Add a Rust command `start_local_api()` that spawns `pttools serve` as
   a subprocess on a free local port and returns the port to JS.
5. Add a Rust command `stop_local_api()` for clean shutdown.
6. Wire the dashboard JS to call these via `@tauri-apps/api`.
7. Manual sanity: launch the app, dashboard renders, can talk to the
   embedded API.

### Phase 2: License + auto-update (week 2)

1. Add a license check Rust module that calls
   `api.pentest-tools.local/v1/license/check`.
2. Persist the token in the OS keychain (macOS Keychain, Windows
   Credential Manager, Linux Secret Service via `keyring` crate).
3. On first launch, present a login screen that exchanges
   email+password (or OAuth code) for a license token via
   `api.pentest-tools.local/v1/license/issue`.
4. Add Tauri's built-in auto-update against a Cloudflare R2-hosted
   release feed signed with the team's release key.

### Phase 3: Local-first / cloud-sync toggle (week 3)

1. Settings page: "Where do findings live?" — Local only / Sync to
   app.pentest-tools.local.
2. Local mode keeps the existing SQLite findings DB pattern.
3. Sync mode uploads each finding to `api.pentest-tools.local/v1/findings` on
   completion. Fully optional. Privacy-first solos leave it off.
4. Sync mode includes a "what's sent" panel showing the exact payload
   schema so users can audit it.

### Phase 4: Code signing + distribution (week 4-5)

1. Apple Developer ID + Notarization for macOS (~$99/year + signing CI)
2. Windows EV cert ($300-500/year + signing CI). Without EV the app gets
   SmartScreen warnings for the first ~3000 installs.
3. Linux: AppImage + Flatpak + Snap. Self-signed; users on Linux are
   used to verifying checksums.
4. GitHub Actions release workflow: build all 3 platforms in parallel,
   sign in matrix jobs, upload to a Cloudflare R2 bucket, update the
   release feed, post to Discord.

### Phase 5: Beta then GA

1. Private beta to existing Pro/Team customers (waitlist signup form on
   pentest-tools.local/desktop)
2. 2-week beta with telemetry on (opt-in)
3. Address top 5 bug reports
4. GA release announcement

## Validation

- `pentest-tools-desktop` binary launches under 2 seconds on M-series Mac
  and modern Windows
- Final installer size: under 30MB on macOS, under 25MB on Windows,
  under 40MB on Linux
- License check round-trip: under 500ms
- App memory at idle: under 200MB
- Dashboard loads in under 1 second on first launch
- All Playwright e2e tests from the OSS dashboard pass against the
  embedded webview
- Auto-update from version N to N+1 succeeds in CI

## Out of scope (explicit non-goals)

- iOS / Android (different scope, Pro mobile features ship via PWA on
  app.pentest-tools.local)
- Cross-platform clipboard sync between desktop instances
- Plugin system (deferred to v2)
- Built-in browser for the BrowserAgent (use system browser via tauri's
  shell.open)

## Open questions for the user

- Tauri vs Electron preference?
- Apple Developer account in your org's name or your personal account?
- Windows EV cert budget approved?
- AUR / Flatpak / Snap — pick which Linux channels matter
- Pricing communication: is this ALWAYS bundled in Pro, or also a
  one-time purchase option for users who want lifetime ownership?

## How to resume

Paste this spec's content as the prompt for the next session. Start with
Phase 1 (Tauri scaffold) — that's a 2-3 day chunk that's mostly
mechanical and low-risk.
