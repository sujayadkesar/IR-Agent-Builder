# DFIR Agent Builder

> Velociraptor-class triage collector compiler — point-and-click UI, AWS S3 / KMS write-only uploads, single-binary Rust collector. Built for mass GPO deployment.

![architecture](docs/architecture.svg)

## What this is

An IR engineering tool that lets a team:

1. **Visually pick** which forensic artifacts to acquire (Prefetch, Amcache, Registry hives, EVTX, MFT, Memory dump, KAPE-style targets, browser, cloud, persistence — see the full catalog in [`builder-server/src/lib/catalog.js`](builder-server/src/lib/catalog.js)).
2. **Configure where evidence lands** — AWS S3 (multipart, SSE-KMS, write-only IAM) or local/UNC.
3. **Click Build** and get a single hardened `Collector.exe` whose embedded config has the artifact list, encryption keys, and upload credentials baked in at compile time.
4. **Push the EXE** through GPO startup script / SCCM / Intune to thousands of endpoints. It runs once, drops triage into S3, and exits.

It is a clean-room reimplementation of Velociraptor's "Offline Collector Builder" idea, with three deliberate differences:

| | Velociraptor | This tool |
|-|--------------|-----------|
| Embed model | Patches a YAML blob into a reserved 80KB section of the prebuilt binary | Each build is a fresh Rust compilation with config baked in via `include_bytes!` — **no size limit, no signature mismatch** |
| Detection footprint | Endpoints see a known Velociraptor binary signature | Each build is a unique binary; no shared static signatures |
| Dependency | Requires the Velociraptor binary on the build host | Pure Rust + Node, no third-party runtime download |
| Encryption | X509 / PGP wrapping | Same hybrid scheme: RSA-OAEP-SHA256 wraps a per-run AES-256-GCM key |

Velociraptor is excellent and battle-tested — this tool stands on its shoulders. See [docs/research-summary.md](docs/research-summary.md) for the full design rationale.

## Architecture

```
┌────────────────────┐    REST/SSE     ┌────────────────────┐    cargo build    ┌────────────────────┐
│  React + Vite UI   │ ───────────────▶│  Node.js / Express │ ─────────────────▶│  Rust Collector    │
│  (cyberdark theme) │  /api/build     │  build orchestrator│  embeds JSON cfg  │  → Collector.exe   │
└────────────────────┘                 └────────────────────┘                   └────────────────────┘
                                                │
                                                ▼ better-sqlite3
                                       ┌────────────────────┐
                                       │  Audit ledger      │
                                       │  (no secrets)      │
                                       └────────────────────┘
```

**Three components:**

- **`builder-ui/`** — React + Vite + TypeScript + Tailwind. 6-step wizard. Live size/time estimator. AWS connection validator + IAM policy generator.
- **`builder-server/`** — Node.js + Express. Generates RSA-4096 keypairs. Validates S3 connectivity. Spawns `cargo build` and streams the log over Server-Sent Events. Records every build in a SQLite audit ledger.
- **`collector/`** — Rust binary. Single-shot; drops triage to S3 or local. ~2.5 MB stripped release binary.

## Quick start (dev)

Prerequisites: Node 20+, Rust stable, Windows 10/11 host (for the collector to actually run; you can build cross-platform).

```bash
# 1. Backend
cd builder-server
npm install
npm start            # listens on :8787

# 2. UI (separate terminal)
cd builder-ui
npm install
npm run dev          # opens http://localhost:5173 with /api proxy
```

That's it. Open the UI, run through the 6 steps, click **BUILD COLLECTOR**, and the resulting `Collector_<id>.exe` will be downloadable from the page.

## Collector lifecycle

Each Collector.exe, when run on an endpoint, performs:

1. Verify it has admin token (manifest forces UAC; runtime check is defence in depth).
2. Parse embedded JSON config (compiled in — not on disk).
3. Create scratch dir under `%TEMP%\dfir-<id>\`.
4. **Take a VSS snapshot of C:\\** so locked Registry hives and EVTX are readable.
5. Run each enabled artifact module:
   - File-pattern artifacts → glob from VSS root, copy to scratch.
   - Live artifacts → shell out to native tools (`netstat`, `tasklist`, `ipconfig`, `wmic`, `netsh`) and capture stdout/stderr.
   - Memory dump → invoke `winpmem.exe` if present alongside collector.
6. Pack scratch into a ZIP container (DEFLATE).
7. **Encrypt** the ZIP with AES-256-GCM, wrap the key with RSA-OAEP-SHA256, write `[magic][hdr_len][hdr_json][ciphertext]`.
8. **Upload** to S3 (PutObject ≤100MB, multipart for larger) with SSE-KMS, or copy to local/UNC.
9. Securely overwrite + delete plaintext zip and scratch.
10. Exit with code 0 on success, 1 on any unrecoverable failure.

Total runtime: 5-15 min for QuickTriage; 30-60 min for SANS Triage; 1-4 hr for Deep Dive.

## Bundle presets (matching §2.10 of research)

| Preset | Artifacts | Time | Size |
|--------|-----------|------|------|
| **Quick Triage** | Execution evidence + live network + EVTX (last 7d) + persistence | 5-15 min | ~200 MB |
| **SANS / KAPE Triage** | + Full Registry + all EVTX + browser + jump lists + RDP cache | 30-60 min | 1-3 GB |
| **Deep Dive** | + Full MFT/USN + RAM dump + Outlook OST/PST + Teams | 1-4 hr | 5-20 GB |
| **Threat Hunt** | Targeted: live net + persistence + Sysmon + PowerShell | 15-30 min | ~500 MB |

## AWS production setup

The IR engineer creates **once**, then every build references these:

1. **Dedicated forensics AWS account** (separate from prod).
2. **S3 bucket** with: versioning ON, Object Lock COMPLIANCE mode (365-day retention), SSE-KMS with CMK, deny non-HTTPS, deny DeleteObject from everyone (incl. root), CloudTrail logging.
3. **KMS Customer Managed Key** (multi-region if collecting across regions). Annual rotation. Separate "key admin" vs "key user" identities.
4. **Per-build IAM user** named `dfir-collector-<build-id>`, **write-only** policy from the wizard's "Generate IAM Policy" button. Access key 90-day expiry. Tag with build metadata.
5. **Read-only IR analyst role** (assumed via SSO + MFA) with `s3:GetObject`, `kms:Decrypt`. Source-IP-restricted to corporate VPN.

The wizard generates the IAM policy JSON for you — paste it into the IAM console.

See [docs/aws-setup.md](docs/aws-setup.md) for the full walkthrough.

## GPO deployment

Two deployment patterns:

**1. Startup script (recommended)** — runs as `NT AUTHORITY\SYSTEM`, satisfying the admin requirement automatically:

```powershell
# In Group Policy Management:
# Computer Configuration → Policies → Windows Settings → Scripts → Startup
# Add Script: \\fileserver\IRTools\Collector_a3f9b221.exe
```

**2. SCCM / Intune** — wrap as a Win32 app with a registry-key detection rule (the collector writes `HKLM\Software\DFIR\LastRun` on completion).

The collector's `silent` mode (default) suppresses all UI; the only artifact left on the endpoint after a successful run is the log entry in `%TEMP%\dfir-collector-fatal.log` (only on failure) and the registry detection key.

## Encrypted container format

```
+----------------+--------+--------------+---------------------+----------------------+
| "DFIR" (4 B)   | v (1B) | hdr_len (4B) | header_json (N B)   | AES-GCM ciphertext   |
+----------------+--------+--------------+---------------------+----------------------+
                                                                ↑
                                       (nonce is in header.nonce_b64 — 12 bytes)
```

The header JSON contains the wrapped AES key and is **AAD-bound** to the ciphertext, so any tampering with the header will fail authentication. See [docs/decrypt.md](docs/decrypt.md) for an analyst-side decryption helper script.

## Repo layout

```
agentbuilder/
├── builder-ui/                  React + Vite UI (the wizard)
│   ├── src/
│   │   ├── App.tsx              ← entry, stepper, footer
│   │   ├── components/steps/    ← Step1Target.tsx ... Step6Review.tsx
│   │   ├── components/ui/       ← Card, Form (Field/Input/Select/Toggle)
│   │   └── lib/                 ← types, api, bundles
│   └── ...
│
├── builder-server/              Node Express orchestrator
│   ├── src/
│   │   ├── server.js            ← /api/build, /api/keypair/generate, SSE log stream
│   │   └── lib/
│   │       ├── catalog.js       ← artifact + bundle catalog
│   │       ├── aws.js           ← IAM policy generator + S3 connection validator
│   │       └── ledger.js        ← SQLite audit ledger
│   └── ...
│
├── collector/                   Rust collector (single-binary EXE)
│   ├── Cargo.toml
│   ├── build.rs                 ← embeds admin manifest into PE
│   └── src/
│       ├── main.rs              ← lifecycle (admin → VSS → artifacts → encrypt → upload)
│       ├── config.rs            ← embedded config struct (compile-time JSON)
│       ├── elevation.rs         ← Windows admin token check
│       ├── logging.rs
│       ├── report.rs            ← run_report.json
│       ├── vss/                 ← VSS snapshot via vssadmin + mklink junction
│       ├── artifacts/
│       │   ├── mod.rs           ← dispatcher (one match arm per artifact id)
│       │   ├── patterns.rs      ← glob-based file collection (VSS-aware)
│       │   ├── live.rs          ← netstat / pslist / wmic / etc.
│       │   └── kape.rs          ← KAPE-style target catalog
│       ├── crypto/
│       │   ├── mod.rs           ← secure_delete
│       │   └── x509.rs          ← AES-GCM + RSA-OAEP hybrid encrypt
│       ├── upload/
│       │   ├── mod.rs           ← dispatch (s3 / local)
│       │   └── s3.rs            ← SigV4 + multipart
│       └── zipper.rs
│
├── docs/
│   ├── architecture.svg
│   ├── aws-setup.md
│   ├── decrypt.md
│   └── research-summary.md
│
└── builds/                      ← per-build output (gitignored)
```

## Beyond Velociraptor — what's next

The current build is an MVP. Production roadmap:

- **Code signing pipeline** — AzureSignTool integration for EV cert signing of every build.
- **Native artifact parsers** — direct `parse_evtx`, `parse_prefetch`, `parse_mft` instead of raw file copy (smaller container, faster analyst workflow).
- **AWS Transfer Family SFTP option** — embeds an SSH private key instead of AWS access key, eliminating credential exposure entirely.
- **STS temporary credentials** — replace static IAM keys with short-lived STS tokens via an internal credential broker.
- **Configurable EDR exclusion path** — reads HKLM\Software\DFIR\ExclusionPath at runtime so the build doesn't need to know it.
- **Differential collection** — `Collector --since 2026-04-01` for follow-up acquisitions.
- **In-process memory acquisition** — drop the winpmem.exe sidecar; use a kernel driver compiled into a separate signed `.sys`.

## Security caveats (read this)

- Embedded AWS keys can be extracted from any binary. The IAM policy must be **write-only**, scoped by `${aws:username}` prefix, and the bucket must have Object Lock so even a stolen key cannot tamper with collected evidence. See `aws.js` `generateIamPolicy()`.
- The X509 private key from Step 4 is generated on the backend, returned once, and **not persisted**. If you lose it, every collection from that build is unrecoverable. Push it into AWS Secrets Manager / HashiCorp Vault immediately.
- VSS snapshots take a few seconds. Production servers under heavy I/O may briefly stall — schedule via GPO for off-hours where possible.
- Memory dumps require `winpmem.exe` alongside the collector and a kernel driver load. Some EDRs flag this — code-sign the collector and add to the AV exclusion list.

## License

Internal — DFIR engineering use only.
