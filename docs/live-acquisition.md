# Live acquisition strategy

How this collector handles **locked files on a running endpoint** — the
exact problem that bit us in the 2026-05-07 02:41 run when every
registry hive failed with `os error 32 (sharing violation)`.

## The problem

The Windows kernel keeps several files open with `FILE_SHARE_NONE` while
the system is running. These include:

| File | Purpose | Why it's locked |
|------|---------|-----------------|
| `Windows\System32\config\SAM` | Local user accounts + password hashes | Loaded as `HKLM\SAM`, kernel holds an exclusive handle |
| `Windows\System32\config\SECURITY` | LSA secrets, cached domain creds | Loaded as `HKLM\SECURITY` |
| `Windows\System32\config\SOFTWARE` | Installed software, autorun keys, OS info | Loaded as `HKLM\SOFTWARE` |
| `Windows\System32\config\SYSTEM` | Services, drivers, network, ShimCache | Loaded as `HKLM\SYSTEM` |
| `Users\<u>\NTUSER.DAT` | Per-user profile (UserAssist, RunMRU, TypedURLs) | Loaded as `HKU\<sid>` while user logged in |
| `Users\<u>\AppData\Local\Microsoft\Windows\UsrClass.dat` | Per-user shellbags, COM registrations | Loaded as `HKU\<sid>_Classes` |
| `Windows\AppCompat\Programs\Amcache.hve` | First-execution record per binary | Sometimes held by `CompatTelRunner.exe` |
| `$MFT`, `$LogFile`, `$Extend\$UsnJrnl` | NTFS metadata | Always exclusively held by the kernel |
| `pagefile.sys`, `hiberfil.sys` | Swap + hibernation | Always exclusively held |

A naive `CreateFile(path, GENERIC_READ, FILE_SHARE_READ)` returns
`ERROR_SHARING_VIOLATION (32)` for every one of these. That's exactly what
KAPE, FTK Imager, RawCopy.exe, Velociraptor, Binalyze AIR, and CrowdStrike
Falcon Forensics all have to solve.

## How professional tools solve it (industry survey)

| Tool | Approach | Reference |
|------|----------|-----------|
| **Velociraptor** | Auto accessor: try OS API; on failure, use raw NTFS parser via the `ntfs` Go package. Also offers VSS-based artifacts. | [docs](https://docs.velociraptor.app/docs/forensic/filesystem/ntfs/) |
| **KAPE** (Eric Zimmerman) | Two paths: (a) `--vss` flag triggers VSS snapshot, copy from snapshot; (b) for individual files KAPE can shell out to `RawCopy.exe` (Joakim Schicht) | RawCopy = NTFS parser + `\\.\C:` raw read |
| **FTK Imager** | Same as RawCopy: parse `\\.\C:`, walk MFT, extract data runs | Closed source but documented |
| **Binalyze AIR** | "Off-Network Responder" agent uses VSS for snapshot collection + raw FS extraction for in-use files | [Binalyze docs](https://kb.binalyze.com/air/features/acquisition) |
| **CrowdStrike Falcon Forensics Collector** | Kernel driver for direct disk access (vendor-only); plus VSS + native API | Closed source |
| **Mimikatz / impacket secretsdump** | `RegSaveKey()` API call with `SeBackupPrivilege` — asks the kernel to flush the loaded hive | [Praetorian writeup](https://www.praetorian.com/blog/how-to-detect-and-dump-credentials-from-the-windows-registry/) |
| **Microsoft Defender for Endpoint Live Response** | Native APIs + their own kernel driver | Vendor-only |

The common pattern: **layered fallbacks**. No single technique works
everywhere — VSS isn't available on Home edition, raw NTFS doesn't work on
ReFS volumes, native APIs work for some file types but not others. The
right answer is to try them in order from cheapest-and-strictest to most
expensive-and-universal.

## What this collector does (the ladder)

For every file the collector tries to acquire, it walks this ladder:

```
        ┌──────────────────────────────────────────────┐
        │ 1. std::fs::copy(src, dst)                   │   handles  ✓ unlocked files
        └──────────────────────────────────────────────┘
                         │ ERROR_SHARING_VIOLATION (32)
                         ▼
        ┌──────────────────────────────────────────────┐
        │ 2. CreateFile(FILE_SHARE_READ|WRITE|DELETE)  │   handles  ✓ files w/ shared-write
        │    with FILE_FLAG_BACKUP_SEMANTICS           │           ✓ files w/ tolerant locks
        └──────────────────────────────────────────────┘
                         │ still error 32
                         ▼
        ┌──────────────────────────────────────────────┐
        │ 3. Raw NTFS read of \\.\C:                   │   handles  ✓ EVERYTHING (registry,
        │    via the `ntfs` crate                      │              $MFT, pagefile, …)
        └──────────────────────────────────────────────┘
                         │ very rare failure (ReFS, encrypted)
                         ▼
                   Log + skip
```

In addition, a **VSS snapshot** can be taken at the start of the run via
PowerShell + WMI `Win32_ShadowCopy::Create()`. When successful, all
file-pattern artifacts read from the snapshot path instead of `C:\` —
files in the snapshot aren't locked, so step 1 of the ladder succeeds for
everything.

For **registry hives specifically**, the collector also runs a
`reg save HKLM\SAM …` call (which uses `RegSaveKeyExW` internally with
`SeBackupPrivilege`). This is the same technique impacket and Mimikatz
use, and it gets the **live** hive state — not the file-on-disk state,
which can be hours stale because the kernel buffers writes.

## Strategy summary by artifact type

| Artifact | Primary | Fallback 1 | Fallback 2 |
|----------|---------|------------|------------|
| `registry.hives` | `reg save` (live state) | VSS snapshot file copy | Raw NTFS |
| `execution.amcache` | `reg load`+`reg save` (live) | VSS file copy | Raw NTFS |
| `filesystem.mft` | Raw NTFS read of `\\.\C:` (always — `$MFT` is NEVER unlockable via APIs) | — | — |
| `eventlogs.*` | Shared read (works on .evtx — they ALLOW `FILE_SHARE_READ`) | VSS file copy | Raw NTFS |
| `filesystem.lnk` | Direct copy (these are user files, not OS-locked) | — | — |
| `execution.prefetch` | Direct copy (.pf files allow shared-read) | — | — |
| `live.netstat`, `live.pslist` etc. | Native Windows tools (`netstat`, `tasklist`, `wmic`, `netsh`) — no file system involved | — | — |
| `memory.fulldump` | `winpmem.exe` (kernel driver) | — | — |

## VSS — implementation note

`vssadmin create shadow /for=C:` is the obvious choice but it's
**Server-only** in modern Windows; on Pro/Home it returns
`ExitStatus(2)` with empty stderr (which is exactly what bit us). We
replaced it with PowerShell `[WMIClass]'Win32_ShadowCopy'.Create("C:\\", "ClientAccessible")`,
which works on **every** Windows edition because WMI doesn't have the
SKU restriction.

The vssadmin call is kept as a secondary fallback for Server hosts where
admin policy may have hardened WMI access.

## Raw NTFS — implementation note

Implemented in `collector/src/acquisition/raw_ntfs.rs` using the
[`ntfs`](https://crates.io/crates/ntfs) crate, which provides a pure-Rust
NTFS structure parser (no `unsafe`, no dependencies on `ntfs.sys`). The
collector:

1. Opens `\\.\C:` with `FILE_FLAG_BACKUP_SEMANTICS` (admin only) — the
   handle is opened with `FILE_SHARE_*` set to all-shared so we don't
   block the kernel.
2. Hands the handle to `ntfs::Ntfs::new()` as a `Read + Seek` source.
3. Walks the file's path component by component starting at the root
   directory, doing case-insensitive name matches.
4. Opens the file's default `$DATA` attribute and streams its bytes to
   the destination, walking sparse runs / data extents as needed.

This is precisely what Velociraptor's `ntfs` accessor does (in Go) and
what KAPE/RawCopy.exe does.

## What this collector does NOT do (yet)

- **Encrypted (EFS) files** would come out as ciphertext from the raw
  NTFS path. Decryption requires the per-user DPAPI master key, which
  needs separate handling (the `cred.dpapi` artifact captures the key
  material but doesn't decrypt at acquisition time).
- **Compressed files** are read as the underlying compressed bytes —
  the analyst would need to inflate them. The `ntfs` crate does support
  decompression but we haven't wired it in yet.
- **Alternate Data Streams (ADS)** are not collected. ADS-bearing files
  like `Zone.Identifier` (Mark of the Web) would need an explicit ADS
  acquisition pass.
- **ReFS volumes**. The raw fallback assumes NTFS. For Server hosts with
  ReFS data volumes (rare for system volumes), the fallback fails and
  we log a warning.
- **A custom kernel driver for direct disk access**. This is what
  CrowdStrike / SentinelOne use and would be the next-generation
  approach — but it requires a code-signed driver, signed by a
  whitelisted CA, and is a several-month project.
