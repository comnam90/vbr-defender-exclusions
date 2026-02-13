# Set-VeeamDefenderExclusions

A PowerShell script to configure Microsoft Defender antivirus exclusions for Veeam Backup & Replication infrastructure. Automates the recommendations from [Veeam KB1999](https://www.veeam.com/kb1999).

## Features

- **Role-based configuration** — Select one or more Veeam roles; exclusions are merged and deduplicated automatically
- **Three exclusion types** — Path, process, and file extension exclusions
- **Intelligent detection** — Auto-discovers installed Veeam packages, PostgreSQL location, and version-specific paths (v12 vs v13)
- **Idempotent** — Skips exclusions that already exist (or don't exist when removing)
- **Reversible** — Use `-Remove` to cleanly undo all exclusions
- **Safe** — Full `-WhatIf` support for dry-run testing
- **Process exclusions** — Automatically scans Veeam installation directories for executables

## Requirements

- Windows 10 / Server 2016 or later
- PowerShell 5.1+
- Administrator privileges
- Microsoft Defender active (WinDefend service running)

## Installation

Download the script or clone this repository:

```powershell
# Option 1: Download directly
Invoke-WebRequest -Uri "https://gist.githubusercontent.com/comnam90/fc472779d16fae0c38df4299bb1206e5/raw/477655b37b4575fcbf6877244af1d55e2f3fb60a/Set-VeeamDefenderExclusions.ps1" -OutFile "Set-VeeamDefenderExclusions.ps1"
```

## Quick Start

```powershell
# Typical VBR 12+ server with local PostgreSQL
.\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -IncludePostgreSQL

# Preview changes without applying (dry-run)
.\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -IncludePostgreSQL -WhatIf

# Remove exclusions
.\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -IncludePostgreSQL -Remove
```

## Roles

| Role | Description |
|------|-------------|
| `BackupServer` | Veeam Backup & Replication Server |
| `EnterpriseManager` | Veeam Backup Enterprise Manager |
| `Console` | Veeam Backup & Replication Console |
| `ProtectedGuest` | Guest OS of a protected Windows VM |
| `RestoreTarget` | Guest OS used as a file-level restore target |
| `BackupInfrastructure` | Proxy, Repository, WAN Accelerator, Mount Server, etc. |

Multiple roles can be specified: `-Role BackupServer,EnterpriseManager`

## Parameters

### Common Flags

| Parameter | Description |
|-----------|-------------|
| `-Role` | **(Required)** One or more Veeam roles to configure |
| `-Remove` | Remove exclusions instead of adding them |
| `-IncludePostgreSQL` | Add PostgreSQL exclusions (install folder, data directory, postgres.exe process) |
| `-IncludeVeeamFLR` | Add `C:\VeeamFLR\` — review [KB1999](https://www.veeam.com/kb1999) trade-off note first |
| `-IncludeRepositoryExtensions` | Add file extension exclusions (.vbk, .vib, .vom, etc.) globally |
| `-CustomLogPath` | Non-default Veeam log directory (if changed per [KB1825](https://www.veeam.com/kb1825)) |

### ProtectedGuest Flags

| Parameter | Description |
|-----------|-------------|
| `-EnableGuestProcessing` | Application-Aware Processing / Guest File System Indexing paths |
| `-EnableInlineEntropy` | Malware Detection Inline Entropy Analysis (*.ridx) |
| `-EnableSQLLogBackup` | SQL Server Transaction Log Backup (VeeamLogShipper) |
| `-EnablePersistentAgent` | Veeam Guest Agent install folder |

### BackupInfrastructure Paths

| Parameter | Description |
|-----------|-------------|
| `-CDPCachePath` | CDP Proxy cache folder (default: `C:\VeeamCDP`) |
| `-WANCachePath` | WAN Accelerator cache folder (required when WAN Accelerator detected) |
| `-InstantRecoveryWriteCachePath` | vPowerNFS instant-recovery write-cache path |
| `-BackupFilesPath` | Backup repository root folder |
| `-CapacityTierArchiveIndexPath` | Capacity Tier archive-index directory |

## Usage Examples

### Backup Server

```powershell
# Standard VBR 12+ with PostgreSQL
.\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -IncludePostgreSQL

# VBR with Enterprise Manager on same server
.\Set-VeeamDefenderExclusions.ps1 -Role BackupServer,EnterpriseManager -IncludePostgreSQL

# Include VeeamFLR folder (read KB4535 trade-off note first)
.\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -IncludePostgreSQL -IncludeVeeamFLR
```

### Backup Infrastructure (Proxy/Repository)

```powershell
# Auto-detect installed packages
.\Set-VeeamDefenderExclusions.ps1 -Role BackupInfrastructure

# Windows Repository with backup files path
.\Set-VeeamDefenderExclusions.ps1 -Role BackupInfrastructure -BackupFilesPath "D:\VeeamBackups"

# Repository with global extension exclusions instead of folder
.\Set-VeeamDefenderExclusions.ps1 -Role BackupInfrastructure -IncludeRepositoryExtensions

# WAN Accelerator (cache path required)
.\Set-VeeamDefenderExclusions.ps1 -Role BackupInfrastructure -WANCachePath "E:\WANCache"
```

### Protected Guest VMs

```powershell
# Guest with Application-Aware Processing
.\Set-VeeamDefenderExclusions.ps1 -Role ProtectedGuest -EnableGuestProcessing

# Guest with SQL log backup and persistent agent
.\Set-VeeamDefenderExclusions.ps1 -Role ProtectedGuest -EnableGuestProcessing -EnableSQLLogBackup -EnablePersistentAgent

# Malware detection inline entropy analysis
.\Set-VeeamDefenderExclusions.ps1 -Role ProtectedGuest -EnableInlineEntropy
```

### Console Only

```powershell
.\Set-VeeamDefenderExclusions.ps1 -Role Console
```

### Cleanup

```powershell
# Remove all exclusions (use same parameters as when adding)
.\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -IncludePostgreSQL -Remove

# Preview removal
.\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -IncludePostgreSQL -Remove -WhatIf
```

## How It Works

1. **Role Processing** — Each selected role adds its required paths to a deduplicated HashSet
2. **Registry Lookups** — VBR Catalog, NFS root, and PostgreSQL paths are resolved from registry (with fallback defaults)
3. **Package Detection** — For `BackupInfrastructure`, the script scans Programs & Features to detect installed Veeam components
4. **Version Detection** — Checks whether v12 (x86) or v13+ (x64) paths exist for Backup Transport
5. **Process Scanning** — Scans Veeam installation directories for .exe files
6. **Idempotency Check** — Reads current Defender exclusions to skip duplicates
7. **Apply Exclusions** — Adds (or removes) path, process, and extension exclusions via `Add-MpPreference` / `Remove-MpPreference`

## Output Example

```
[14:32:01] [INFO] Veeam  -  Defender Exclusion Setup
[14:32:01] [INFO] ===================================
[14:32:01] [INFO] Action         : Add
[14:32:01] [INFO] Selected roles : BackupServer

[14:32:01] [INFO] -- BackupServer --------------------------
[14:32:01] [INFO]   VBRCatalog : C:\VBRCatalog
[14:32:01] [WARN]   NFS RootFolder : registry key absent -- skipped

[14:32:01] [INFO]   + PostgreSQL: PostgreSQL 15
[14:32:01] [INFO]       install : C:\Program Files\PostgreSQL\15
[14:32:01] [INFO]       data    : C:\Program Files\PostgreSQL\15\data
[14:32:01] [INFO]       process : postgres.exe

[14:32:01] [INFO] -- Process Exclusions --------------------
[14:32:01] [INFO]   Found 47 unique process(es) in Veeam directories

[14:32:01] [INFO] === Adding 18 unique path exclusion(s) ===
[14:32:01] [OK]   ADD   C:\Program Files\Veeam
[14:32:01] [OK]   ADD   C:\Program Files\Common Files\Veeam
...

[14:32:02] [INFO] === Results ===
[14:32:02] [INFO]   Paths:
[14:32:02] [INFO]     Added   : 18
[14:32:02] [INFO]     Skipped : 0  (already present)
[14:32:02] [INFO]     Failed  : 0
[14:32:02] [INFO]   Processes:
[14:32:02] [INFO]     Added   : 47
[14:32:02] [INFO]     Skipped : 0  (already present)
[14:32:02] [INFO]     Failed  : 0

[14:32:02] [OK] Done.
```

## Exclusion Types

### Path Exclusions

Folder and file pattern exclusions added via `Add-MpPreference -ExclusionPath`:

- `C:\Program Files\Veeam\`
- `C:\Program Files (x86)\Veeam\`
- `C:\ProgramData\Veeam\`
- `C:\Windows\Veeam\`
- `C:\VBRCatalog\` (or custom path from registry)
- And many more based on role...

### Process Exclusions

Executable names discovered by scanning Veeam installation directories:

- `Veeam.Backup.Service.exe`
- `Veeam.Backup.Manager.exe`
- `VeeamTransportSvc.exe`
- `postgres.exe` (when `-IncludePostgreSQL` specified)
- All other .exe files found in Veeam folders...

### Extension Exclusions (with `-IncludeRepositoryExtensions`)

Backup file extensions added via `Add-MpPreference -ExclusionExtension`:

| Extension | Description |
|-----------|-------------|
| `.vbk` | Full backup files |
| `.vib` | Incremental backup files |
| `.vrb` | Reverse incremental files |
| `.vbm` | Backup metadata |
| `.vom` | NAS backup files |
| `.vlb` | Log backup files |
| And 20+ more... | |

## Comparison to Alternatives

| Feature | This Script | Simple KB Script | Interactive Menu Script |
|---------|:-----------:|:----------------:|:-----------------------:|
| Role-based architecture | ✓ | ✗ | ✓ |
| Idempotent | ✓ | ✗ | ✓ |
| `-WhatIf` support | ✓ | ✗ | ✗ |
| Remove functionality | ✓ | ✓ | ✗ |
| Process exclusions | ✓ | ✗ | ✓ |
| Version detection (v12/v13) | ✓ | ✗ | ✗ |
| Package auto-detection | ✓ | ✗ | ✗ |
| Correct extension format | ✓ | ✗ | ✗ |
| Automation-friendly | ✓ | ✓ | ✗ |
| PostgreSQL registry lookup | ✓ | ✓ | ✗ |

## Troubleshooting

### "WinDefend service is not running"

Microsoft Defender must be active. Check if another AV product has disabled it:

```powershell
Get-Service WinDefend
Get-MpComputerStatus
```

### Exclusions not applied

Run with `-WhatIf` to preview, then check current exclusions:

```powershell
(Get-MpPreference).ExclusionPath
(Get-MpPreference).ExclusionProcess
(Get-MpPreference).ExclusionExtension
```

### Registry keys not found

The script uses sensible defaults when registry keys are missing. Warnings are displayed but execution continues.

## References

- [Veeam KB4535 — Antivirus Exclusions](https://www.veeam.com/kb4535)
- [Veeam KB1825 — Custom Log Paths](https://www.veeam.com/kb1825)
- [PostgreSQL Wiki — Antivirus Software](https://wiki.postgresql.org/wiki/Running_%26_Installing_PostgreSQL_On_Native_Windows#Antivirus_software)

## License

MIT License
