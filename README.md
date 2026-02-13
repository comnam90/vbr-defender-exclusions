# Veeam Backup & Replication - Microsoft Defender Exclusions

A role-aware PowerShell script that automates Microsoft Defender exclusions for Veeam Backup & Replication infrastructure based on [Veeam KB1999](https://www.veeam.com/kb1999).

## The Problem

Manual antivirus exclusions are tedious and error-prone. A typical VBR server acting as a mount server, proxy, and repository requires **57 individual exclusions** (25 paths + 32 file extensions). Miss one and you'll spend the next three months troubleshooting intermittent performance issues.

When Microsoft Defender decides to real-time scan a 4TB `.vbk` file every time Veeam touches it, performance falls off a cliff.

## The Solution

`Set-VeeamDefenderExclusions.ps1` is infrastructure-aware. You declare what the server does and it builds the exclusion list accordingly. It's idempotent, safe to run multiple times, and smart enough to understand component roles.

## Features

- **Role-Based Configuration**: Exclude only what each server needs
- **Intelligent Auto-Detection**: Queries registry for actual install paths, scans for installed packages
- **PostgreSQL Awareness**: Automatically detects and excludes PostgreSQL paths
- **Process Scanning**: Dynamically builds process exclusions by scanning installation directories
- **Idempotent**: Checks existing exclusions before adding, safe to run repeatedly
- **WhatIf Support**: Preview changes before applying

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Administrator privileges
- Veeam Backup & Replication installed

## Usage

### Standard All-In-One VBR Server

```powershell
.\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -IncludePostgreSQL
```

### Repository Server

The `-IncludeRepositoryExtensions` switch adds file type exclusions (`.vbk`, `.vib`, etc.) that repositories need but proxies don't.

```powershell
.\Set-VeeamDefenderExclusions.ps1 -Role BackupInfrastructure -IncludeRepositoryExtensions
```

### Backup Proxy

```powershell
.\Set-VeeamDefenderExclusions.ps1 -Role BackupInfrastructure
```

### Preview Changes (WhatIf)

```powershell
.\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -IncludePostgreSQL -WhatIf
```

### Remove Exclusions

The `-Remove` switch reverses the logic, removing only Veeam-specific exclusions defined by the specified roles.

```powershell
.\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -Remove
```

## Parameters

### `-Role` (Required)
Specifies the Veeam infrastructure role(s) for this server.

**Valid values:**
- `BackupServer` - VBR server with catalog and configuration database
- `BackupInfrastructure` - Proxy, repository, mount server, WAN accelerator, etc.
- `ProtectedGuest` - VM with Application-Aware Processing enabled

Can accept multiple roles: `-Role BackupServer, BackupInfrastructure`

### `-IncludePostgreSQL` (Switch)
Adds exclusions for PostgreSQL database engine. Automatically detects version and data directory.

### `-IncludeRepositoryExtensions` (Switch)
Adds file extension exclusions for backup files (`.vbk`, `.vib`, `.vrb`, etc.). Use on repository servers.

### `-Remove` (Switch)
Removes exclusions instead of adding them. Removes only the exclusions that would be added based on the specified roles.

### `-WhatIf` (Switch)
Shows what changes would be made without actually applying them.

## How It Works

1. **Role Detection**: Determines what exclusions are needed based on specified roles
2. **Package Scanning**: Scans installed Windows packages to detect components (WAN Accelerator, CDP Proxy, etc.)
3. **Registry Queries**: Retrieves actual install paths from registry (VBR Catalog, NFS root)
4. **Process Discovery**: Scans Veeam installation directories for all executables
5. **PostgreSQL Detection**: If included, locates PostgreSQL version and data directory
6. **Idempotent Application**: Checks existing exclusions before adding to avoid duplicates

## Edge Cases & Limitations

- **WAN Accelerator Cache**: Script will prompt for cache path if WAN Accelerator is detected
- **Custom Paths**: If you've moved logs or catalogs to non-standard locations, you may need additional manual exclusions
- **Version Support**: Tested on v12.x, handles v13+ path differences

## Contributing

Hit an edge case? Found a bug? Open an issue or submit a pull request. I want this to work everywhere.

## Related

For full background and context, see the blog post: [Automating Veeam Defender Exclusions](https://bcthomas.com/2026/02/automating-veeam-defender-exclusions/)

## License

MIT License - See [LICENSE](LICENSE) file for details

## Credits

Based on guidance from [Veeam KB1999: Antivirus Exclusions](https://www.veeam.com/kb1999)
