#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Configures Microsoft Defender antivirus exclusions for Veeam
    Backup & Replication infrastructure.

.DESCRIPTION
    Adds (or removes) the antivirus exclusions recommended by Veeam for one
    or more roles on the target server.  Exclusions across all selected roles
    are merged and de-duplicated before being applied.

    Exclusion types:
    - Path exclusions: folders and file patterns
    - Process exclusions: executables found in Veeam installation directories
    - Extension exclusions: backup file extensions (with -IncludeRepositoryExtensions)

    Features:
    - Static paths are added directly.
    - Registry-backed paths (VBRCatalog, NFS root, PostgreSQL) are resolved
      automatically; a documented default is used when the key is absent.
    - When BackupInfrastructure is selected the script scans the Programs &
      Features registry keys to determine which Veeam packages are installed
      and adds only the paths relevant to those packages.  Version-dependent
      paths (e.g. Backup Transport v12 vs v13) are resolved by checking which
      directory actually exists on disk.
    - Process exclusions are auto-discovered by scanning Veeam installation
      directories for .exe files.
    - PostgreSQL exclusions (when -IncludePostgreSQL is specified) include
      the install folder, data directory, and postgres.exe process.

    The script is idempotent: exclusions already present (or absent when
    using -Remove) are reported and skipped.  Full -WhatIf support is
    provided.

    Reference: https://www.veeam.com/kb4535

.PARAMETER Role
    One or more Veeam roles present on the target server.  Specify multiple
    values separated by commas.

        BackupServer           - Veeam Backup & Replication Server
        EnterpriseManager      - Veeam Backup Enterprise Manager
        Console                - Veeam Backup & Replication Console
        ProtectedGuest         - Guest OS of a protected Windows VM
        RestoreTarget          - Guest OS used as a file-level restore target
        BackupInfrastructure   - Any Backup Infrastructure component
                                 (Proxy, Repository, WAN Accelerator, etc.)

.PARAMETER IncludeVeeamFLR
    Adds C:\VeeamFLR\ to the exclusion list.  Review the Veeam KB trade-off
    note before enabling -- on some AV products this prevents Scan Backup /
    SureBackup on-demand scans.  Relevant to BackupServer, Console, and
    the Mount Service package in BackupInfrastructure.

.PARAMETER IncludePostgreSQL
    Adds PostgreSQL exclusions for the Veeam configuration database.
    The script auto-detects the PostgreSQL install location from registry
    and adds: the install folder, data directory, and postgres.exe process.
    Falls back to C:\Program Files\PostgreSQL\ if registry lookup fails.
    Required when using a local PostgreSQL instance (default for VBR 12+).

.PARAMETER IncludeRepositoryExtensions
    Adds file-extension exclusions for Veeam backup repository files
    (.vbk, .vib, .vom, etc.) via Add-MpPreference -ExclusionExtension.
    Also adds compound patterns (*.vbk.tmp, *.vacm_*tmp, etc.) as path
    exclusions.  Use this as an alternative to -BackupFilesPath when
    you want extension-based exclusions that apply globally rather than
    folder-based exclusions.

.PARAMETER CustomLogPath
    Non-default Veeam log directory.  C:\ProgramData\Veeam\ is always
    included; only supply this if the log path was changed (KB1825).

.PARAMETER EnableGuestProcessing
    (ProtectedGuest)  Adds paths used by Application-Aware Processing
    and/or Guest File System Indexing.

.PARAMETER EnableInlineEntropy
    (ProtectedGuest)  Adds the *.ridx file pattern used by Malware
    Detection Inline Entropy Analysis.

.PARAMETER EnableSQLLogBackup
    (ProtectedGuest)  Adds the VeeamLogShipper folder used by SQL Server
    Transaction Log Backup.

.PARAMETER EnablePersistentAgent
    (ProtectedGuest)  Adds the Veeam Guest Agent install folder.

.PARAMETER CDPCachePath
    (BackupInfrastructure)  CDP Proxy cache folder override.
    Default: C:\VeeamCDP

.PARAMETER WANCachePath
    (BackupInfrastructure)  WAN Accelerator cache folder.  No documented
    system default -- must be provided when a WAN Accelerator package is
    detected.

.PARAMETER InstantRecoveryWriteCachePath
    (BackupInfrastructure)  vPowerNFS instant-recovery write-cache path.
    Configured per repository on the Mount Server; supply it if vPowerNFS
    is installed.

.PARAMETER BackupFilesPath
    (BackupInfrastructure)  Backup-repository root when this machine acts
    as a Windows Backup Repository.

.PARAMETER CapacityTierArchiveIndexPath
    (BackupInfrastructure)  Capacity Tier archive-index directory, if in
    use.

.EXAMPLE
    # Typical VBR 12+ server with local PostgreSQL
    .\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -IncludePostgreSQL

.EXAMPLE
    # BackupServer and EnterpriseManager on one box
    .\Set-VeeamDefenderExclusions.ps1 -Role BackupServer,EnterpriseManager `
        -IncludePostgreSQL

.EXAMPLE
    # Protected guest with App-Aware Processing and SQL log backup
    .\Set-VeeamDefenderExclusions.ps1 -Role ProtectedGuest `
        -EnableGuestProcessing -EnableSQLLogBackup

.EXAMPLE
    # Proxy / Repository -- packages are auto-detected
    .\Set-VeeamDefenderExclusions.ps1 -Role BackupInfrastructure `
        -BackupFilesPath D:\VeeamRepo

.EXAMPLE
    # Dry run -- shows what would be added without changing anything
    .\Set-VeeamDefenderExclusions.ps1 -Role BackupServer `
        -IncludePostgreSQL -WhatIf

.EXAMPLE
    # Repository with extension-based exclusions instead of folder exclusion
    .\Set-VeeamDefenderExclusions.ps1 -Role BackupInfrastructure `
        -IncludeRepositoryExtensions

.EXAMPLE
    # Remove all exclusions that were previously added
    .\Set-VeeamDefenderExclusions.ps1 -Role BackupServer -IncludePostgreSQL -Remove

.PARAMETER Remove
    Removes exclusions instead of adding them.  Use the same role and flag
    parameters as when adding to ensure all exclusions are removed.

.NOTES
    Must be run as Administrator.  Requires Windows 10 / Server 2016 or
    later with Microsoft Defender active.

    Use -IncludeRepositoryExtensions for global file-extension exclusions
    as an alternative to -BackupFilesPath folder exclusions.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    # ── Role selection ──────────────────────────────────────────────────────
    [Parameter(Mandatory)]
    [ValidateSet('BackupServer','EnterpriseManager','Console',
                 'ProtectedGuest','RestoreTarget','BackupInfrastructure')]
    [string[]]$Role,

    # ── Common flags ────────────────────────────────────────────────────────
    [switch]$IncludeVeeamFLR,
    [switch]$IncludePostgreSQL,
    [switch]$IncludeRepositoryExtensions,
    [switch]$Remove,
    [ValidateNotNullOrEmpty()] [string]$CustomLogPath,

    # ── ProtectedGuest feature flags ────────────────────────────────────────
    [switch]$EnableGuestProcessing,
    [switch]$EnableInlineEntropy,
    [switch]$EnableSQLLogBackup,
    [switch]$EnablePersistentAgent,

    # ── BackupInfrastructure configurable paths ─────────────────────────────
    [ValidateNotNullOrEmpty()] [string]$CDPCachePath,
    [ValidateNotNullOrEmpty()] [string]$WANCachePath,
    [ValidateNotNullOrEmpty()] [string]$InstantRecoveryWriteCachePath,
    [ValidateNotNullOrEmpty()] [string]$BackupFilesPath,
    [ValidateNotNullOrEmpty()] [string]$CapacityTierArchiveIndexPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Parameter-Role Validation (auto-add missing roles with warning)
# ---------------------------------------------------------------------------
$protectedGuestParams = @{
    EnableGuestProcessing = $EnableGuestProcessing
    EnableInlineEntropy   = $EnableInlineEntropy
    EnableSQLLogBackup    = $EnableSQLLogBackup
    EnablePersistentAgent = $EnablePersistentAgent
}

$infraParams = @{
    CDPCachePath                  = $CDPCachePath
    WANCachePath                  = $WANCachePath
    InstantRecoveryWriteCachePath = $InstantRecoveryWriteCachePath
    BackupFilesPath               = $BackupFilesPath
    CapacityTierArchiveIndexPath  = $CapacityTierArchiveIndexPath
}

# Check for ProtectedGuest parameters without the role
$usedPGParams = $protectedGuestParams.GetEnumerator() | Where-Object { $_.Value } | Select-Object -ExpandProperty Key
if ($usedPGParams -and 'ProtectedGuest' -notin $Role) {
    $roleWarning = "Parameters [$($usedPGParams -join ', ')] require -Role ProtectedGuest -- adding role automatically"
    # Write warning after log system is available (deferred)
    $script:DeferredPGWarning = $roleWarning
    $Role = [string[]]$Role + 'ProtectedGuest'
}

# Check for BackupInfrastructure parameters without the role
$usedInfraParams = $infraParams.GetEnumerator() | Where-Object { $_.Value } | Select-Object -ExpandProperty Key
if ($usedInfraParams -and 'BackupInfrastructure' -notin $Role) {
    $roleWarning = "Parameters [$($usedInfraParams -join ', ')] require -Role BackupInfrastructure -- adding role automatically"
    # Write warning after log system is available (deferred)
    $script:DeferredInfraWarning = $roleWarning
    $Role = [string[]]$Role + 'BackupInfrastructure'
}

# ---------------------------------------------------------------------------
# Shared Path Collections (DRY)
# ---------------------------------------------------------------------------
$script:CommonVeeamPaths = @(
    'C:\Program Files\Veeam'
    'C:\Program Files\Common Files\Veeam'
    'C:\ProgramData\Veeam'
)

$script:CommonVeeamPathsX86 = @(
    'C:\Program Files (x86)\Veeam'
    'C:\Program Files (x86)\Common Files\Veeam'
)

$script:CommonWindowsPaths = @(
    'C:\Windows\Veeam'
)

$script:CommonTempPaths = @(
    'C:\Windows\Temp\VeeamBackup'
    'C:\Windows\Temp\VeeamBackupTemp'
    'C:\Windows\Temp\veeamdumprecorder'
    'C:\Windows\Temp\*\veeamflr-*.flat'
)

$script:BackupServerExtraPaths = @(
    'C:\Windows\SystemTemp\veeam-*.json'
    'C:\Windows\TEMP\VeeamForeignSessionContext'
    'C:\Users\*\AppData\Local\Veeam\Backup'
)

# Repository file extensions (KB1999)
# Simple extensions - applied via Add-MpPreference -ExclusionExtension
$script:RepositoryExtensions = @(
    'erm'
    'flat'
    'vab'
    'vacm'
    'vasm'
    'vbk'
    'vblob'
    'vbm'
    'vcache'
    'vib'
    'vindex'
    'vlb'
    'vmdk'
    'vom'
    'vrb'
    'vsb'
    'vslice'
    'vsm'
    'vsource'
    'vsourcecopy'
    'vsourcetemp'
    'vstore'
    'vstorecopy'
    'vstoretemp'
)

# Compound patterns - applied via Add-MpPreference -ExclusionPath
$script:RepositoryPatterns = @(
    '*.vacm_*tmp'
    '*.vasm_*tmp'
    '*.vbk.tmp'
    '*.vbm.temp'
    '*.vbm_*tmp'
    '*.vom_*tmp'
    '*.vsm_*tmp'
)

# Directories to scan for process exclusions (installation folders only)
$script:ProcessScanPaths = @(
    'C:\Program Files\Veeam'
    'C:\Program Files (x86)\Veeam'
    'C:\Program Files\Common Files\Veeam'
    'C:\Program Files (x86)\Common Files\Veeam'
    'C:\Windows\Veeam'
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('INFO','WARN','ERR','OK')]
        [string]$Level = 'INFO'
    )
    $clr = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERR = 'Red'; OK = 'Green' }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [$Level] $Message" -ForegroundColor $clr[$Level]
}

function Get-RegValue {
    <#
    .SYNOPSIS
        Returns a single registry value, or $null if the key or value is
        absent.  Never throws.
    #>
    param(
        [Parameter(Mandatory)] [string]$Key,
        [Parameter(Mandatory)] [string]$Name
    )
    try   { return (Get-ItemProperty -Path $Key -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

function Get-InstalledPackageNames {
    <#
    .SYNOPSIS
        Returns the DisplayName values from both Uninstall registry hives.
        Used to detect which Veeam packages are installed.
    #>
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    [string[]]$names = @()
    foreach ($root in $roots) {
        if (Test-Path $root) {
            $names += Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $dn = (Get-ItemProperty -Path $_.PSPath -Name DisplayName -ErrorAction Stop).DisplayName
                    if ($dn) { $dn }
                }
                catch { }   # no DisplayName value -- skip
            }
        }
    }
    return $names
}

function Get-VBRCatalogPath {
    <#
    .SYNOPSIS
        Retrieves the VBR Catalog path from registry or returns default.
    #>
    $v = Get-RegValue -Key 'HKLM:\SOFTWARE\Veeam\Veeam Backup Catalog' -Name 'CatalogPath'
    if ($v) {
        Write-Log "  VBRCatalog : $v"
        return $v
    }
    Write-Log '  VBRCatalog : registry key absent -- using default (C:\VBRCatalog)' -Level WARN
    return 'C:\VBRCatalog'
}

function Get-NFSRootPath {
    <#
    .SYNOPSIS
        Retrieves the NFS root folder from registry if present.
    #>
    $v = Get-RegValue -Key 'HKLM:\SOFTWARE\Wow6432Node\Veeam\Veeam NFS' -Name 'RootFolder'
    if ($v) {
        Write-Log "  NFS RootFolder : $v"
        return $v
    }
    Write-Log '  NFS RootFolder : registry key absent -- skipped' -Level WARN
    return $null
}

function Add-PathsToSet {
    <#
    .SYNOPSIS
        Adds an array of paths to a HashSet, suppressing output.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$PathSet,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Paths
    )
    foreach ($p in $Paths) {
        [void]$PathSet.Add($p)
    }
}

function Get-ExecutablesFromPaths {
    <#
    .SYNOPSIS
        Scans directories for .exe files and returns unique process names.
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$Paths
    )
    $exeSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($path in $Paths) {
        if (-not (Test-Path $path -PathType Container)) { continue }
        try {
            Get-ChildItem -Path $path -Filter '*.exe' -Recurse -ErrorAction SilentlyContinue |
                ForEach-Object { [void]$exeSet.Add($_.Name) }
        }
        catch { }  # Skip inaccessible directories
    }
    return $exeSet
}

function Get-PostgreSQLInstallInfo {
    <#
    .SYNOPSIS
        Finds PostgreSQL installation from registry.  Returns hashtable with
        InstallPath, DataPath, and ProcessPath, or $null if not found.
    #>
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($root in $uninstallRoots) {
        if (-not (Test-Path $root)) { continue }

        $pgKey = Get-ChildItem $root -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -like 'PostgreSQL*' } |
            Select-Object -First 1

        if ($pgKey) {
            try {
                $props = Get-ItemProperty -Path $pgKey.PSPath -ErrorAction Stop
                if ($props.InstallLocation) {
                    $installPath = $props.InstallLocation.TrimEnd('\')
                    return @{
                        InstallPath = $installPath
                        DataPath    = Join-Path $installPath 'data'
                        ProcessPath = Join-Path $installPath 'bin\postgres.exe'
                        Version     = $props.DisplayName
                    }
                }
            }
            catch { }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Role Handlers
# ---------------------------------------------------------------------------
function Add-BackupServerPaths {
    param([System.Collections.Generic.HashSet[string]]$PathSet)

    Write-Log ''
    Write-Log '-- BackupServer --------------------------'

    Add-PathsToSet -PathSet $PathSet -Paths $script:CommonVeeamPaths
    Add-PathsToSet -PathSet $PathSet -Paths $script:CommonVeeamPathsX86
    Add-PathsToSet -PathSet $PathSet -Paths $script:CommonWindowsPaths
    Add-PathsToSet -PathSet $PathSet -Paths $script:CommonTempPaths
    Add-PathsToSet -PathSet $PathSet -Paths $script:BackupServerExtraPaths

    [void]$PathSet.Add((Get-VBRCatalogPath))

    $nfsRoot = Get-NFSRootPath
    if ($nfsRoot) { [void]$PathSet.Add($nfsRoot) }
}

function Add-EnterpriseManagerPaths {
    param([System.Collections.Generic.HashSet[string]]$PathSet)

    Write-Log ''
    Write-Log '-- EnterpriseManager ---------------------'

    Add-PathsToSet -PathSet $PathSet -Paths $script:CommonVeeamPaths

    [void]$PathSet.Add((Get-VBRCatalogPath))
}

function Add-ConsolePaths {
    param([System.Collections.Generic.HashSet[string]]$PathSet)

    Write-Log ''
    Write-Log '-- Console -------------------------------'

    Add-PathsToSet -PathSet $PathSet -Paths $script:CommonVeeamPaths
    Add-PathsToSet -PathSet $PathSet -Paths $script:CommonVeeamPathsX86
    Add-PathsToSet -PathSet $PathSet -Paths $script:CommonWindowsPaths
    Add-PathsToSet -PathSet $PathSet -Paths $script:CommonTempPaths
    [void]$PathSet.Add('C:\Users\*\AppData\Local\Veeam\Backup')
}

function Add-ProtectedGuestPaths {
    param([System.Collections.Generic.HashSet[string]]$PathSet)

    Write-Log ''
    Write-Log '-- ProtectedGuest ------------------------'

    $anyAdded = $false

    if ($script:EnableGuestProcessing) {
        [void]$PathSet.Add("$env:ProgramData\Veeam")
        [void]$PathSet.Add("$env:SystemRoot\VeeamVssSupport")
        Write-Log "  + GuestProcessing : $env:ProgramData\Veeam"
        Write-Log "                      $env:SystemRoot\VeeamVssSupport"
        $anyAdded = $true
    }
    if ($script:EnableInlineEntropy) {
        [void]$PathSet.Add("$env:SystemRoot\TEMP\*.ridx")
        Write-Log "  + InlineEntropy  : $env:SystemRoot\TEMP\*.ridx"
        $anyAdded = $true
    }
    if ($script:EnableSQLLogBackup) {
        [void]$PathSet.Add("$env:SystemRoot\VeeamLogShipper")
        Write-Log "  + SQLLogBackup   : $env:SystemRoot\VeeamLogShipper"
        $anyAdded = $true
    }
    if ($script:EnablePersistentAgent) {
        [void]$PathSet.Add('C:\Program Files\Common Files\Veeam\Backup and Replication\Veeam Guest Agent')
        Write-Log '  + PersistentAgent: ...\Veeam Guest Agent'
        $anyAdded = $true
    }

    if (-not $anyAdded) {
        Write-Log '  No feature flags supplied -- no paths added for this role.' -Level WARN
        Write-Log '  Available: -EnableGuestProcessing  -EnableInlineEntropy  -EnableSQLLogBackup  -EnablePersistentAgent' -Level WARN
    }
}

function Add-RestoreTargetPaths {
    param([System.Collections.Generic.HashSet[string]]$PathSet)

    Write-Log ''
    Write-Log '-- RestoreTarget -------------------------'

    [void]$PathSet.Add("$env:ProgramData\Veeam")
    [void]$PathSet.Add("$env:SystemRoot\VeeamVssSupport")
    Write-Log "  $env:ProgramData\Veeam"
    Write-Log "  $env:SystemRoot\VeeamVssSupport"
}

function Add-BackupInfrastructurePaths {
    param(
        [System.Collections.Generic.HashSet[string]]$PathSet,
        [hashtable]$Config
    )

    Write-Log ''
    Write-Log '-- BackupInfrastructure -------------------'

    # General folders -- all infrastructure components use these
    Add-PathsToSet -PathSet $PathSet -Paths @(
        'C:\ProgramData\Veeam'
        'C:\Windows\Temp\Veeam'
        'C:\Windows\Temp\VeeamBackupTemp'
    )

    # Package definitions for data-driven detection
    $packageDefinitions = @(
        @{
            Pattern = 'Veeam Installer Service'
            Name    = 'Veeam Installer Service'
            Paths   = @('C:\Windows\Veeam\Backup')
        }
        @{
            Pattern     = 'Veeam Backup Transport'
            Name        = 'Veeam Backup Transport'
            PathsV13    = @('C:\Program Files\Veeam\Backup Transport')
            PathsLegacy = @('C:\Program Files (x86)\Veeam\Backup Transport')
            V13Check    = 'C:\Program Files\Veeam\Backup Transport'
        }
        @{
            Pattern = 'Veeam Guest Interaction*'
            Name    = 'Veeam Guest Interaction Proxy Service'
            Paths   = @('C:\Program Files\Veeam\Veeam Guest Interaction Service')
        }
        @{
            Pattern      = 'Veeam CDP Proxy'
            Name         = 'Veeam CDP Proxy'
            Paths        = @('C:\Program Files\Veeam\CDP Proxy Service')
            CacheParam   = 'CDPCachePath'
            CacheDefault = 'C:\VeeamCDP'
            CacheLabel   = 'cache'
        }
        @{
            Pattern           = 'Veeam Backup vPowerNFS'
            Name              = 'Veeam Backup vPowerNFS'
            Paths             = @('C:\Program Files (x86)\Veeam\vPowerNFS')
            OptionalParam     = 'InstantRecoveryWriteCachePath'
            OptionalLabel     = 'write cache'
            OptionalWarn      = '-InstantRecoveryWriteCachePath not supplied -- check each repository mount server'
        }
        @{
            Pattern = 'Veeam Hyper-V*'
            Name    = 'Veeam Hyper-V Integration'
            Paths   = @('C:\Program Files\Veeam\Hyper-V Integration')
        }
        @{
            Pattern           = 'Veeam Mount Service'
            Name              = 'Veeam Mount Service'
            Paths             = @(
                'C:\Program Files\Common Files\Veeam\Backup and Replication'
                'C:\Windows\Temp\*\veeamflr-*.flat'
            )
            SupportsVeeamFLR  = $true
            OptionalParam     = 'BackupFilesPath'
            OptionalLabel     = 'backup files'
            OptionalWarn      = '-BackupFilesPath not supplied -- provide it if this machine is a Windows Repository'
            SecondaryParam    = 'CapacityTierArchiveIndexPath'
            SecondaryLabel    = 'capacity tier index'
        }
        @{
            Pattern        = 'Veeam WAN Accelerator*'
            Name           = 'Veeam WAN Accelerator Service'
            Paths          = @('C:\Program Files\Veeam\WAN Accelerator Service')
            RequiredParam  = 'WANCachePath'
            RequiredLabel  = 'WAN cache'
            RequiredWarn   = '-WANCachePath not supplied -- must be provided for WAN Accelerator'
        }
        @{
            Pattern = 'Veeam Remote Tape*'
            Name    = 'Veeam Remote Tape Access Service'
            Paths   = @('C:\Program Files (x86)\Veeam\Backup Tape')
        }
        @{
            Pattern = 'Veeam Backup Cloud*'
            Name    = 'Veeam Backup Cloud Gateway'
            Paths   = @('C:\Program Files (x86)\Veeam\Backup Gate')
        }
        @{
            Pattern = 'Veeam Threat Hunter'
            Name    = 'Veeam Threat Hunter'
            Paths   = @('C:\Program Files\Veeam\Backup and Replication\Threat Hunter')
        }
        @{
            Pattern = 'Veeam Transaction Log*'
            Name    = 'Veeam Transaction Log Backup Service'
            Paths   = @('C:\Program Files\Common Files\Veeam\Backup and Replication\Log Backup Service')
        }
    )

    # Scan Programs & Features for installed Veeam packages
    Write-Log '  Scanning installed packages ...'
    $pkgNames = Get-InstalledPackageNames
    $detections = 0

    foreach ($pkg in $packageDefinitions) {
        if ($pkgNames -ilike $pkg.Pattern) {
            Write-Log "  [pkg] $($pkg.Name)"
            $detections++

            # Handle version-specific paths (v13 vs legacy)
            if ($pkg.ContainsKey('V13Check')) {
                if (Test-Path $pkg['V13Check']) {
                    Add-PathsToSet -PathSet $PathSet -Paths $pkg['PathsV13']
                    Write-Log '       -> v13+ path detected'
                } else {
                    Add-PathsToSet -PathSet $PathSet -Paths $pkg['PathsLegacy']
                    Write-Log '       -> v12.3.2 (x86) path used'
                }
            } elseif ($pkg.ContainsKey('Paths')) {
                Add-PathsToSet -PathSet $PathSet -Paths $pkg['Paths']
            }

            # Handle cache paths with defaults
            if ($pkg.ContainsKey('CacheParam')) {
                $cacheValue = $Config[$pkg['CacheParam']]
                $cachePath = if ($cacheValue) { $cacheValue } else { $pkg['CacheDefault'] }
                [void]$PathSet.Add($cachePath)
                Write-Log "       $($pkg['CacheLabel']): $cachePath"
            }

            # Handle VeeamFLR support
            if ($pkg.ContainsKey('SupportsVeeamFLR') -and $pkg['SupportsVeeamFLR'] -and $Config['IncludeVeeamFLR']) {
                [void]$PathSet.Add('C:\VeeamFLR')
                Write-Log '       + VeeamFLR'
            }

            # Handle optional parameters
            if ($pkg.ContainsKey('OptionalParam')) {
                $optValue = $Config[$pkg['OptionalParam']]
                if ($optValue) {
                    [void]$PathSet.Add($optValue)
                    Write-Log "       $($pkg['OptionalLabel']): $optValue"
                } else {
                    Write-Log "       $($pkg['OptionalWarn'])" -Level WARN
                }
            }

            # Handle secondary optional parameters
            if ($pkg.ContainsKey('SecondaryParam')) {
                $secValue = $Config[$pkg['SecondaryParam']]
                if ($secValue) {
                    [void]$PathSet.Add($secValue)
                    Write-Log "       $($pkg['SecondaryLabel']): $secValue"
                }
            }

            # Handle required parameters
            if ($pkg.ContainsKey('RequiredParam')) {
                $reqValue = $Config[$pkg['RequiredParam']]
                if ($reqValue) {
                    [void]$PathSet.Add($reqValue)
                    Write-Log "       $($pkg['RequiredLabel']): $reqValue"
                } else {
                    Write-Log "       $($pkg['RequiredWarn'])" -Level WARN
                }
            }
        }
    }

    if ($detections -eq 0) {
        Write-Log '  No Veeam infrastructure packages detected -- only general paths added.' -Level WARN
    }
}

function Add-CommonOptionalPaths {
    <#
    .SYNOPSIS
        Adds optional paths and processes that apply across multiple roles.
    #>
    param(
        [System.Collections.Generic.HashSet[string]]$PathSet,
        [System.Collections.Generic.HashSet[string]]$ProcessSet,
        [string[]]$SelectedRoles,
        [switch]$IncludeVeeamFLR,
        [switch]$IncludePostgreSQL,
        [string]$CustomLogPath
    )

    $veeamFLRRoles = @('BackupServer', 'Console')
    $postgresRoles = @('BackupServer', 'EnterpriseManager')
    $customLogRoles = @('BackupServer', 'EnterpriseManager', 'Console', 'BackupInfrastructure')

    $hasVeeamFLRRole = $SelectedRoles | Where-Object { $_ -in $veeamFLRRoles }
    $hasPostgresRole = $SelectedRoles | Where-Object { $_ -in $postgresRoles }
    $hasCustomLogRole = $SelectedRoles | Where-Object { $_ -in $customLogRoles }

    if ($IncludeVeeamFLR -and $hasVeeamFLRRole) {
        [void]$PathSet.Add('C:\VeeamFLR')
        Write-Log '  + VeeamFLR'
    }

    if ($IncludePostgreSQL -and $hasPostgresRole) {
        $pgInfo = Get-PostgreSQLInstallInfo
        if ($pgInfo) {
            Write-Log "  + PostgreSQL: $($pgInfo.Version)"
            [void]$PathSet.Add($pgInfo.InstallPath)
            Write-Log "      install : $($pgInfo.InstallPath)"
            if (Test-Path $pgInfo.DataPath) {
                [void]$PathSet.Add($pgInfo.DataPath)
                Write-Log "      data    : $($pgInfo.DataPath)"
            }
            if (Test-Path $pgInfo.ProcessPath) {
                [void]$ProcessSet.Add('postgres.exe')
                Write-Log '      process : postgres.exe'
            }
        } else {
            # Fallback to default path if registry lookup fails
            [void]$PathSet.Add('C:\Program Files\PostgreSQL')
            Write-Log '  + PostgreSQL: C:\Program Files\PostgreSQL (registry not found)' -Level WARN
        }
    }

    if ($CustomLogPath -and $hasCustomLogRole) {
        [void]$PathSet.Add($CustomLogPath)
        Write-Log "  + CustomLog: $CustomLogPath"
    }
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
$actionVerb = if ($Remove) { 'Remove' } else { 'Add' }
Write-Log 'Veeam  -  Defender Exclusion Setup'
Write-Log '==================================='
Write-Log "Action         : $actionVerb"
Write-Log "Selected roles : $($Role -join ', ')"

# Output deferred role-addition warnings
if ($script:DeferredPGWarning) {
    Write-Log $script:DeferredPGWarning -Level WARN
}
if ($script:DeferredInfraWarning) {
    Write-Log $script:DeferredInfraWarning -Level WARN
}

$svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Log 'The WinDefend service is not running.  Cannot continue.' -Level ERR
    exit 1
}

# ---------------------------------------------------------------------------
# Path and process collection
# Case-insensitive HashSets give us automatic de-duplication across roles.
# ---------------------------------------------------------------------------
$pathSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$processSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)

# Store switches in script scope for role handlers
$script:EnableGuestProcessing = $EnableGuestProcessing
$script:EnableInlineEntropy = $EnableInlineEntropy
$script:EnableSQLLogBackup = $EnableSQLLogBackup
$script:EnablePersistentAgent = $EnablePersistentAgent

# Process each role
if ('BackupServer' -in $Role) {
    Add-BackupServerPaths -PathSet $pathSet
}

if ('EnterpriseManager' -in $Role) {
    Add-EnterpriseManagerPaths -PathSet $pathSet
}

if ('Console' -in $Role) {
    Add-ConsolePaths -PathSet $pathSet
}

if ('ProtectedGuest' -in $Role) {
    Add-ProtectedGuestPaths -PathSet $pathSet
}

if ('RestoreTarget' -in $Role) {
    Add-RestoreTargetPaths -PathSet $pathSet
}

if ('BackupInfrastructure' -in $Role) {
    $infraConfig = @{
        CDPCachePath                  = $CDPCachePath
        WANCachePath                  = $WANCachePath
        InstantRecoveryWriteCachePath = $InstantRecoveryWriteCachePath
        BackupFilesPath               = $BackupFilesPath
        CapacityTierArchiveIndexPath  = $CapacityTierArchiveIndexPath
        IncludeVeeamFLR               = $IncludeVeeamFLR
    }
    Add-BackupInfrastructurePaths -PathSet $pathSet -Config $infraConfig
}

# Add common optional paths (consolidated handling)
Add-CommonOptionalPaths -PathSet $pathSet -ProcessSet $processSet -SelectedRoles $Role `
    -IncludeVeeamFLR:$IncludeVeeamFLR `
    -IncludePostgreSQL:$IncludePostgreSQL `
    -CustomLogPath $CustomLogPath

# ---------------------------------------------------------------------------
# Process collection (scan installation directories for executables)
# ---------------------------------------------------------------------------
Write-Log ''
Write-Log '-- Process Exclusions --------------------'
$foundProcesses = Get-ExecutablesFromPaths -Paths $script:ProcessScanPaths
foreach ($exe in $foundProcesses) {
    [void]$processSet.Add($exe)
}
Write-Log "  Found $($processSet.Count) unique process(es) in Veeam directories"

# ---------------------------------------------------------------------------
# Read the current Defender exclusion lists so we can skip duplicates cleanly
# ---------------------------------------------------------------------------
$existingPathSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$existingExtSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$existingProcessSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
try {
    $mpPref = Get-MpPreference -ErrorAction Stop
    if ($mpPref.ExclusionPath) {
        foreach ($ep in $mpPref.ExclusionPath) {
            [void]$existingPathSet.Add($ep.TrimEnd('\'))
        }
    }
    if ($mpPref.ExclusionExtension) {
        foreach ($ee in $mpPref.ExclusionExtension) {
            [void]$existingExtSet.Add($ee.TrimStart('.'))
        }
    }
    if ($mpPref.ExclusionProcess) {
        foreach ($epr in $mpPref.ExclusionProcess) {
            [void]$existingProcessSet.Add($epr)
        }
    }
}
catch {
    Write-Log 'Could not read current Defender exclusions; will attempt all.' -Level WARN
}

# ---------------------------------------------------------------------------
# Apply exclusions (Add or Remove based on $Remove switch)
# ---------------------------------------------------------------------------
$stats = [PSCustomObject]@{
    PathsAdded     = 0; PathsRemoved   = 0; PathsSkipped   = 0; PathsFailed   = 0
    ProcessesAdded = 0; ProcessesRemoved = 0; ProcessesSkipped = 0; ProcessesFailed = 0
    ExtsAdded      = 0; ExtsRemoved    = 0; ExtsSkipped    = 0; ExtsFailed    = 0
    PatternsAdded  = 0; PatternsRemoved = 0; PatternsSkipped = 0; PatternsFailed = 0
}

# --- Path exclusions ---
Write-Log ''
Write-Log "=== ${actionVerb}ing $($pathSet.Count) unique path exclusion(s) ==="

foreach ($p in $pathSet) {
    $normalizedPath = $p.TrimEnd('\')
    $exists = $existingPathSet.Contains($normalizedPath)

    if ($Remove) {
        if (-not $exists) {
            Write-Log "  SKIP  $p  (not present)" -Level WARN
            $stats.PathsSkipped++
            continue
        }
        try {
            if ($PSCmdlet.ShouldProcess($p, 'Remove-MpPreference -ExclusionPath')) {
                Remove-MpPreference -ExclusionPath $p -ErrorAction Stop
                Write-Log "  DEL   $p" -Level OK
                $stats.PathsRemoved++
            }
        }
        catch {
            Write-Log "  FAIL  $p  --  $_" -Level ERR
            $stats.PathsFailed++
        }
    } else {
        if ($exists) {
            Write-Log "  SKIP  $p  (already present)" -Level WARN
            $stats.PathsSkipped++
            continue
        }
        try {
            if ($PSCmdlet.ShouldProcess($p, 'Add-MpPreference -ExclusionPath')) {
                Add-MpPreference -ExclusionPath $p -ErrorAction Stop
                Write-Log "  ADD   $p" -Level OK
                $stats.PathsAdded++
            }
        }
        catch {
            Write-Log "  FAIL  $p  --  $_" -Level ERR
            $stats.PathsFailed++
        }
    }
}

# --- Process exclusions ---
Write-Log ''
Write-Log "=== ${actionVerb}ing $($processSet.Count) unique process exclusion(s) ==="

foreach ($proc in $processSet) {
    $exists = $existingProcessSet.Contains($proc)

    if ($Remove) {
        if (-not $exists) {
            Write-Log "  SKIP  $proc  (not present)" -Level WARN
            $stats.ProcessesSkipped++
            continue
        }
        try {
            if ($PSCmdlet.ShouldProcess($proc, 'Remove-MpPreference -ExclusionProcess')) {
                Remove-MpPreference -ExclusionProcess $proc -ErrorAction Stop
                Write-Log "  DEL   $proc" -Level OK
                $stats.ProcessesRemoved++
            }
        }
        catch {
            Write-Log "  FAIL  $proc  --  $_" -Level ERR
            $stats.ProcessesFailed++
        }
    } else {
        if ($exists) {
            Write-Log "  SKIP  $proc  (already present)" -Level WARN
            $stats.ProcessesSkipped++
            continue
        }
        try {
            if ($PSCmdlet.ShouldProcess($proc, 'Add-MpPreference -ExclusionProcess')) {
                Add-MpPreference -ExclusionProcess $proc -ErrorAction Stop
                Write-Log "  ADD   $proc" -Level OK
                $stats.ProcessesAdded++
            }
        }
        catch {
            Write-Log "  FAIL  $proc  --  $_" -Level ERR
            $stats.ProcessesFailed++
        }
    }
}

# ---------------------------------------------------------------------------
# Apply repository extension exclusions (if requested)
# ---------------------------------------------------------------------------
if ($IncludeRepositoryExtensions) {
    Write-Log ''
    Write-Log "=== ${actionVerb}ing $($script:RepositoryExtensions.Count) extension exclusion(s) ==="

    foreach ($ext in $script:RepositoryExtensions) {
        $exists = $existingExtSet.Contains($ext)

        if ($Remove) {
            if (-not $exists) {
                Write-Log "  SKIP  .$ext  (not present)" -Level WARN
                $stats.ExtsSkipped++
                continue
            }
            try {
                if ($PSCmdlet.ShouldProcess(".$ext", 'Remove-MpPreference -ExclusionExtension')) {
                    Remove-MpPreference -ExclusionExtension $ext -ErrorAction Stop
                    Write-Log "  DEL   .$ext" -Level OK
                    $stats.ExtsRemoved++
                }
            }
            catch {
                Write-Log "  FAIL  .$ext  --  $_" -Level ERR
                $stats.ExtsFailed++
            }
        } else {
            if ($exists) {
                Write-Log "  SKIP  .$ext  (already present)" -Level WARN
                $stats.ExtsSkipped++
                continue
            }
            try {
                if ($PSCmdlet.ShouldProcess(".$ext", 'Add-MpPreference -ExclusionExtension')) {
                    Add-MpPreference -ExclusionExtension $ext -ErrorAction Stop
                    Write-Log "  ADD   .$ext" -Level OK
                    $stats.ExtsAdded++
                }
            }
            catch {
                Write-Log "  FAIL  .$ext  --  $_" -Level ERR
                $stats.ExtsFailed++
            }
        }
    }

    Write-Log ''
    Write-Log "=== ${actionVerb}ing $($script:RepositoryPatterns.Count) compound pattern exclusion(s) ==="

    foreach ($pattern in $script:RepositoryPatterns) {
        $exists = $existingPathSet.Contains($pattern)

        if ($Remove) {
            if (-not $exists) {
                Write-Log "  SKIP  $pattern  (not present)" -Level WARN
                $stats.PatternsSkipped++
                continue
            }
            try {
                if ($PSCmdlet.ShouldProcess($pattern, 'Remove-MpPreference -ExclusionPath')) {
                    Remove-MpPreference -ExclusionPath $pattern -ErrorAction Stop
                    Write-Log "  DEL   $pattern" -Level OK
                    $stats.PatternsRemoved++
                }
            }
            catch {
                Write-Log "  FAIL  $pattern  --  $_" -Level ERR
                $stats.PatternsFailed++
            }
        } else {
            if ($exists) {
                Write-Log "  SKIP  $pattern  (already present)" -Level WARN
                $stats.PatternsSkipped++
                continue
            }
            try {
                if ($PSCmdlet.ShouldProcess($pattern, 'Add-MpPreference -ExclusionPath')) {
                    Add-MpPreference -ExclusionPath $pattern -ErrorAction Stop
                    Write-Log "  ADD   $pattern" -Level OK
                    $stats.PatternsAdded++
                }
            }
            catch {
                Write-Log "  FAIL  $pattern  --  $_" -Level ERR
                $stats.PatternsFailed++
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Log ''
Write-Log '=== Results ==='

if ($Remove) {
    Write-Log '  Paths:'
    Write-Log "    Removed : $($stats.PathsRemoved)"
    Write-Log "    Skipped : $($stats.PathsSkipped)  (not present)"
    Write-Log "    Failed  : $($stats.PathsFailed)"
    Write-Log '  Processes:'
    Write-Log "    Removed : $($stats.ProcessesRemoved)"
    Write-Log "    Skipped : $($stats.ProcessesSkipped)  (not present)"
    Write-Log "    Failed  : $($stats.ProcessesFailed)"

    if ($IncludeRepositoryExtensions) {
        Write-Log '  Extensions:'
        Write-Log "    Removed : $($stats.ExtsRemoved)"
        Write-Log "    Skipped : $($stats.ExtsSkipped)  (not present)"
        Write-Log "    Failed  : $($stats.ExtsFailed)"
        Write-Log '  Compound Patterns:'
        Write-Log "    Removed : $($stats.PatternsRemoved)"
        Write-Log "    Skipped : $($stats.PatternsSkipped)  (not present)"
        Write-Log "    Failed  : $($stats.PatternsFailed)"
    }
} else {
    Write-Log '  Paths:'
    Write-Log "    Added   : $($stats.PathsAdded)"
    Write-Log "    Skipped : $($stats.PathsSkipped)  (already present)"
    Write-Log "    Failed  : $($stats.PathsFailed)"
    Write-Log '  Processes:'
    Write-Log "    Added   : $($stats.ProcessesAdded)"
    Write-Log "    Skipped : $($stats.ProcessesSkipped)  (already present)"
    Write-Log "    Failed  : $($stats.ProcessesFailed)"

    if ($IncludeRepositoryExtensions) {
        Write-Log '  Extensions:'
        Write-Log "    Added   : $($stats.ExtsAdded)"
        Write-Log "    Skipped : $($stats.ExtsSkipped)  (already present)"
        Write-Log "    Failed  : $($stats.ExtsFailed)"
        Write-Log '  Compound Patterns:'
        Write-Log "    Added   : $($stats.PatternsAdded)"
        Write-Log "    Skipped : $($stats.PatternsSkipped)  (already present)"
        Write-Log "    Failed  : $($stats.PatternsFailed)"
    }
}

$totalFailed = $stats.PathsFailed + $stats.ProcessesFailed + $stats.ExtsFailed + $stats.PatternsFailed
if ($totalFailed -gt 0) {
    Write-Log ''
    Write-Log "Finished with $totalFailed error(s).  Review messages above." -Level ERR
    exit 1
}

Write-Log ''
Write-Log 'Done.' -Level OK
