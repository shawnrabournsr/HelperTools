<#
.SYNOPSIS
    RMADGrab v2.2
    RMAD Baseline Extractor (Edition-aware, Version-aware)

.DESCRIPTION
    Extracts RMAD configuration, collections, backup posture, forest recovery,
    hybrid recovery, sessions, environment identity, and directory service
    (Recycle Bin + Tombstone Lifetime).

    Adds:
        - RMAD version detection
        - RMAD edition detection (Standard vs DRE/Forest Edition)
        - Warning if RMAD version < 10.4
        - Skips FE-only sections on Standard RMAD

    Outputs in current directory:
        - RMADGrab_yyyy-MM-dd_HHmmss.json      (pretty)
        - RMADGrab_yyyy-MM-dd_HHmmss.min.json  (minified)
        - RMADGrab_yyyy-MM-dd_HHmmss.md        (Markdown)
#>

Write-Host "========================================="
Write-Host " RMADGrab v2.2 — RMAD Baseline Extractor"
Write-Host " Generated: $(Get-Date)"
Write-Host "=========================================`n"

# ---------------------------------------------------------
# OUTPUT FILES
# ---------------------------------------------------------
$timestamp = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
$mdFile    = "RMADGrab_$timestamp.md"
$jsonFile  = "RMADGrab_$timestamp.json"
$jsonMin   = "RMADGrab_$timestamp.min.json"

$RMADGrab = [ordered]@{}

# ---------------------------------------------------------
# META (Edition + Version Detection)
# ---------------------------------------------------------
Write-Host "=== RMADGrab v2.2 — Edition & Version Detection ==="

$RMADGrab.Meta = [ordered]@{
    RMADVersion     = $null
    RMADEdition     = "Unknown"
    IsDRE           = $false
    VersionOK       = $false
    Modules         = @()
    Warnings        = @()
    SkippedSections = @()
}

function Add-Warn { param($msg) ; $RMADGrab.Meta.Warnings += $msg ; Write-Warning $msg }
function Skip-Section { param($name) ; $RMADGrab.Meta.SkippedSections += $name ; Write-Host "Skipping section: $name" }

# Detect RMAD version
Write-Host "Detecting RMAD Version..."

$rmadVer = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
           Where-Object { $_.DisplayName -like "Recovery Manager*" } |
           Select-Object DisplayName, DisplayVersion, Publisher

if ($rmadVer) {
    $RMADGrab.Meta.RMADVersion = $rmadVer.DisplayVersion
    Write-Host "RMAD Version Detected: $($rmadVer.DisplayVersion)"
} else {
    Add-Warn "RMAD not detected on this server. Extraction will be limited."
}

# Version check (<10.4 warning)
if ($RMADGrab.Meta.RMADVersion) {
    try {
        $ver = [version]$RMADGrab.Meta.RMADVersion
        if ($ver.Major -ge 10 -and $ver.Minor -ge 4) {
            $RMADGrab.Meta.VersionOK = $true
            Write-Host "RMAD version is 10.4 or higher — OK."
        } else {
            Add-Warn "RMAD version is below 10.4 — some settings may not render correctly."
            $RMADGrab.Meta.VersionOK = $false
        }
    }
    catch {
        Add-Warn "Unable to parse RMAD version."
    }
}

Write-Host ""

# Detect RMAD edition (Standard vs DRE)
Write-Host "Detecting RMAD Edition..."

$dllFE = @(
    "QuestSoftware.RecoveryManager.AD.PowerShellFE.dll",
    "QuestSoftware.RecoveryManager.AD.PowerShell64.dll"
)

$modulesFound = @()

foreach ($dll in $dllFE) {
    $found = Get-Module -ListAvailable |
             Where-Object { $_.Name -like "*RecoveryManager*" -and $_.Path -like "*$dll*" }
    if ($found) { $modulesFound += $found }
}

$RMADGrab.Meta.Modules = $modulesFound

if ($modulesFound.Count -gt 0) {
    $RMADGrab.Meta.IsDRE = $true
    $RMADGrab.Meta.RMADEdition = "Forest Edition (DRE)"
    Write-Host "RMAD Edition: Forest Edition (DRE)"
} else {
    $RMADGrab.Meta.IsDRE = $false
    $RMADGrab.Meta.RMADEdition = "Standard Edition"
    Write-Host "RMAD Edition: Standard Edition"
}

Write-Host ""
Write-Host "=== Edition & Version Detection Complete ==="
Write-Host "`n"

# ---------------------------------------------------------
# MODULE DISCOVERY
# ---------------------------------------------------------
Write-Host "=== MODULE DISCOVERY ==="

$rmadRegPath = "HKLM:\SOFTWARE\Quest\Recovery Manager for Active Directory"
$installPath = (Get-ItemProperty -Path $rmadRegPath -ErrorAction SilentlyContinue).InstallPath

$RMADGrab.InstallPath = $installPath

if (-not $installPath) {
    Write-Warning "RMAD InstallPath not found. Cannot load modules."
    $RMADGrab.LoadedModules = @()
} else {
    Write-Host "RMAD InstallPath: $installPath"

    $dll64 = Join-Path $installPath "QuestSoftware.RecoveryManager.AD.PowerShell64.dll"
    $dllFEPath = Join-Path $installPath "QuestSoftware.RecoveryManager.AD.PowerShellFE.dll"

    $loadedModules = @()

    foreach ($dll in @($dll64, $dllFEPath)) {
        if (Test-Path $dll) {
            try {
                Import-Module $dll -ErrorAction SilentlyContinue
                Write-Host "Loaded module: $dll"
                $loadedModules += $dll
            } catch {
                Write-Warning "Failed to load module: $dll"
            }
        } else {
            Write-Warning "Module not found: $dll"
        }
    }

    $RMADGrab.LoadedModules = $loadedModules
}

Write-Host "`n"

# ---------------------------------------------------------
# SERVER IDENTITY
# ---------------------------------------------------------
Write-Host "=== SERVER IDENTITY ==="

$hostname = $env:COMPUTERNAME
$ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
       Where-Object { $_.IPAddress -notlike "169.*" }).IPAddress

$rmadVerDetail = $rmadVer

$RMADGrab.ServerIdentity = @{
    Hostname    = $hostname
    IPAddresses = $ip
    RMADVersion = $rmadVerDetail
}

Write-Host "Hostname: $hostname"
Write-Host "IP: $ip"
Write-Host "RMAD Version: $($rmadVerDetail.DisplayVersion)"
Write-Host "`n"

# ---------------------------------------------------------
# GLOBAL OPTIONS
# ---------------------------------------------------------
Write-Host "=== GLOBAL OPTIONS ==="

try {
    $glSet = Get-RMADGlobalOptions -ErrorAction SilentlyContinue
    $RMADGrab.GlobalOptions = $glSet
    if ($glSet) { $glSet | Format-List * }
} catch {
    Write-Warning "Global Options unavailable."
    $RMADGrab.GlobalOptions = $null
}

Write-Host "`n"

# ---------------------------------------------------------
# COLLECTIONS
# ---------------------------------------------------------
Write-Host "=== COLLECTIONS ==="

$RMADGrab.Collections = @()

try {
    $collections = Get-RMADCollection -ErrorAction SilentlyContinue

    foreach ($coll in $collections) {
        Write-Host "`n--- $($coll.Name) ---"

        $items = Get-RMADCollectionItem -Name $coll.Name -ErrorAction SilentlyContinue

        $RMADGrab.Collections += [ordered]@{
            Name                       = $coll.Name
            BackupType                 = if ($coll.MakeWindowsServerBackup) { "BMR" } else { "AD" }
            EncryptionEnabled          = $coll.BackupPasswordEnabled
            ScheduleEnabled            = $coll.ScheduleEnabled
            Schedule                   = $coll.Schedule
            LastRun                    = $coll.LastRunDate
            LastResult                 = $coll.LastResult
            ConsoleSideBackupPath      = $coll.ConsoleSideBackupPath
            ConsoleSideRetention       = $coll.ConsoleSideRetentionPolicyCount
            AgentSideBackupPath        = $coll.AgentSideBackupPath
            AgentSideRetention         = $coll.AgentSideRetentionPolicyCount
            AgentCredential            = $coll.AgentCredential
            SecondaryStorageCredential = $coll.SecondaryStorageCredential
            StorageCredential          = $coll.StorageCredential
            ScheduleCredential         = $coll.ScheduleCredential
            DomainControllers          = $items.ComputerName
        }

        if ($items) {
            $items | Format-Table ComputerName, Enabled
        } else {
            Write-Warning "No collection items for $($coll.Name)."
        }
    }

} catch {
    Write-Warning "Collections unavailable."
}

Write-Host "`n"

# ---------------------------------------------------------
# BACKUP INVENTORY
# ---------------------------------------------------------
Write-Host "=== BACKUP INVENTORY (Last 30 Days) ==="

$RMADGrab.Backups = @()

try {
    $backups = Get-RMADBackup -MinDate (Get-Date).AddDays(-30) -ErrorAction SilentlyContinue
    $RMADGrab.Backups = $backups
    if ($backups) {
        $backups | Format-Table BackupID, ComputerName, Date, IsSecureStorage, Path
    } else {
        Write-Host "No backups in last 30 days."
    }
} catch {
    Write-Warning "Backup Inventory unavailable."
}

Write-Host "`n"

# ---------------------------------------------------------
# BACKUP INTEGRITY (READ-ONLY)
# ---------------------------------------------------------
Write-Host "=== BACKUP INTEGRITY (Last 5 Backups, No DB Write) ==="

$RMADGrab.BackupIntegrity = @()

try {
    if ($backups) {
        $integrity = $backups |
            Sort-Object Date -Descending |
            Select-Object -First 5 |
            Test-RMADBackup -NoUpdate -ErrorAction SilentlyContinue

        $RMADGrab.BackupIntegrity = $integrity
        if ($integrity) {
            $integrity | Format-Table BackupID, IntegrityStatus, Date
        } else {
            Write-Host "No integrity results."
        }
    } else {
        Write-Host "Skipping integrity: no backups."
    }
} catch {
    Write-Warning "Backup Integrity unavailable."
}

Write-Host "`n"

# ---------------------------------------------------------
# BACKUP SESSIONS
# ---------------------------------------------------------
Write-Host "=== BACKUP SESSIONS (Last 14 Days) ==="

$RMADGrab.Sessions = @()

try {
    $sessions = Get-RMADSession -DayCount 14 -ErrorAction SilentlyContinue
    $RMADGrab.Sessions = $sessions
    if ($sessions) {
        $sessions | Format-Table Date, FolderName, Result, Scheduled
    } else {
        Write-Host "No sessions in last 14 days."
    }
} catch {
    Write-Warning "Backup Sessions unavailable."
}

Write-Host "`n"

# ---------------------------------------------------------
# FAILED SESSION ITEMS (DYNAMIC)
# ---------------------------------------------------------
Write-Host "=== FAILED SESSION ITEMS ==="

$RMADGrab.FailedSessionItems = @()

try {
    if ($sessions) {
        $failed = $sessions | Where-Object { $_.Result -eq "Error" }
        if ($failed) {
            $items = $failed | Get-RMADSessionItem -ErrorAction SilentlyContinue
            $RMADGrab.FailedSessionItems = $items

            if ($items) {
                $props = $items | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                if ($props) {
                    $items | Select-Object $props | Format-Table -AutoSize
                } else {
                    Write-Warning "Failed SessionItems returned no properties."
                }
            } else {
                Write-Host "No SessionItems for failed sessions."
            }
        } else {
            Write-Host "No failed sessions."
        }
    } else {
        Write-Host "No sessions to analyze."
    }
} catch {
    Write-Warning "Failed Session Items unavailable."
}

Write-Host "`n"

# ---------------------------------------------------------
# HYBRID RECOVERY (DRE-only)
# ---------------------------------------------------------
Write-Host "=== HYBRID RECOVERY ==="

$RMADGrab.HybridRecovery = [ordered]@{
    Global  = $null
    Domains = @()
}

if ($RMADGrab.Meta.IsDRE) {
    try {
        $hyGlobal  = Get-RMADHybridRecoveryOptions -ErrorAction SilentlyContinue
        $hyDomains = Get-RMADHybridRecoveryDomainOptions -ErrorAction SilentlyContinue

        $RMADGrab.HybridRecovery.Global  = $hyGlobal
        $RMADGrab.HybridRecovery.Domains = $hyDomains

        if ($hyGlobal)  { $hyGlobal  | Format-List * }
        if ($hyDomains) { $hyDomains | Format-Table DomainName, Enabled, TenantId }
    } catch {
        Write-Warning "Hybrid Recovery unavailable."
    }
} else {
    Skip-Section "HybridRecovery (Standard Edition)"
}

Write-Host "`n"

# ---------------------------------------------------------
# FOREST RECOVERY (DRE-only, READ-ONLY)
# ---------------------------------------------------------
Write-Host "=== FOREST RECOVERY ==="

$RMADGrab.ForestRecovery = [ordered]@{
    Project        = $null
    Domains        = @()
    Computers      = @()
    FaultTolerance = $null
}

if ($RMADGrab.Meta.IsDRE) {
    try {
        $feProj  = Get-RMADFEProject        -ErrorAction SilentlyContinue
        $feDom   = Get-RMADFEDomain         -ErrorAction SilentlyContinue
        $feComp  = Get-RMADFEComputer       -ErrorAction SilentlyContinue
        $feFault = Get-RMADFEFaultTolerance -ErrorAction SilentlyContinue

        $RMADGrab.ForestRecovery.Project        = $feProj
        $RMADGrab.ForestRecovery.Domains        = $feDom
        $RMADGrab.ForestRecovery.Computers      = $feComp
        $RMADGrab.ForestRecovery.FaultTolerance = $feFault

        if ($feProj)  { $feProj  | Format-List * }
        if ($feDom)   { $feDom   | Format-Table Name, ForestName, DomainID }
        if ($feComp)  { $feComp  | Format-Table ComputerName, DomainName, Role }
        if ($feFault) { $feFault | Format-List * }
    } catch {
        Write-Warning "Forest Recovery unavailable."
    }
} else {
    Skip-Section "ForestRecovery (Standard Edition)"
}

Write-Host "`n"

# ---------------------------------------------------------
# DIRECTORY SERVICE (Resilient Version)
# ---------------------------------------------------------
Write-Host "=== DIRECTORY SERVICE (Resilient) ==="

$RMADGrab.DirectoryService = [ordered]@{
    RecycleBinEnabled      = $null
    TombstoneLifetimeDays  = $null
    Diagnostics            = @()
}

function Add-Diag { param($msg) ; $RMADGrab.DirectoryService.Diagnostics += $msg ; Write-Host $msg }

try {
    Add-Diag "Step 1: Attempting Get-ADForest..."

    $forest = $null
    try {
        $forest = Get-ADForest -ErrorAction Stop
        Add-Diag "  Forest retrieved."
        Add-Diag "  Forest.ConfigurationNamingContext: $($forest.ConfigurationNamingContext)"
    }
    catch {
        Add-Diag "  Get-ADForest FAILED: $($_.Exception.Message)"
    }

    # Always fall back to RootDSE if forest object is missing config DN
    if ($forest -and $forest.ConfigurationNamingContext) {
        $configDN = $forest.ConfigurationNamingContext
        Add-Diag "  Using ConfigurationNamingContext from Get-ADForest."
    }
    else {
        Add-Diag "  Forest.ConfigurationNamingContext is EMPTY. Falling back to RootDSE..."
        try {
            $rootDSE = Get-ADRootDSE -ErrorAction Stop
            $configDN = $rootDSE.configurationNamingContext
            Add-Diag "  RootDSE configurationNamingContext: $configDN"
        }
        catch {
            Add-Diag "  RootDSE lookup FAILED: $($_.Exception.Message)"
            throw
        }
    }

    # Recycle Bin Detection
    Add-Diag "Step 2: Checking Recycle Bin Feature object..."

    $rbPath = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$configDN"
    Add-Diag "  Recycle Bin SearchBase: $rbPath"

    try {
        $rbObj = Get-ADObject -Filter * -SearchBase $rbPath -ErrorAction Stop
        Add-Diag "  Recycle Bin object FOUND."
        $RMADGrab.DirectoryService.RecycleBinEnabled = $true
    }
    catch {
        Add-Diag "  Recycle Bin object NOT found or query failed: $($_.Exception.Message)"
        $RMADGrab.DirectoryService.RecycleBinEnabled = $false
    }

    # Tombstone Lifetime Detection
    Add-Diag "Step 3: Checking Directory Service object for tombstoneLifetime..."

    $dsPath = "CN=Directory Service,CN=Windows NT,CN=Services,$configDN"
    Add-Diag "  Directory Service object DN: $dsPath"

    try {
        $dsObj = Get-ADObject -Identity $dsPath -Properties tombstoneLifetime -ErrorAction Stop
        Add-Diag "  Directory Service object retrieved."

        if ($dsObj.tombstoneLifetime) {
            Add-Diag "  tombstoneLifetime attribute present: $($dsObj.tombstoneLifetime)"
            $RMADGrab.DirectoryService.TombstoneLifetimeDays = $dsObj.tombstoneLifetime
        }
        else {
            Add-Diag "  tombstoneLifetime attribute NOT present. Using default 180."
            $RMADGrab.DirectoryService.TombstoneLifetimeDays = 180
        }
    }
    catch {
        Add-Diag "  Failed to retrieve Directory Service object: $($_.Exception.Message)"
        Add-Diag "  Using default tombstoneLifetime = 180."
        $RMADGrab.DirectoryService.TombstoneLifetimeDays = 180
    }
}
catch {
    Add-Diag "FATAL: Entire Directory Service block failed: $($_.Exception.Message)"
}

Write-Host "`n"

# ---------------------------------------------------------
# EXPORT JSON (PRETTY + MINIFIED)
# ---------------------------------------------------------
Write-Host "=== EXPORT JSON ==="

$prettyJson = $RMADGrab | ConvertTo-Json -Depth 10
$prettyJson | Out-File $jsonFile -Encoding UTF8

$minJson = $RMADGrab | ConvertTo-Json -Depth 10 -Compress
$minJson | Out-File $jsonMin -Encoding UTF8

Write-Host "Pretty JSON written to:  $jsonFile"
Write-Host "Minified JSON written to: $jsonMin"

# ---------------------------------------------------------
# EXPORT MARKDOWN
# ---------------------------------------------------------
Write-Host "=== EXPORT MARKDOWN ==="

'## RMADGrab Baseline Extractor' | Out-File $mdFile -Encoding UTF8
"Generated: $(Get-Date)"         | Add-Content $mdFile
""                               | Add-Content $mdFile

foreach ($key in $RMADGrab.Keys) {

    "## $key"     | Add-Content $mdFile
    '```json'     | Add-Content $mdFile

    $RMADGrab[$key] |
        ConvertTo-Json -Depth 10 |
        Out-String |
        ForEach-Object { $_ } |
        Add-Content $mdFile

    '```'         | Add-Content $mdFile
    ""            | Add-Content $mdFile
}

Write-Host "Markdown written to: $mdFile"
Write-Host ""
Write-Host "==================================="
Write-Host " RMADGrab v2.2 COMPLETE"
Write-Host "==================================="
