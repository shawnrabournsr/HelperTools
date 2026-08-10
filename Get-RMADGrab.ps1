<#
.SYNOPSIS
    RMADGrab v3.2
    RMAD Baseline Extractor (Edition-aware, Version-aware)

.DESCRIPTION
    Extracts RMAD configuration, collections, backup posture, forest recovery,
    hybrid recovery, sessions, environment identity, and directory service
    (Recycle Bin + Tombstone Lifetime).

    Changes from v3.1:
        - Fixed edition detection false negative on real DRE/Forest Edition
          servers: v3.1 only read the registry (InstallPath, and thus the FE
          DLL path check) inside the "PSSnapin not registered" fallback
          branch of module loading. Whenever the base RMAD cmdlets were
          already loaded in the session (the common case when RMADGrab is
          run from RMAD's own Management Shell shortcut), that branch never
          ran, so InstallPath stayed null and edition detection had nothing
          to check besides "is Get-RMADFEProject already loaded" - which can
          be false even on genuine DRE installs if the FE-specific module
          just wasn't imported into that particular session. Confirmed on a
          real customer server: RMAD Version Detected correctly showed
          "Disaster Recovery Edition" from the uninstall string, but Edition
          Detection still reported "Standard Edition".
        - The registry actually exposes a direct, authoritative signal for
          this: HKLM:\SOFTWARE\Quest\Recovery Manager for Active
          Directory\ForestEdition (REG_DWORD, 1 = DRE/Forest Edition). The
          registry is now always read up front regardless of module load
          path, and this flag is the primary edition signal - cmdlet/DLL
          presence are secondary confirmation only.
        - Added a separate, independent probe/load attempt for the
          Forest Edition-specific module, decoupled from the base-cmdlet
          check - so a session with the base snap-in already loaded still
          gets a chance to pick up the FE module if it's missing.
        - If the registry confirms DRE but FE cmdlets still aren't available
          after that load attempt, this is now surfaced as an explicit
          warning (rather than silently mislabeling as Standard Edition or
          just having Forest Recovery/Hybrid Recovery/Cloud Storage sections
          come back "unavailable" with no explanation).
        - Registry CurrentVersion is now used as a fallback source for
          RMADVersion if the uninstall-key lookup finds nothing.

    Changes from v3.0:
        - Added a Secure Storage section: lists registered Secure Storage
          servers (Get-RMADStorageServer) and spot-checks a sample of
          Secure Storage-backed backups (Test-RMADSecureStorageBackup).
        - Added a Cloud Storage (Tier 2) section, DRE/Forest Edition-only:
          reports on Azure Blob / AWS S3 targets registered via
          Get-RMADFECloudStorage. Skips gracefully (with a message) on
          Standard Edition or if the cmdlet isn't present.
        - Added a generic Get-RedactedObject helper for object types whose
          exact schema isn't confirmed from Quest's docs (StorageServer,
          CloudStorage) - scans every property and redacts anything whose
          *name* looks secret-shaped, rather than dumping the object as-is.
        - Broadened the redaction match pattern from "Credential|Password|
          Secret" to also catch "ConnectionString", "AccessKey", "ApiKey",
          "Token", "Pwd", and anything ending in "Key". This closes a real
          gap: Set-RMADFECloudStorage takes -AzureConnectionString and
          -AwsAccessKey directly (an Azure connection string typically
          embeds the storage account key), and the old pattern would have
          missed both.
        - Made the Backup Integrity "no DB write" switch detection dynamic
          (probes Test-RMADBackup's actual parameter set at runtime) instead
          of hardcoding -NoUpdate, which doesn't exist on all versions.
          Confirmed via a live Get-Help against RMAD DRE that this cmdlet's
          parameter set is just -Id/-InputObject, -ShareCredential, and
          -UseStorageCredential - no write-control switch at all on that
          version - so the messaging reports what's actually known rather
          than assuming a database-write side effect.

    Changes from v2.2 (carried forward into v3.x):
        - Fixed version comparison bug: "$ver.Major -ge 10 -and $ver.Minor -ge 4"
          incorrectly flagged anything like 11.0 as "below 10.4". Now does a
          real System.Version comparison.
        - Fixed edition detection order/method: v2.2 checked Get-Module
          -ListAvailable BEFORE modules were ever imported, and that cmdlet
          only searches $env:PSModulePath - which RMAD's install directory
          usually isn't on. That meant IsDRE was almost always false, silently
          skipping Hybrid/Forest Recovery sections even on DRE. Now edition is
          detected AFTER module load, based on which cmdlets/DLLs are actually
          present.
        - Fixed AD Recycle Bin check: v2.2 checked whether the "Recycle Bin
          Feature" *definition* object exists under Optional Features, which
          is true on virtually every modern forest whether or not the feature
          is enabled. Now uses Get-ADOptionalFeature and checks EnabledScopes.
        - Redacts credential fields (AgentCredential, StorageCredential, etc.)
          before export - only username/"configured" flag is kept, never the
          full credential object.
        - Unified, hardened module loading (snap-in first, then registry-based
          DLL discovery across both registry views, with real error handling).
        - Consistent UTF8 encoding on all file writes.

    Outputs in current directory:
        - RMADGrab_yyyy-MM-dd_HHmmss.json      (pretty)
        - RMADGrab_yyyy-MM-dd_HHmmss.min.json  (minified)
        - RMADGrab_yyyy-MM-dd_HHmmss.md        (Markdown)
#>


Write-Host "========================================="
Write-Host " RMADGrab v3.2 - RMAD Baseline Extractor"
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

$RMADGrab.Meta = [ordered]@{
    ScriptVersion            = "3.2"
    RMADVersion              = $null
    RMADEdition              = "Unknown"
    IsDRE                    = $false
    ForestEditionRegistryFlag = $null
    VersionOK                = $false
    ModuleLoadMethod         = $null
    InstallPath              = $null
    LoadedModules            = @()
    Warnings                 = @()
    SkippedSections          = @()
}

function Add-Warn { param($msg) ; $RMADGrab.Meta.Warnings += $msg ; Write-Warning $msg }
function Skip-Section { param($name) ; $RMADGrab.Meta.SkippedSections += $name ; Write-Host "Skipping section: $name" }

# Redacts credential-bearing objects before they ever get written to disk.
# Only keeps whether a credential is configured and (if present) a username -
# never the credential object itself, which may carry secret material
# depending on how the underlying cmdlet populates it.
function Get-RedactedCredentialInfo {
    param($CredObj)

    if (-not $CredObj) {
        return [ordered]@{ Configured = $false }
    }

    $userName = $null
    foreach ($prop in @('UserName', 'User', 'Identity', 'Account')) {
        if ($CredObj.PSObject.Properties.Name -contains $prop -and $CredObj.$prop) {
            $userName = $CredObj.$prop
            break
        }
    }

    return [ordered]@{
        Configured = $true
        UserName   = $userName
        Note       = 'Secret material intentionally omitted from baseline export'
    }
}

# Generic version of the above for object types whose exact property schema
# isn't confirmed from Quest's documentation (e.g. StorageServer). Rather
# than guess specific property names and risk missing a secret-bearing one,
# this scans every property on the object and redacts anything whose *name*
# looks credential/password-shaped.
function Get-RedactedObject {
    param($InputObj)

    if (-not $InputObj) { return $null }

    $result = [ordered]@{}
    foreach ($prop in $InputObj.PSObject.Properties) {
        # Broad on purpose: a missed secret is a leak, a redacted non-secret is
        # just a slightly less informative export. Catches things like
        # AzureConnectionString (embeds an account key) and AwsAccessKey that
        # a narrower "Credential|Password|Secret" pattern would miss.
        if ($prop.Name -match 'Credential|Password|Secret|ConnectionString|AccessKey|ApiKey|Token|Pwd|Key$') {
            $result[$prop.Name] = Get-RedactedCredentialInfo -CredObj $prop.Value
        } else {
            $result[$prop.Name] = $prop.Value
        }
    }
    return [pscustomobject]$result
}

# ---------------------------------------------------------
# VERSION DETECTION
# ---------------------------------------------------------
Write-Host "=== RMADGrab v3.2 - Version Detection ==="

$uninstallRoots = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$rmadVer = Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
           Where-Object { $_.DisplayName -like "Recovery Manager for Active Directory*" } |
           Select-Object DisplayName, DisplayVersion, Publisher -First 1

if ($rmadVer) {
    $RMADGrab.Meta.RMADVersion = $rmadVer.DisplayVersion
    Write-Host "RMAD Version Detected: $($rmadVer.DisplayVersion) ($($rmadVer.DisplayName))"
} else {
    Add-Warn "RMAD not detected on this server (no matching uninstall registry entry). Extraction will be limited."
}

if ($RMADGrab.Meta.RMADVersion) {
    try {
        $ver = [version]$RMADGrab.Meta.RMADVersion
        if ($ver -ge [version]"10.4") {
            $RMADGrab.Meta.VersionOK = $true
            Write-Host "RMAD version is 10.4 or higher - OK."
        } else {
            Add-Warn "RMAD version is below 10.4 - some settings may not render correctly."
            $RMADGrab.Meta.VersionOK = $false
        }
    }
    catch {
        Add-Warn "Unable to parse RMAD version '$($RMADGrab.Meta.RMADVersion)' as a version number."
    }
}

Write-Host ""

# ---------------------------------------------------------
# MODULE DISCOVERY (must happen before edition detection)
# ---------------------------------------------------------
Write-Host "=== MODULE DISCOVERY ==="

# Always read the registry first, regardless of whether the base RMAD
# cmdlets are already loaded in this session. v3.1 only did this lookup
# inside the "snap-in not registered" fallback branch, which meant it was
# skipped entirely whenever cmdlets were already loaded - silently losing
# InstallPath (and the authoritative ForestEdition flag below) on exactly
# the common case of a session opened via RMAD's own Management Shell
# shortcut. That, in turn, broke edition detection on real DRE servers.
$regCandidates = @(
    "HKLM:\SOFTWARE\Quest\Recovery Manager for Active Directory",
    "HKLM:\SOFTWARE\WOW6432Node\Quest\Recovery Manager for Active Directory"
)

$rmadRegProps = $null
foreach ($regPath in $regCandidates) {
    $rmadRegProps = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if ($rmadRegProps) { break }
}

if ($rmadRegProps) {
    $RMADGrab.Meta.InstallPath = $rmadRegProps.InstallPath
    if ($null -ne $rmadRegProps.ForestEdition) {
        # ForestEdition is a REG_DWORD flag (0/1) written directly by the
        # installer - the single most authoritative edition signal
        # available, since it doesn't depend on what happens to be loaded
        # in the current PowerShell session.
        $RMADGrab.Meta.ForestEditionRegistryFlag = [bool]$rmadRegProps.ForestEdition
    }
    # Fallback source for version info if the uninstall-key lookup earlier
    # came up empty.
    if (-not $RMADGrab.Meta.RMADVersion -and $rmadRegProps.CurrentVersion) {
        $RMADGrab.Meta.RMADVersion = $rmadRegProps.CurrentVersion
        Write-Host "RMAD Version (from registry CurrentVersion, uninstall key lookup found nothing): $($rmadRegProps.CurrentVersion)"
    }
}

if (Get-Command Get-RMADBackup -ErrorAction SilentlyContinue) {
    $RMADGrab.Meta.ModuleLoadMethod = 'AlreadyLoaded'
    Write-Host "RMAD cmdlets already loaded in this session."
}
else {
    # Try the snap-in first - works on most standard installs.
    try {
        Add-PSSnapin Quest.RecoveryManager.AD.PowerShell -ErrorAction Stop
        $RMADGrab.Meta.ModuleLoadMethod = 'PSSnapin'
        Write-Host "Loaded via PSSnapin: Quest.RecoveryManager.AD.PowerShell"
    }
    catch {
        Write-Host "PSSnapin not available, falling back to registry-based module discovery..." -ForegroundColor Yellow

        if (-not $RMADGrab.Meta.InstallPath) {
            Add-Warn "RMAD InstallPath not found in the registry, and the PSSnapin isn't registered. Module-dependent sections will be skipped."
        }
        else {
            Write-Host "RMAD InstallPath: $($RMADGrab.Meta.InstallPath)"

            $candidateDlls = @(
                (Join-Path $RMADGrab.Meta.InstallPath "QuestSoftware.RecoveryManager.AD.PowerShell64.dll"),
                (Join-Path $RMADGrab.Meta.InstallPath "QuestSoftware.RecoveryManager.AD.PowerShell.dll"),
                (Join-Path $RMADGrab.Meta.InstallPath "QuestSoftware.RecoveryManager.AD.PowerShellFE.dll")
            )

            $loadedModules = @()
            foreach ($dll in $candidateDlls) {
                if (Test-Path -LiteralPath $dll) {
                    try {
                        Import-Module $dll -ErrorAction Stop
                        Write-Host "Loaded module: $dll"
                        $loadedModules += $dll
                    }
                    catch {
                        Add-Warn "Failed to load module '$dll': $($_.Exception.Message)"
                    }
                }
            }

            $RMADGrab.Meta.LoadedModules = $loadedModules
            $RMADGrab.Meta.ModuleLoadMethod = 'RegistryDllImport'

            if ($loadedModules.Count -eq 0) {
                Add-Warn "No RMAD PowerShell module DLLs could be loaded from '$($RMADGrab.Meta.InstallPath)'."
            }
        }
    }

    if (-not (Get-Command Get-RMADBackup -ErrorAction SilentlyContinue)) {
        Add-Warn "RMAD cmdlets are not available after module discovery. All RMAD-cmdlet-dependent sections will be skipped."
    }
}

# Separately probe for the Forest Edition-specific module. This has to be
# independent of the base-cmdlet check above: a session can have the base
# snap-in already loaded (e.g. opened via a shortcut that's been carried
# forward through years of upgrades) without the FE-specific module ever
# having been imported into that same session, even on a genuine DRE/FE
# install. That mismatch is exactly what produced a false "Standard Edition"
# read on an actual DRE server - the base cmdlets were "AlreadyLoaded" so the
# registry/DLL-loading branch above never ran at all.
if (-not (Get-Command Get-RMADFEProject -ErrorAction SilentlyContinue) -and $RMADGrab.Meta.InstallPath) {
    $feDll = Join-Path $RMADGrab.Meta.InstallPath "QuestSoftware.RecoveryManager.AD.PowerShellFE.dll"
    if (Test-Path -LiteralPath $feDll) {
        try {
            Import-Module $feDll -ErrorAction Stop
            Write-Host "Loaded FE module: $feDll"
        }
        catch {
            Add-Warn "Found the Forest Edition module DLL at '$feDll' but failed to load it: $($_.Exception.Message)"
        }
    }
}

Write-Host ""

# ---------------------------------------------------------
# EDITION DETECTION (now runs AFTER modules are loaded)
# ---------------------------------------------------------
Write-Host "=== EDITION DETECTION ==="

# The registry's ForestEdition flag is the primary, authoritative signal -
# it reflects what was actually installed, not what happens to be loaded in
# this particular session. Cmdlet/DLL presence are secondary confirmation
# and a fallback for cases where the registry value isn't available.
$feRegistryFlag  = $RMADGrab.Meta.ForestEditionRegistryFlag -eq $true
$feCmdletPresent = [bool](Get-Command Get-RMADFEProject -ErrorAction SilentlyContinue)

$feDllOnDisk = $false
if ($RMADGrab.Meta.InstallPath) {
    $feDllOnDisk = Test-Path -LiteralPath (Join-Path $RMADGrab.Meta.InstallPath "QuestSoftware.RecoveryManager.AD.PowerShellFE.dll")
}

if ($feRegistryFlag -or $feCmdletPresent -or $feDllOnDisk) {
    $RMADGrab.Meta.IsDRE = $true
    $RMADGrab.Meta.RMADEdition = "Forest Edition (DRE)"
} else {
    $RMADGrab.Meta.IsDRE = $false
    $RMADGrab.Meta.RMADEdition = "Standard Edition"
}

# If the registry confirms DRE but the FE cmdlets still aren't loaded even
# after the load attempt above (e.g. the DLL wasn't where we expected, or
# failed to import), say so explicitly - otherwise the Forest
# Recovery/Hybrid Recovery/Cloud Storage sections further down will just
# come back "unavailable" with no indication that the edition itself was
# identified correctly.
if ($feRegistryFlag -and -not $feCmdletPresent) {
    Add-Warn "Registry confirms this install is Forest Edition/DRE (ForestEdition=1), but Forest Edition-specific cmdlets (e.g. Get-RMADFEProject) are still not available in this session even after attempting to load the FE module. Forest Recovery / Hybrid Recovery / Cloud Storage sections below may report 'unavailable' despite the feature genuinely being present - try re-running from the 'Recovery Manager for Active Directory Forest Edition' Management Shell shortcut specifically."
}

Write-Host "RMAD Edition: $($RMADGrab.Meta.RMADEdition) (registry flag: $feRegistryFlag, FE cmdlet loaded: $feCmdletPresent, FE DLL on disk: $feDllOnDisk)"
Write-Host "=== Edition & Version Detection Complete ===`n"

# ---------------------------------------------------------
# SERVER IDENTITY
# ---------------------------------------------------------
Write-Host "=== SERVER IDENTITY ==="

$hostname = $env:COMPUTERNAME
$ipAddresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" -and $_.AddressState -eq 'Preferred' } |
               Select-Object -ExpandProperty IPAddress

$RMADGrab.ServerIdentity = [ordered]@{
    Hostname    = $hostname
    IPAddresses = $ipAddresses
    RMADVersion = $rmadVer
}

Write-Host "Hostname: $hostname"
Write-Host "IP: $($ipAddresses -join ', ')"
Write-Host "RMAD Version: $($rmadVer.DisplayVersion)"
Write-Host "`n"

# ---------------------------------------------------------
# GLOBAL OPTIONS
# ---------------------------------------------------------
Write-Host "=== GLOBAL OPTIONS ==="

try {
    $glSet = Get-RMADGlobalOptions -ErrorAction Stop
    $RMADGrab.GlobalOptions = $glSet
    if ($glSet) { $glSet | Format-List * }
} catch {
    Write-Warning "Global Options unavailable: $($_.Exception.Message)"
    $RMADGrab.GlobalOptions = $null
}

Write-Host "`n"

# ---------------------------------------------------------
# COLLECTIONS (credential fields redacted before storage)
# ---------------------------------------------------------
Write-Host "=== COLLECTIONS ==="

$RMADGrab.Collections = @()

try {
    $collections = Get-RMADCollection -ErrorAction Stop

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
            AgentCredential            = Get-RedactedCredentialInfo -CredObj $coll.AgentCredential
            SecondaryStorageCredential = Get-RedactedCredentialInfo -CredObj $coll.SecondaryStorageCredential
            StorageCredential          = Get-RedactedCredentialInfo -CredObj $coll.StorageCredential
            ScheduleCredential         = Get-RedactedCredentialInfo -CredObj $coll.ScheduleCredential
            DomainControllers          = $items.ComputerName
        }

        if ($items) {
            $items | Format-Table ComputerName, Enabled
        } else {
            Write-Warning "No collection items for $($coll.Name)."
        }
    }

} catch {
    Write-Warning "Collections unavailable: $($_.Exception.Message)"
}

Write-Host "`n"

# ---------------------------------------------------------
# BACKUP INVENTORY
# ---------------------------------------------------------
Write-Host "=== BACKUP INVENTORY (Last 30 Days) ==="

$RMADGrab.Backups = @()
$backups = $null

try {
    $backups = Get-RMADBackup -MinDate (Get-Date).AddDays(-30) -ErrorAction Stop
    $RMADGrab.Backups = $backups
    if ($backups) {
        $backups | Format-Table BackupID, ComputerName, Date, IsSecureStorage, Path
    } else {
        Write-Host "No backups in last 30 days."
    }
} catch {
    Write-Warning "Backup Inventory unavailable: $($_.Exception.Message)"
}

Write-Host "`n"

# ---------------------------------------------------------
# BACKUP INTEGRITY (READ-ONLY)
# ---------------------------------------------------------
Write-Host "=== BACKUP INTEGRITY (Last 5 Backups) ==="

$RMADGrab.BackupIntegrity = @()

# NOTE: confirmed via `Get-Help Test-RMADBackup -Full` against a live RMAD
# Forest Edition install that this cmdlet's parameter set is just
# -Id/-InputObject, -ShareCredential, -UseStorageCredential - there is no
# "don't write to the database" switch at all, on any version we've checked.
# Quest's own description says it "calculates the checksum of the backup
# file and compares it with the checksum stored in the backup" - it does not
# document writing status back to the registration database as a side
# effect. So the v2.2 comment "No DB Write" appears to have been an
# assumption baked into the original script rather than a real, confirmed
# behavior (or a real switch that existed in some other version).
#
# We still probe for a few plausible parameter names in case some other
# RMAD version *does* expose write-control, so this keeps working if that
# ever turns out to be true - but we no longer warn alarmingly about a
# side effect we have no evidence for.
$noDbWriteParamCandidates = @('NoUpdate', 'DoNotUpdate', 'SkipUpdate', 'ReadOnly', 'CheckOnly', 'NoDbUpdate', 'NoDatabaseUpdate')
$noDbWriteParam = $null

$testCmd = Get-Command Test-RMADBackup -ErrorAction SilentlyContinue
if ($testCmd) {
    foreach ($candidate in $noDbWriteParamCandidates) {
        if ($testCmd.Parameters.ContainsKey($candidate)) {
            $noDbWriteParam = $candidate
            break
        }
    }
}

if ($noDbWriteParam) {
    Write-Host "Using -$noDbWriteParam to avoid writing status back to the backup registration database."
} elseif ($testCmd) {
    Write-Host "This RMAD version's Test-RMADBackup has no write-control switch (only Id/InputObject/ShareCredential/UseStorageCredential per Get-Help) - proceeding as-is. Quest's documentation for this cmdlet doesn't describe a database-write side effect."
}

try {
    if ($backups) {
        $testParams = @{ ErrorAction = 'Stop' }
        if ($noDbWriteParam) { $testParams[$noDbWriteParam] = $true }

        $integrity = $backups |
            Sort-Object Date -Descending |
            Select-Object -First 5 |
            Test-RMADBackup @testParams

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
    Write-Warning "Backup Integrity unavailable: $($_.Exception.Message)"
}

Write-Host "`n"

# ---------------------------------------------------------
# SECURE STORAGE
# ---------------------------------------------------------
Write-Host "=== SECURE STORAGE ==="

$RMADGrab.SecureStorage = [ordered]@{
    Servers      = @()
    BackupChecks = @()
}

try {
    $storageServers = Get-RMADStorageServer -ErrorAction Stop

    if ($storageServers) {
        foreach ($srv in $storageServers) {
            $RMADGrab.SecureStorage.Servers += (Get-RedactedObject -InputObj $srv)
        }
        $storageServers | Format-List *
    } else {
        Write-Host "No secure storage servers registered."
    }
} catch {
    Write-Warning "Secure Storage Servers unavailable: $($_.Exception.Message)"
}

Write-Host ""

# Spot-check reachability/integrity of a sample of Secure Storage-backed
# backups, if any showed up in the last-30-days inventory above and the
# cmdlet is available on this version.
try {
    if ($backups) {
        $secureBackups = $backups | Where-Object { $_.IsSecureStorage }

        if ($secureBackups) {
            $testSSCmd = Get-Command Test-RMADSecureStorageBackup -ErrorAction SilentlyContinue
            if ($testSSCmd) {
                $ssResults = $secureBackups | Select-Object -First 5 | Test-RMADSecureStorageBackup -ErrorAction Stop
                $RMADGrab.SecureStorage.BackupChecks = $ssResults
                if ($ssResults) {
                    $ssResults | Format-Table -AutoSize
                } else {
                    Write-Host "No results from Test-RMADSecureStorageBackup."
                }
            } else {
                Write-Host "Test-RMADSecureStorageBackup cmdlet not available on this RMAD version - skipping."
            }
        } else {
            Write-Host "No Secure Storage-backed backups found in the last-30-days sample."
        }
    } else {
        Write-Host "Skipping Secure Storage backup check: no backup inventory available."
    }
} catch {
    Write-Warning "Secure Storage backup check unavailable: $($_.Exception.Message)"
}

Write-Host "`n"

# ---------------------------------------------------------
# CLOUD STORAGE (Tier 2 - Azure Blob / AWS S3, DRE-only)
# ---------------------------------------------------------
# NOTE: this is a distinct feature from the on-prem Secure Storage server
# above. RMAD DRE/Forest Edition can additionally copy backups to an Azure
# Blob or AWS S3 container as a secondary (Tier 2) destination, configured
# via Get-RMADFECloudStorage / Set-RMADFECloudStorage. Confirmed from Quest's
# docs that Set-RMADFECloudStorage takes -AzureConnectionString,
# -AwsAccessKey, and -AwsSecretKey directly - an Azure connection string in
# particular typically embeds the storage account key. If Get-RMADFECloudStorage
# returns the same properties, that's real secret material, so this section
# goes through the same generic Get-RedactedObject redaction as everything
# else rather than being dumped raw.
Write-Host "=== CLOUD STORAGE (Tier 2) ==="

$RMADGrab.CloudStorage = @()

if ($RMADGrab.Meta.IsDRE) {
    try {
        $cloudStorageCmd = Get-Command Get-RMADFECloudStorage -ErrorAction SilentlyContinue
        if ($cloudStorageCmd) {
            $cloudStorage = Get-RMADFECloudStorage -ErrorAction Stop

            if ($cloudStorage) {
                foreach ($cs in $cloudStorage) {
                    $RMADGrab.CloudStorage += (Get-RedactedObject -InputObj $cs)
                }
                # Format-List on the redacted objects, not the raw ones - the
                # console output shouldn't leak what the export doesn't.
                $RMADGrab.CloudStorage | Format-List *
            } else {
                Write-Host "No cloud storage (Azure Blob / AWS S3) registered."
            }
        } else {
            Write-Host "Get-RMADFECloudStorage cmdlet not available on this RMAD version/edition - skipping."
        }
    } catch {
        Write-Warning "Cloud Storage unavailable: $($_.Exception.Message)"
    }
} else {
    Skip-Section "CloudStorage (Standard Edition - Tier 2 cloud storage requires DRE/Forest Edition)"
}

Write-Host "`n"

# ---------------------------------------------------------
# BACKUP SESSIONS
# ---------------------------------------------------------
Write-Host "=== BACKUP SESSIONS (Last 14 Days) ==="

$RMADGrab.Sessions = @()
$sessions = $null

try {
    $sessions = Get-RMADSession -DayCount 14 -ErrorAction Stop
    $RMADGrab.Sessions = $sessions
    if ($sessions) {
        $sessions | Format-Table Date, FolderName, Result, Scheduled
    } else {
        Write-Host "No sessions in last 14 days."
    }
} catch {
    Write-Warning "Backup Sessions unavailable: $($_.Exception.Message)"
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
            $items = $failed | Get-RMADSessionItem -ErrorAction Stop
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
    Write-Warning "Failed Session Items unavailable: $($_.Exception.Message)"
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
        $hyGlobal  = Get-RMADHybridRecoveryOptions -ErrorAction Stop
        $hyDomains = Get-RMADHybridRecoveryDomainOptions -ErrorAction Stop

        $RMADGrab.HybridRecovery.Global  = $hyGlobal
        $RMADGrab.HybridRecovery.Domains = $hyDomains

        if ($hyGlobal)  { $hyGlobal  | Format-List * }
        if ($hyDomains) { $hyDomains | Format-Table DomainName, Enabled, TenantId }
    } catch {
        Write-Warning "Hybrid Recovery unavailable: $($_.Exception.Message)"
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
        $feProj  = Get-RMADFEProject        -ErrorAction Stop
        $feDom   = Get-RMADFEDomain         -ErrorAction Stop
        $feComp  = Get-RMADFEComputer       -ErrorAction Stop
        $feFault = Get-RMADFEFaultTolerance -ErrorAction Stop

        $RMADGrab.ForestRecovery.Project        = $feProj
        $RMADGrab.ForestRecovery.Domains        = $feDom
        $RMADGrab.ForestRecovery.Computers      = $feComp
        $RMADGrab.ForestRecovery.FaultTolerance = $feFault

        if ($feProj)  { $feProj  | Format-List * }
        if ($feDom)   { $feDom   | Format-Table Name, ForestName, DomainID }
        if ($feComp)  { $feComp  | Format-Table ComputerName, DomainName, Role }
        if ($feFault) { $feFault | Format-List * }
    } catch {
        Write-Warning "Forest Recovery unavailable: $($_.Exception.Message)"
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
    RecycleBinEnabled     = $null
    RecycleBinCheckMethod = $null
    TombstoneLifetimeDays = $null
    Diagnostics           = @()
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

    # --- Recycle Bin Detection ---
    # NOTE (v3 fix): the presence of the "Recycle Bin Feature" definition
    # object under CN=Optional Features does NOT mean the feature is enabled -
    # that object exists on essentially every forest at FFL 2008 R2+
    # regardless of whether Recycle Bin was ever turned on. The only reliable
    # signal is whether the feature has EnabledScopes populated, which
    # Get-ADOptionalFeature exposes directly.
    Add-Diag "Step 2: Checking AD Recycle Bin enabled state via Get-ADOptionalFeature..."

    try {
        $rbFeature = Get-ADOptionalFeature -Filter { Name -eq "Recycle Bin Feature" } -ErrorAction Stop

        if ($rbFeature -and $rbFeature.EnabledScopes -and $rbFeature.EnabledScopes.Count -gt 0) {
            $RMADGrab.DirectoryService.RecycleBinEnabled = $true
            $RMADGrab.DirectoryService.RecycleBinCheckMethod = 'EnabledScopes'
            Add-Diag "  Recycle Bin ENABLED. EnabledScopes: $($rbFeature.EnabledScopes -join ', ')"
        }
        elseif ($rbFeature) {
            $RMADGrab.DirectoryService.RecycleBinEnabled = $false
            $RMADGrab.DirectoryService.RecycleBinCheckMethod = 'EnabledScopes'
            Add-Diag "  Recycle Bin feature exists but EnabledScopes is empty - NOT enabled."
        }
        else {
            $RMADGrab.DirectoryService.RecycleBinEnabled = $false
            $RMADGrab.DirectoryService.RecycleBinCheckMethod = 'EnabledScopes'
            Add-Diag "  Recycle Bin Feature object not returned by Get-ADOptionalFeature - treating as not enabled."
        }
    }
    catch {
        Add-Diag "  Get-ADOptionalFeature FAILED ($($_.Exception.Message)). Falling back to object-existence check."
        Add-Diag "  WARNING: this fallback only confirms the feature is definable on this forest, NOT that it is enabled - treat this result as low-confidence."

        $rbPath = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$configDN"
        try {
            $rbObj = Get-ADObject -Filter * -SearchBase $rbPath -ErrorAction Stop
            $RMADGrab.DirectoryService.RecycleBinEnabled = $null
            $RMADGrab.DirectoryService.RecycleBinCheckMethod = 'FeatureObjectExistsOnly-LowConfidence'
            Add-Diag "  Recycle Bin feature object found, but enabled state is UNKNOWN with this fallback method."
        }
        catch {
            $RMADGrab.DirectoryService.RecycleBinEnabled = $false
            $RMADGrab.DirectoryService.RecycleBinCheckMethod = 'FeatureObjectExistsOnly-LowConfidence'
            Add-Diag "  Recycle Bin object NOT found either: $($_.Exception.Message)"
        }
    }

    # --- Tombstone Lifetime Detection ---
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
"Generated: $(Get-Date)"         | Add-Content $mdFile -Encoding UTF8
""                               | Add-Content $mdFile -Encoding UTF8

foreach ($key in $RMADGrab.Keys) {

    "## $key"     | Add-Content $mdFile -Encoding UTF8
    '```json'     | Add-Content $mdFile -Encoding UTF8

    $RMADGrab[$key] |
        ConvertTo-Json -Depth 10 |
        Out-String |
        ForEach-Object { $_ } |
        Add-Content $mdFile -Encoding UTF8

    '```'         | Add-Content $mdFile -Encoding UTF8
    ""            | Add-Content $mdFile -Encoding UTF8
}

Write-Host "Markdown written to: $mdFile"
Write-Host ""
Write-Host "==================================="
Write-Host " RMADGrab v3.2 COMPLETE"
Write-Host "==================================="
