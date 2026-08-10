<#
.SYNOPSIS
    Reconciles the Recovery Manager for Active Directory (RMAD) backup catalog
    against the files that actually exist on disk, and unregisters any
    catalog entries whose backup file is missing ("ghost" entries).

.DESCRIPTION
    RMAD registers every backup it creates (or that you manually import) in its
    backup registration database. If someone deletes a .bkf/.vhdx file directly
    from the filesystem instead of using the RMAD console, the catalog still
    thinks the backup exists ("the index still says the book is on the shelf").
    That inflates the size RMAD reports vs. what's actually consuming disk space.

    This script:
      1. Reads every backup registered in the catalog (Get-RMADBackup -All).
      2. Verifies the backup file is actually present at its registered Path.
      3. If missing, logs it and unregisters it with Remove-RMADBackup.
      4. If present, leaves it alone and moves to the next one.

.NOTES
    - Run this ON the RMAD console server, in an elevated PowerShell session.
    - Requires the RMAD Management Shell snap-in to be installed (it ships
      with the RMAD "Core Components" / console install).
    - ALWAYS do a dry run first (-WhatIf, default in this script) before
      passing -Confirm to actually remove anything.
    - Back up the backup registration database (backups.mdb, typically under
      %ProgramData%\Quest\Recovery Manager for Active Directory) before running
      live, just in case.
    - Secure Storage server backups aren't plain files on the local filesystem
      in the same way -- this script skips those by default. Use
      Test-RMADSecureStorageBackup for that scenario instead.

.PARAMETER Remove
    If specified, actually unregisters the orphaned entries. Without this
    switch, the script only reports what it *would* remove (dry run).

.PARAMETER LogPath
    Optional path to a CSV file where the results (found / missing) are logged.

.EXAMPLE
    # Dry run - just see what's orphaned, nothing is changed
    .\Invoke-RMADCatalogCleanup.ps1

.EXAMPLE
    # Actually unregister the orphaned entries, logging everything to CSV
    .\Invoke-RMADCatalogCleanup.ps1 -Remove -LogPath C:\Temp\RMAD-Cleanup.csv

.EXAMPLE
    # Same as above, but skip all confirmation prompts (useful when there are
    # a lot of orphaned entries and clicking through prompts isn't practical)
    .\Invoke-RMADCatalogCleanup.ps1 -Remove -Force -LogPath C:\Temp\RMAD-Cleanup.csv
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Remove,
    [switch]$Force,
    [string]$LogPath
)

# --- Make sure the RMAD Management Shell cmdlets are loaded ---
# Layered approach: if Get-RMADBackup is already available, do nothing. Otherwise
# try the snap-in name first (fast path), and if that fails, fall back to
# discovering the install path from the registry and importing the DLLs directly.
# This makes the script resilient across RMAD versions/editions where the
# snap-in name or install location isn't guaranteed to match what we expect.

$RMADModuleInfo = [pscustomobject]@{
    InstallPath   = $null
    LoadMethod    = $null
    LoadedModules = @()
}

if (Get-Command Get-RMADBackup -ErrorAction SilentlyContinue) {
    $RMADModuleInfo.LoadMethod = 'AlreadyLoaded'
}
else {
    Write-Host "=== MODULE DISCOVERY ===" -ForegroundColor Cyan

    # First, try the snap-in - works on most standard installs
    try {
        Add-PSSnapin Quest.RecoveryManager.AD.PowerShell -ErrorAction Stop
        $RMADModuleInfo.LoadMethod = 'PSSnapin'
        Write-Host "Loaded via PSSnapin: Quest.RecoveryManager.AD.PowerShell"
    }
    catch {
        Write-Host "PSSnapin not available, falling back to registry-based module discovery..." -ForegroundColor Yellow

        # Check both the native and WOW6432Node registry locations, in case this
        # is a 32-bit registry view on a 64-bit OS.
        $regCandidates = @(
            "HKLM:\SOFTWARE\Quest\Recovery Manager for Active Directory",
            "HKLM:\SOFTWARE\WOW6432Node\Quest\Recovery Manager for Active Directory"
        )

        $installPath = $null
        foreach ($regPath in $regCandidates) {
            $installPath = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).InstallPath
            if ($installPath) { break }
        }

        $RMADModuleInfo.InstallPath = $installPath

        if (-not $installPath) {
            Write-Error "RMAD InstallPath not found in the registry, and the PSSnapin isn't registered. Make sure this is running on the RMAD console server with the Management Shell component installed."
            return
        }

        Write-Host "RMAD InstallPath: $installPath"

        # Candidate module DLLs - not every install has all of these; we load
        # whichever are present. Order matters least here since PowerShell will
        # just skip duplicate cmdlet registrations.
        $candidateDlls = @(
            (Join-Path $installPath "QuestSoftware.RecoveryManager.AD.PowerShell64.dll"),
            (Join-Path $installPath "QuestSoftware.RecoveryManager.AD.PowerShell.dll"),
            (Join-Path $installPath "QuestSoftware.RecoveryManager.AD.PowerShellFE.dll")
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
                    Write-Warning "Failed to load module: $dll - $_"
                }
            }
        }

        $RMADModuleInfo.LoadedModules = $loadedModules
        $RMADModuleInfo.LoadMethod = 'RegistryDllImport'

        if ($loadedModules.Count -eq 0) {
            Write-Error "No RMAD PowerShell module DLLs could be loaded from '$installPath'. Check that the Management Shell component is installed."
            return
        }
    }

    # Final check regardless of which path we took above
    if (-not (Get-Command Get-RMADBackup -ErrorAction SilentlyContinue)) {
        Write-Error "RMAD module(s) were loaded but Get-RMADBackup still isn't available. The DLL(s) found may not match this RMAD version's cmdlet set."
        return
    }

    Write-Host "=== MODULE DISCOVERY COMPLETE (method: $($RMADModuleInfo.LoadMethod)) ===`n" -ForegroundColor Cyan
}

Write-Host "Reading full backup catalog (including entries whose files are missing)..." -ForegroundColor Cyan

# -All = every registered backup, whether or not the file is physically present
$allBackups = Get-RMADBackup -All

Write-Host "Catalog contains $($allBackups.Count) registered backup(s). Verifying each on disk..." -ForegroundColor Cyan

$results = New-Object System.Collections.Generic.List[object]
$missing = New-Object System.Collections.Generic.List[object]

foreach ($backup in $allBackups) {

    $path   = $backup.Path
    $exists = $false

    if ([string]::IsNullOrWhiteSpace($path)) {
        # No local path (e.g. Secure Storage backup) - skip verification, leave registered
        $status = 'Skipped-NoLocalPath'
    }
    else {
        $exists = Test-Path -LiteralPath $path
        $status = if ($exists) { 'Present' } else { 'Missing' }
    }

    $record = [pscustomobject]@{
        Id           = $backup.Id
        Guid         = $backup.BackupGuid
        ComputerName = $backup.ComputerName
        Domain       = $backup.Domain
        Date         = $backup.Date
        Path         = $path
        Status       = $status
    }

    $results.Add($record) | Out-Null

    if ($status -eq 'Missing') {
        $missing.Add($backup) | Out-Null
        Write-Host "'$path' was not found (Backup Id: $($backup.Id), Computer: $($backup.ComputerName), Date: $($backup.Date))" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Summary: $($allBackups.Count) registered, $($missing.Count) orphaned (file missing on disk)." -ForegroundColor Cyan

if ($LogPath) {
    $results | Export-Csv -Path $LogPath -NoTypeInformation
    Write-Host "Full results written to $LogPath" -ForegroundColor Cyan
}

if ($missing.Count -eq 0) {
    Write-Host "Nothing to unregister. Catalog matches disk contents." -ForegroundColor Green
    return
}

if (-not $Remove) {
    Write-Host ""
    Write-Host "Dry run only - no entries were unregistered. Re-run with -Remove (add -Force to skip confirmation prompts) to unregister the $($missing.Count) orphaned entries above." -ForegroundColor Magenta
    return
}

Write-Host ""
Write-Host "Unregistering $($missing.Count) orphaned backup(s) from the catalog..." -ForegroundColor Cyan
if ($Force) {
    Write-Host "(-Force specified: confirmation prompts are suppressed)" -ForegroundColor DarkYellow
}

foreach ($backup in $missing) {
    # -Force skips our own ShouldProcess prompt. -WhatIf still works normally
    # (WhatIfPreference is honored by ShouldProcess regardless of -Force).
    $proceed = if ($Force) { $true } else { $PSCmdlet.ShouldProcess("Backup Id $($backup.Id) - $($backup.Path)", "Remove-RMADBackup (unregister)") }

    if ($proceed) {
        try {
            # -Confirm:$false suppresses Remove-RMADBackup's own internal
            # confirmation prompt, which is what was causing a popup per file.
            $backup | Remove-RMADBackup -Confirm:$false -ErrorAction Stop
            Write-Host "Unregistered Id $($backup.Id) ($($backup.Path))" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to unregister Id $($backup.Id) ($($backup.Path)): $_"
        }
    }
}

Write-Host "Done." -ForegroundColor Cyan
