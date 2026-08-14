<#
.SYNOPSIS
    Reconciles the Recovery Manager for Active Directory (RMAD) backup catalog
    against the files that actually exist on disk, and unregisters any
    catalog entries whose backup file is confirmed missing ("ghost" entries).

.DESCRIPTION
    RMAD registers every backup it creates (or that you manually import) in its
    backup registration database. If someone deletes a .bkf/.vhdx file directly
    from the filesystem instead of using the RMAD console, the catalog still
    thinks the backup exists. That inflates the size RMAD reports vs. what's
    actually consuming disk space.

    THIS VERSION ADDS A REACHABILITY GUARD.
    A prior version of this script relied on a single Test-Path against each
    backup's registered path. That produced a false-positive mass-orphan result
    in practice: local (C:\...) catalog paths only mean anything relative to
    whichever machine happens to run the script. When the script was run in a
    session/context where a local path didn't resolve to the real backup
    location (wrong host, different session, mapped drive not present, etc.),
    every local-path entry looked "missing" even though the files were untouched
    -- and a subsequent -Remove pass unregistered them anyway.

    To prevent that, this version checks the PARENT DIRECTORY of each backup
    path first:
      - If the parent directory itself does not resolve/exist/is unreachable,
        the entry is marked 'Unverifiable-LocationUnreachable' and is NEVER
        removed, regardless of -Remove or -Force. This is the case that bit us
        last time (wrong execution context) as well as genuine network/share
        outages, permission problems, etc. -- all ambiguous causes that should
        stop and get a human to look, not silently unregister.
      - Only if the parent directory clearly exists AND the specific file does
        not is an entry marked 'Missing' (a real, confident orphan) and
        eligible for removal.

    This is a heuristic, not a guarantee -- if the wrong machine happens to have
    an identically-named but empty parent folder, it would still misreport.
    Belt-and-suspenders: pass -ExpectedConsoleName to have the script hard-stop
    if it isn't running on the host you expect, and always run the -Remove pass
    directly on the actual RMAD console server in an interactive session, not
    through a relay/jump host.

.NOTES
    - Run this ON the RMAD console server, in an elevated PowerShell session.
    - Requires the RMAD Management Shell snap-in/module to be available.
    - ALWAYS do a dry run first (default) before passing -Remove.
    - Back up the backup registration database (backups.mdb / Rmad.db3,
      typically under %ProgramData%\Quest\Recovery Manager for Active
      Directory) before running live, just in case.
    - Secure Storage server backups aren't plain files on the local filesystem
      in the same way -- this script skips those by default (no local Path).
      Use Test-RMADSecureStorageBackup for that scenario instead.
    - If a prior run of the ORIGINAL script incorrectly unregistered entries
      whose files are still present on disk, those files were NOT deleted --
      Remove-RMADBackup only unregisters the catalog entry. Use
      BackupDBImport.exe (or the equivalent import cmdlet for your version) to
      re-register them rather than re-running the backups.

.PARAMETER Remove
    If specified, actually unregisters entries confirmed 'Missing'. Without
    this switch, the script only reports what it *would* remove (dry run).
    Entries marked 'Unverifiable-LocationUnreachable' are NEVER removed, even
    with this switch.

.PARAMETER Force
    Skips the per-entry confirmation prompt when removing 'Missing' entries.
    Has no effect on 'Unverifiable-LocationUnreachable' entries -- those are
    never removable through this script.

.PARAMETER LogPath
    Optional path to a CSV file where the full results (Present / Missing /
    Unverifiable) are logged, along with the host and account that ran the
    script, for audit purposes.

.PARAMETER ExpectedConsoleName
    Optional. If specified, the script hard-stops before doing anything if
    $env:COMPUTERNAME doesn't match this value. Use this to guarantee the
    script is only ever run directly on the real RMAD console server.

.EXAMPLE
    # Dry run - just see what's orphaned, nothing is changed
    .\Invoke-RMADCatalogCleanup.ps1

.EXAMPLE
    # Dry run, but hard-stop if this isn't actually running on the console
    .\Invoke-RMADCatalogCleanup.ps1 -ExpectedConsoleName SWADBNSPRD02

.EXAMPLE
    # Actually unregister confirmed orphans, logging everything to CSV
    .\Invoke-RMADCatalogCleanup.ps1 -Remove -LogPath C:\Temp\RMAD-Cleanup.csv

.EXAMPLE
    # Same as above, but skip confirmation prompts (useful for a lot of orphans)
    .\Invoke-RMADCatalogCleanup.ps1 -Remove -Force -LogPath C:\Temp\RMAD-Cleanup.csv
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Remove,
    [switch]$Force,
    [string]$LogPath,
    [string]$ExpectedConsoleName
)

# --- Optional hard-stop guard: only run on the host you expect ---
if ($ExpectedConsoleName -and ($env:COMPUTERNAME -ne $ExpectedConsoleName)) {
    Write-Error "This is running on '$($env:COMPUTERNAME)', but -ExpectedConsoleName specified '$ExpectedConsoleName'. Refusing to continue -- local backup paths would not resolve correctly from the wrong host. Re-run this directly on $ExpectedConsoleName."
    return
}

Write-Host "Running as $(whoami) on $($env:COMPUTERNAME)" -ForegroundColor DarkCyan

# --- Make sure the RMAD Management Shell cmdlets are loaded ---
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

    try {
        Add-PSSnapin Quest.RecoveryManager.AD.PowerShell -ErrorAction Stop
        $RMADModuleInfo.LoadMethod = 'PSSnapin'
        Write-Host "Loaded via PSSnapin: Quest.RecoveryManager.AD.PowerShell"
    }
    catch {
        Write-Host "PSSnapin not available, falling back to registry-based module discovery..." -ForegroundColor Yellow

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

        # NOTE: we load only the FIRST candidate that's present and successfully
        # imports, rather than all of them. Loading multiple modules that may
        # define the same cmdlet name can silently let a later import win over
        # an earlier one -- if those versions behave differently (e.g. how they
        # populate .Path), you can get inconsistent results between runs without
        # any error being raised. Given RMAD.PowerShell.dll (console/basic) and
        # RMAD.PowerShellFE.dll (Forest Edition) can both expose backup cmdlets,
        # picking one deliberately and logging which one avoids that ambiguity.
        $candidateDlls = @(
            (Join-Path $installPath "QuestSoftware.RecoveryManager.AD.PowerShell64.dll"),
            (Join-Path $installPath "QuestSoftware.RecoveryManager.AD.PowerShell.dll"),
            (Join-Path $installPath "QuestSoftware.RecoveryManager.AD.PowerShellFE.dll")
        )

        $loadedModule = $null
        foreach ($dll in $candidateDlls) {
            if (Test-Path -LiteralPath $dll) {
                try {
                    Import-Module $dll -ErrorAction Stop
                    Write-Host "Loaded module: $dll" -ForegroundColor Green
                    $loadedModule = $dll
                    break
                }
                catch {
                    Write-Warning "Failed to load module: $dll - $_"
                }
            }
        }

        $RMADModuleInfo.LoadedModules = @($loadedModule)
        $RMADModuleInfo.LoadMethod = 'RegistryDllImport'

        if (-not $loadedModule) {
            Write-Error "No RMAD PowerShell module DLL could be loaded from '$installPath'. Check that the Management Shell component is installed."
            return
        }
    }

    if (-not (Get-Command Get-RMADBackup -ErrorAction SilentlyContinue)) {
        Write-Error "RMAD module(s) were loaded but Get-RMADBackup still isn't available. The DLL(s) found may not match this RMAD version's cmdlet set."
        return
    }

    Write-Host "=== MODULE DISCOVERY COMPLETE (method: $($RMADModuleInfo.LoadMethod)) ===`n" -ForegroundColor Cyan
}

Write-Host "Reading full backup catalog (including entries whose files are missing)..." -ForegroundColor Cyan

$allBackups = Get-RMADBackup -All

Write-Host "Catalog contains $($allBackups.Count) registered backup(s). Verifying each on disk..." -ForegroundColor Cyan

$results       = New-Object System.Collections.Generic.List[object]
$missing       = New-Object System.Collections.Generic.List[object]
$unverifiable  = New-Object System.Collections.Generic.List[object]

foreach ($backup in $allBackups) {

    $path = $backup.Path

    if ([string]::IsNullOrWhiteSpace($path)) {
        # No local path (e.g. Secure Storage backup) - skip verification, leave registered
        $status = 'Skipped-NoLocalPath'
    }
    else {
        # Reachability guard: check the PARENT directory before trusting a
        # "file not found" result for the file itself. If the parent doesn't
        # resolve, we cannot tell "genuinely deleted" apart from "wrong host /
        # unreachable share / permissions problem" -- so we refuse to guess.
        $parent = Split-Path -Path $path -Parent
        $parentExists = $false

        if ($parent) {
            $parentExists = Test-Path -LiteralPath $parent -PathType Container -ErrorAction SilentlyContinue
        }

        if (-not $parentExists) {
            $status = 'Unverifiable-LocationUnreachable'
        }
        else {
            $fileExists = Test-Path -LiteralPath $path -ErrorAction SilentlyContinue
            $status = if ($fileExists) { 'Present' } else { 'Missing' }
        }
    }

    $record = [pscustomobject]@{
        Id           = $backup.Id
        Guid         = $backup.BackupGuid
        ComputerName = $backup.ComputerName
        Domain       = $backup.Domain
        Date         = $backup.Date
        Path         = $path
        Status       = $status
        RanOnHost    = $env:COMPUTERNAME
        RanAsUser    = (whoami)
    }

    $results.Add($record) | Out-Null

    switch ($status) {
        'Missing' {
            $missing.Add($backup) | Out-Null
            Write-Host "MISSING (confirmed orphan): '$path' (Backup Id: $($backup.Id), Computer: $($backup.ComputerName), Date: $($backup.Date))" -ForegroundColor Yellow
        }
        'Unverifiable-LocationUnreachable' {
            $unverifiable.Add($backup) | Out-Null
            Write-Host "UNVERIFIABLE (parent location unreachable, will NOT be removed): '$path' (Backup Id: $($backup.Id), Computer: $($backup.ComputerName), Date: $($backup.Date))" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Summary: $($allBackups.Count) registered | $($missing.Count) confirmed orphaned (safe to remove) | $($unverifiable.Count) unverifiable (location unreachable -- skipped, never auto-removed)." -ForegroundColor Cyan

if ($unverifiable.Count -gt 0) {
    Write-Host ""
    Write-Host "$($unverifiable.Count) entries could not be verified because their parent directory did not resolve from this session ($($env:COMPUTERNAME), $(whoami))." -ForegroundColor Red
    Write-Host "This is exactly the situation that caused false orphans previously. Do NOT assume these are missing." -ForegroundColor Red
    Write-Host "Check: are you running this on the correct host? Is the referenced share/drive currently reachable with the right permissions?" -ForegroundColor Red
}

if ($LogPath) {
    $results | Export-Csv -Path $LogPath -NoTypeInformation
    Write-Host "Full results (including RanOnHost/RanAsUser for audit) written to $LogPath" -ForegroundColor Cyan
}

if ($missing.Count -eq 0) {
    Write-Host ""
    Write-Host "Nothing confirmed as a safe-to-remove orphan. Catalog matches disk contents (or entries are unverifiable -- see above)." -ForegroundColor Green
    return
}

if (-not $Remove) {
    Write-Host ""
    Write-Host "Dry run only - no entries were unregistered. Re-run with -Remove (add -Force to skip confirmation prompts) to unregister the $($missing.Count) CONFIRMED orphaned entries above. Unverifiable entries are never removed by this script." -ForegroundColor Magenta
    return
}

Write-Host ""
Write-Host "Unregistering $($missing.Count) confirmed orphaned backup(s) from the catalog..." -ForegroundColor Cyan
if ($Force) {
    Write-Host "(-Force specified: confirmation prompts are suppressed)" -ForegroundColor DarkYellow
}

foreach ($backup in $missing) {
    $proceed = if ($Force) { $true } else { $PSCmdlet.ShouldProcess("Backup Id $($backup.Id) - $($backup.Path)", "Remove-RMADBackup (unregister)") }

    if ($proceed) {
        try {
            $backup | Remove-RMADBackup -Confirm:$false -ErrorAction Stop
            Write-Host "Unregistered Id $($backup.Id) ($($backup.Path))" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to unregister Id $($backup.Id) ($($backup.Path)): $_"
        }
    }
}

Write-Host "Done." -ForegroundColor Cyan
