<#
.SYNOPSIS
    For every script in NETLOGON, finds where it is referenced:
      - GPOs (scripts.ini / psscripts.ini / GPP XML in SYSVOL)
      - AD user accounts (scriptPath attribute)
      - Other scripts in NETLOGON (nested calls)
    Optionally also searches full GPO XML reports (slower, more thorough).

.EXAMPLE
    .\Find-NetlogonScriptUsage.ps1
    .\Find-NetlogonScriptUsage.ps1 -IncludeGpoReports -OutCsv C:\Temp\usage.csv
#>
[CmdletBinding()]
param(
    [string]$Domain,
    [string[]]$Extensions = @('.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.kix'),
    [string]$OutCsv = '.\NetlogonScriptUsage.csv',
    [switch]$IncludeGpoReports
)

Import-Module ActiveDirectory, GroupPolicy -ErrorAction Stop
if (-not $Domain) { $Domain = (Get-ADDomain).DNSRoot }

$netlogon = "\\$Domain\NETLOGON"
$policies = "\\$Domain\SYSVOL\$Domain\Policies"

# --- Gather everything once, up front ---------------------------------------

Write-Host 'Loading GPO list...'
$allGpos  = Get-GPO -All -Domain $Domain
$gpoNames = @{}
foreach ($g in $allGpos) { $gpoNames["{$($g.Id)}"] = $g.DisplayName }

Write-Host 'Reading policy files from SYSVOL...'
$policyFiles = Get-ChildItem $policies -Recurse -File -Include *.ini, *.xml -ErrorAction SilentlyContinue |
    ForEach-Object {
        $guid = [regex]::Match($_.FullName, '\{[0-9A-Fa-f-]{36}\}').Value
        [pscustomobject]@{
            Gpo  = if ($gpoNames[$guid]) { $gpoNames[$guid] } else { "Orphaned folder $guid" }
            Path = $_.FullName
            Text = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
        }
    }

$gpoReports = @()
if ($IncludeGpoReports) {
    Write-Host 'Generating GPO reports (this takes a while)...'
    $gpoReports = foreach ($g in $allGpos) {
        [pscustomobject]@{
            Gpo  = $g.DisplayName
            Text = Get-GPOReport -Guid $g.Id -ReportType Xml -Domain $Domain
        }
    }
}

Write-Host 'Loading users with a logon script set...'
$users = Get-ADUser -LDAPFilter '(scriptPath=*)' -Properties scriptPath -Server $Domain

Write-Host 'Reading NETLOGON scripts...'
$scripts = Get-ChildItem $netlogon -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $Extensions -contains $_.Extension } |
    ForEach-Object {
        [pscustomobject]@{
            RelPath   = $_.FullName.Substring($netlogon.Length).TrimStart('\')
            Name      = $_.Name
            LastWrite = $_.LastWriteTime
            Text      = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
        }
    }

# --- Check each script -------------------------------------------------------

$i = 0
$results = foreach ($s in $scripts) {
    $i++
    Write-Progress -Activity 'Checking scripts' -Status $s.RelPath -PercentComplete ($i / $scripts.Count * 100)

    # Match the file name as a whole token so "logon.bat" doesn't match "mylogon.bat" or "logon.bat.old"
    $pattern = '(?<![\w.-])' + [regex]::Escape($s.Name) + '(?![\w.-])'

    $gpoHits    = @($policyFiles | Where-Object { $_.Text -match $pattern })
    $reportHits = @($gpoReports  | Where-Object { $_.Text -match $pattern })
    $userHits   = @($users       | Where-Object { $_.scriptPath -match $pattern })
    $scriptHits = @($scripts     | Where-Object { $_.RelPath -ne $s.RelPath -and $_.Text -match $pattern })

    $gpos = @($gpoHits | ForEach-Object Gpo) + @($reportHits | ForEach-Object Gpo) | Sort-Object -Unique

    [pscustomobject]@{
        Script          = $s.RelPath
        LastWrite       = $s.LastWrite
        Unreferenced    = ($gpos.Count + $userHits.Count + $scriptHits.Count) -eq 0
        GPOs            = $gpos -join '; '
        UserCount       = $userHits.Count
        Users           = ($userHits | Select-Object -First 25 | ForEach-Object SamAccountName) -join '; '
        CalledByScripts = ($scriptHits | ForEach-Object RelPath) -join '; '
        GpoFiles        = ($gpoHits | ForEach-Object Path | Sort-Object -Unique) -join '; '
    }
}
Write-Progress -Activity 'Checking scripts' -Completed

$results | Sort-Object Unreferenced, Script | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
$results | Sort-Object Unreferenced, Script | Format-Table Script, Unreferenced, GPOs, UserCount, CalledByScripts -AutoSize -Wrap

$unused = @($results | Where-Object Unreferenced).Count
Write-Host "`n$($results.Count) scripts checked, $unused with no references found. Full results: $OutCsv"
