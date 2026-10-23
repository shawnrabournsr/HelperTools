<#
.SYNOPSIS
    For every script in NETLOGON, finds where it is referenced:
      - GPOs (scripts.ini / psscripts.ini / GPP XML in SYSVOL)
      - AD user accounts (scriptPath attribute)
      - Other scripts in NETLOGON (nested calls)
    Optionally also searches full GPO XML reports (slower, more thorough).

.PARAMETER Domain
    Target domain (DNS or NetBIOS name). Defaults to the current user's domain.
.PARAMETER Server
    Specific DC to query for AD, SYSVOL and NETLOGON. Defaults to the target domain's PDC emulator.
.PARAMETER UserCsv
    Detail file with one row per script/user pair (every user whose scriptPath references a script).
.PARAMETER Credential
    Credentials for the target domain (e.g. when running from a bastion/admin forest).
    Used for AD queries and the SYSVOL/NETLOGON shares. The GroupPolicy module does not accept
    credentials, so -IncludeGpoReports always runs as the current user.

.EXAMPLE
    .\Find-NetlogonScriptUsage.ps1
.EXAMPLE
    .\Find-NetlogonScriptUsage.ps1 -Domain prod.contoso.com
.EXAMPLE
    .\Find-NetlogonScriptUsage.ps1 -Domain prod.contoso.com -Server dc01.prod.contoso.com -Credential (Get-Credential PROD\admin)
#>
[CmdletBinding()]
param(
    [string]$Domain,
    [string]$Server,
    [pscredential]$Credential,
    [string[]]$Extensions = @('.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.kix'),
    [string]$OutCsv = '.\NetlogonScriptUsage.csv',
    [string]$UserCsv = '.\NetlogonScriptUsers.csv',
    [switch]$IncludeGpoReports
)

Import-Module ActiveDirectory -ErrorAction Stop

# --- Resolve target domain and DC -------------------------------------------

$adParams = @{}
if ($Credential) { $adParams.Credential = $Credential }
if ($Server)     { $adParams.Server = $Server }
elseif ($Domain) { $adParams.Server = $Domain }

$adDomain = Get-ADDomain @adParams -ErrorAction Stop
$Domain   = $adDomain.DNSRoot
if (-not $Server) { $Server = $adDomain.PDCEmulator }
$adParams.Server = $Server

Write-Host "Target domain: $Domain   DC: $Server" -ForegroundColor Cyan

$netlogonUnc = "\\$Server\NETLOGON"
$sysvolUnc   = "\\$Server\SYSVOL"
$drives      = @()

try {
    # Connect to the shares with alternate credentials if supplied
    if ($Credential) {
        $drives += New-PSDrive -Name NLScan -PSProvider FileSystem -Root $netlogonUnc -Credential $Credential -ErrorAction Stop
        $drives += New-PSDrive -Name SVScan -PSProvider FileSystem -Root $sysvolUnc   -Credential $Credential -ErrorAction Stop
        $netlogon = 'NLScan:\'
        $policies = "SVScan:\$Domain\Policies"
    }
    else {
        $netlogon = $netlogonUnc
        $policies = "$sysvolUnc\$Domain\Policies"
    }

    # --- Gather everything once, up front -----------------------------------

    Write-Host 'Loading GPO list...'
    # Read GPO names from AD rather than Get-GPO, so -Credential is honoured
    $gpoNames = @{}
    Get-ADObject @adParams -SearchBase "CN=Policies,CN=System,$($adDomain.DistinguishedName)" -SearchScope OneLevel `
        -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName |
        ForEach-Object { $gpoNames[$_.Name] = $_.DisplayName }

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
        Import-Module GroupPolicy -ErrorAction Stop
        if ($Credential) {
            Write-Warning 'The GroupPolicy module cannot use -Credential; GPO reports will be generated as the current user.'
        }
        Write-Host 'Generating GPO reports (this takes a while)...'
        $gpoReports = foreach ($guid in $gpoNames.Keys) {
            try {
                [pscustomobject]@{
                    Gpo  = $gpoNames[$guid]
                    Text = Get-GPOReport -Guid $guid.Trim('{}') -ReportType Xml -Domain $Domain -Server $Server -ErrorAction Stop
                }
            }
            catch { Write-Warning "Report failed for $($gpoNames[$guid]): $($_.Exception.Message)" }
        }
    }

    Write-Host 'Loading users with a logon script set...'
    $users = Get-ADUser @adParams -LDAPFilter '(scriptPath=*)' -Properties scriptPath

    Write-Host 'Reading NETLOGON scripts...'
    $scripts = Get-ChildItem $netlogon -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $Extensions -contains $_.Extension } |
        ForEach-Object {
            [pscustomobject]@{
                # Path relative to the NETLOGON root, whether accessed via UNC or PSDrive
                RelPath   = $_.FullName -replace '^.*?\\NETLOGON\\|^NLScan:\\', ''
                Name      = $_.Name
                LastWrite = $_.LastWriteTime
                Text      = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
            }
        }

    if (-not $scripts) { Write-Warning "No scripts found in $netlogonUnc"; return }

    # --- Check each script ---------------------------------------------------

    $userRows = [System.Collections.Generic.List[object]]::new()
    $i = 0
    $results = foreach ($s in $scripts) {
        $i++
        Write-Progress -Activity 'Checking scripts' -Status $s.RelPath -PercentComplete ($i / @($scripts).Count * 100)

        # Match the file name as a whole token so "logon.bat" doesn't match "mylogon.bat" or "logon.bat.old"
        $pattern = '(?<![\w.-])' + [regex]::Escape($s.Name) + '(?![\w.-])'

        $gpoHits    = @($policyFiles | Where-Object { $_.Text -match $pattern })
        $reportHits = @($gpoReports  | Where-Object { $_.Text -match $pattern })
        $userHits   = @($users       | Where-Object { $_.scriptPath -match $pattern })
        $scriptHits = @($scripts     | Where-Object { $_.RelPath -ne $s.RelPath -and $_.Text -match $pattern })

        foreach ($u in $userHits) {
            $userRows.Add([pscustomobject]@{
                Domain            = $Domain
                Script            = $s.RelPath
                SamAccountName    = $u.SamAccountName
                Name              = $u.Name
                Enabled           = $u.Enabled
                ScriptPath        = $u.scriptPath
                DistinguishedName = $u.DistinguishedName
            })
        }

        $gpos = @(@($gpoHits | ForEach-Object Gpo) + @($reportHits | ForEach-Object Gpo) | Sort-Object -Unique)

        [pscustomobject]@{
            Domain          = $Domain
            Script          = $s.RelPath
            LastWrite       = $s.LastWrite
            Unreferenced    = ($gpos.Count + $userHits.Count + $scriptHits.Count) -eq 0
            GPOs            = $gpos -join '; '
            UserCount       = $userHits.Count
            DisabledUsers   = @($userHits | Where-Object { -not $_.Enabled }).Count
            UsersPreview    = (($userHits | Select-Object -First 10 | ForEach-Object SamAccountName) -join '; ') +
                              $(if ($userHits.Count -gt 10) { "; (+$($userHits.Count - 10) more, see $UserCsv)" })
            CalledByScripts = ($scriptHits | ForEach-Object RelPath) -join '; '
            GpoFiles        = ($gpoHits | ForEach-Object Path | Sort-Object -Unique) -join '; '
        }
    }
    Write-Progress -Activity 'Checking scripts' -Completed

    $results | Sort-Object Unreferenced, Script | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
    $userRows | Sort-Object Script, SamAccountName | Export-Csv -Path $UserCsv -NoTypeInformation -Encoding UTF8
    $results | Sort-Object Unreferenced, Script | Format-Table Script, Unreferenced, GPOs, UserCount, CalledByScripts -AutoSize -Wrap

    $unused = @($results | Where-Object Unreferenced).Count
    Write-Host "`n$(@($results).Count) scripts checked in $Domain, $unused with no references found."
    Write-Host "Summary: $OutCsv"
    Write-Host "Users:   $UserCsv ($($userRows.Count) script/user pairs)"
}
finally {
    $drives | ForEach-Object { Remove-PSDrive -Name $_.Name -ErrorAction SilentlyContinue }
}
