#Requires -Version 5.1
<#
.SYNOPSIS
    GPO Assessment Collector - read-only, forest-wide data collection mapped to the
    Group Policy Assessment scope:
      1 Inventory & Structure   2 Permissions & Filtering   3 Content
      4 Design & Organization   5 Management Practices

.DESCRIPTION
    Companion to GPO Analyzer v3.2.1. Headless, makes NO changes and installs NOTHING.
    Requires the RSAT ActiveDirectory and GroupPolicy modules on the jump host and an
    account that can read AD, GPOs and SYSVOL in each domain. Admin rights are not required,
    but some ACLs and group memberships may be unreadable to a non-privileged account
    (failures are logged to Errors.csv rather than stopping the run).

    Output folder contains:
      Summary.html            Findings by section/severity (start here)
      Findings.csv            Every finding: Section, Severity, Domain, GPO, Finding, Detail, Recommendation
      GPOInventory.csv        One row per GPO (status, dates, owner, links, filtering, size, flags)
      Links.csv               Every site/domain/OU link (order, enabled, enforced, block inheritance, broken)
      SOMs.csv                Sites/domains/OUs with link counts, block inheritance and object counts
      Permissions.csv         Every GPO ACE as reported by GPMC, classified Tier0/Other
      Delegation.csv          Who can create GPOs and who can link/unlink on OUs (non-Tier0 only)
      WmiFilters.csv          All WMI filters, queries and usage
      Settings.csv            Every parsed setting (side, category, name, value, legacy flag)
      Catalog.csv             Configuration categories: GPO and setting counts per category
      Scripts.csv             Startup/shutdown/logon/logoff scripts
      Loopback.csv            GPOs configuring loopback processing and where they are linked
      PasswordPolicy.csv      Effective domain policy, FGPPs and every GPO carrying account settings
      Conflicts.csv           Settings defined in 2+ GPOs: conflict/redundant, overlapping scope or not
      NearDuplicates.csv      GPO pairs with highly similar content (incl. across domains)
      NamingPrefixes.csv      Name prefix distribution per domain
      BackupCoverage.csv      Only when -BackupPath is supplied
      GPOReports\<domain>\    Raw XML report per GPO (keep for offline re-analysis)
      Errors.csv              Anything that could not be read

.PARAMETER Domain
    One or more domain FQDNs. Defaults to every domain in the current forest.
.PARAMETER BackupPath
    Folder (or share) holding GPMC backups (Backup-GPO output). Used to measure backup coverage.
.PARAMETER AdditionalTier0
    Extra groups/accounts (DOMAIN\name or SID) to treat as Tier 0, e.g. a dedicated GPO admin group.
.PARAMETER StaleDays
    GPOs not modified for this many days are flagged as stale. Default 730.

.EXAMPLE
    .\GPO_Assessment_Collector.ps1
.EXAMPLE
    .\GPO_Assessment_Collector.ps1 -Domain corp.contoso.com -BackupPath \\fs01\GPOBackups -AdditionalTier0 'CORP\T0-GPO-Admins'

.NOTES
    Limitations (by design - confirm in interviews or with GPMC modeling):
    - Conflict "overlap" is based on link scope (same/ancestor SOM, or site). Security filtering,
      WMI filtering, item-level targeting and block inheritance can still prevent a real conflict.
    - Winning value / effective precedence is not computed; use GPMC Group Policy Modeling for that.
    - Whether broad "Authenticated Users" scoping is *intended* can only be confirmed with the owners.
#>
[CmdletBinding()]
param(
    [string[]]$Domain,
    [string]$OutputPath,
    [int]$StaleDays = 730,
    [string]$BackupPath,
    [string[]]$AdditionalTier0 = @(),
    [switch]$SkipSysvol,
    [switch]$SkipObjectCounts,
    [int]$SmallGpoThreshold = 2,
    [int]$LargeGpoThreshold = 250,
    [int]$ManyLinksPerSom = 10,
    [double]$SimilarityThreshold = 0.8
)

$ErrorActionPreference = 'Stop'
$startTime = Get-Date
if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location).Path ("GPOAssessment_{0:yyyyMMdd_HHmmss}" -f $startTime) }

foreach ($m in 'ActiveDirectory', 'GroupPolicy') {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        throw "Required module '$m' is not installed. Install RSAT ($m) on the jump host first - this script does not install anything."
    }
    Import-Module $m -ErrorAction Stop -Verbose:$false
}
$null = New-Item -ItemType Directory -Path $OutputPath -Force
$xmlRoot = Join-Path $OutputPath 'GPOReports'
$null = New-Item -ItemType Directory -Path $xmlRoot -Force

#region ---------- Output containers and helpers ----------
$out = [ordered]@{}
foreach ($n in 'GPOInventory','Links','SOMs','Permissions','Delegation','WmiFilters','Settings','Catalog','Scripts',
               'Loopback','PasswordPolicy','Conflicts','NearDuplicates','NamingPrefixes','BackupCoverage','Findings','Errors') {
    $out[$n] = New-Object System.Collections.Generic.List[object]
}

$SectionNames = @{
    '1' = '1. GPO Inventory & Structure'
    '2' = '2. GPO Permissions & Filtering'
    '3' = '3. GPO Content'
    '4' = '4. GPO Design & Organization'
    '5' = '5. GPO Management Practices'
}

function Log { param([string]$Msg) Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Msg) }

function Add-Finding {
    param([string]$Section, [string]$Severity, [string]$Domain, [string]$GPO, [string]$Finding, [string]$Detail = '', [string]$Recommendation = '')
    $out.Findings.Add([pscustomobject]@{
        Section = $SectionNames[$Section]; Severity = $Severity; Domain = $Domain; GPO = $GPO
        Finding = $Finding; Detail = $Detail; Recommendation = $Recommendation
    })
}

function Add-Err {
    param([string]$Domain, [string]$Context, [string]$Message)
    $out.Errors.Add([pscustomobject]@{ Time = (Get-Date).ToString('s'); Domain = $Domain; Context = $Context; Message = $Message })
    Write-Warning "$Domain - $Context : $Message"
}

# XML helpers. The comma operator stops PowerShell from unrolling XML nodes on return.
function Get-Child    { param($Node, [string]$Name) if ($null -eq $Node) { return $null }; return ,$Node.SelectSingleNode("./*[local-name()='$Name']") }
function Get-Children { param($Node, [string]$Name) if ($null -eq $Node) { return ,@() }; return ,$Node.SelectNodes("./*[local-name()='$Name']") }
function Get-Desc     { param($Node, [string]$Name) if ($null -eq $Node) { return ,@() }; return ,$Node.SelectNodes(".//*[local-name()='$Name']") }
function Get-Text {
    param($Node, [string]$Name)
    $c = Get-Child $Node $Name
    if ($null -ne $c) { return $c.InnerText.Trim() }
    return ''
}

# DN helpers (respect escaped commas such as CN=Smith\, John)
function Split-DN { param([string]$DN) return ,([regex]::Split($DN, '(?<!\\),')) }
function Get-AncestorDNs {
    param([string]$DN)
    $parts = Split-DN $DN
    $list = New-Object System.Collections.Generic.List[string]
    for ($k = 1; $k -lt $parts.Count; $k++) { $list.Add((($parts[$k..($parts.Count - 1)]) -join ',').ToLower()) }
    return ,$list
}
function Test-DNWithin {
    param([string]$Child, [string]$Ancestor)
    $c = $Child.ToLower(); $a = $Ancestor.ToLower()
    return (($c -eq $a) -or $c.EndsWith(',' + $a))
}
function Add-AncestorCount {
    param([string]$DN, [hashtable]$Table)
    foreach ($anc in (Get-AncestorDNs $DN)) {
        if ($Table.ContainsKey($anc)) { $Table[$anc]++ } else { $Table[$anc] = 1 }
    }
}

$script:sidNameCache = @{}
function Resolve-SidName {
    param([string]$Sid)
    if (-not $Sid) { return '' }
    if ($script:sidNameCache.ContainsKey($Sid)) { return $script:sidNameCache[$Sid] }
    $n = $Sid
    try { $n = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch {}
    $script:sidNameCache[$Sid] = $n
    return $n
}
function Resolve-NameSid {
    param([string]$Name)
    if (-not $Name) { return $null }
    if ($Name -match '^S-1-') { return $Name }
    try { return (New-Object System.Security.Principal.NTAccount($Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { return $null }
}

function New-HashSet { return ,([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)) }

# gPLink parser. GPMC link order 1 = highest precedence; it is the LAST entry in the gPLink string.
# Order from Get-GPInheritance is preferred where available; this is the fallback (sites).
function ConvertFrom-GPLink {
    param([string]$GPLink)
    $res = New-Object System.Collections.Generic.List[object]
    if (-not $GPLink -or $GPLink.Trim().Length -eq 0) { return ,$res }
    $mm = [regex]::Matches($GPLink, '(?i)\[LDAP://cn=\{([0-9a-f\-]{36})\},cn=policies,cn=system,([^;\]]+);(\d+)\]')
    $n = $mm.Count; $i = 0
    foreach ($x in $mm) {
        $flags = [int]$x.Groups[3].Value
        $dom = ((($x.Groups[2].Value -split ',') | ForEach-Object { $_ -replace '^DC=', '' }) -join '.').ToLower()
        $res.Add([pscustomobject]@{
            Guid = $x.Groups[1].Value.ToLower(); GpoDomain = $dom
            Enabled = (($flags -band 1) -eq 0); Enforced = (($flags -band 2) -ne 0); Order = ($n - $i)
        })
        $i++
    }
    return ,$res
}

# Schema GUIDs used for delegation checks
$GUID_gPLink      = [guid]'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
$GUID_gPOptions   = [guid]'f30e3bbf-9ff0-11d1-b603-0000f80367c1'
$GUID_GPC         = [guid]'f30e3bc2-9ff0-11d1-b603-0000f80367c1'
$GUID_OUClass     = [guid]'bf967aa5-0de6-11d0-a285-00aa003049e2'
$GUID_DomainClass = [guid]'19195a5b-6da0-11d0-afd3-00c04fd930c9'
$ADR = [System.DirectoryServices.ActiveDirectoryRights]

function Test-RuleAppliesToObject {
    param($Rule)
    if ("$($Rule.AccessControlType)" -ne 'Allow') { return $false }
    if (([int]$Rule.PropagationFlags -band [int][System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { return $false }
    $iot = $Rule.InheritedObjectType
    if ($iot -ne [guid]::Empty -and $iot -ne $GUID_OUClass -and $iot -ne $GUID_DomainClass) { return $false }
    return $true
}
function Get-LinkRight {
    param($Rule)
    if (-not (Test-RuleAppliesToObject $Rule)) { return $null }
    $r = [int]$Rule.ActiveDirectoryRights
    if (($r -band [int]($ADR::GenericAll)) -eq [int]($ADR::GenericAll)) { return 'Full Control' }
    if ($r -band [int]($ADR::WriteDacl))  { return 'Write DACL (can grant itself link rights)' }
    if ($r -band [int]($ADR::WriteOwner)) { return 'Write Owner (can grant itself link rights)' }
    if ($r -band [int]($ADR::WriteProperty)) {
        $ot = $Rule.ObjectType
        if ($ot -eq [guid]::Empty)     { return 'Write all properties' }
        if ($ot -eq $GUID_gPLink)      { return 'Write gPLink (link/unlink GPOs)' }
        if ($ot -eq $GUID_gPOptions)   { return 'Write gPOptions (block inheritance)' }
    }
    return $null
}
function Get-CreateGpoRight {
    param($Rule)
    if ("$($Rule.AccessControlType)" -ne 'Allow') { return $null }
    if (([int]$Rule.PropagationFlags -band [int][System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { return $null }
    $r = [int]$Rule.ActiveDirectoryRights
    if (($r -band [int]($ADR::GenericAll)) -eq [int]($ADR::GenericAll)) { return 'Full Control on Policies container' }
    if (($r -band [int]($ADR::CreateChild)) -and ($Rule.ObjectType -eq [guid]::Empty -or $Rule.ObjectType -eq $GUID_GPC)) { return 'Create groupPolicyContainer' }
    if ($r -band [int]($ADR::WriteDacl)) { return 'Write DACL on Policies container' }
    return $null
}

function Get-PrincipalClass {
    param($Ctx, [string]$Sid)
    if ($Ctx.Tier0.Contains($Sid)) { return 'Tier0 group' }
    if ($Ctx.Tier0Members.Contains($Sid)) { return 'Tier0 member (individual ACE)' }
    if ($Sid -in 'S-1-5-11', 'S-1-1-0', "$($Ctx.Sid)-513", "$($Ctx.Sid)-515") { return 'Broad group' }
    return 'Other'
}

$GppFriendly = @{
    Drive = 'Drive Maps'; Registry = 'Registry'; SharedPrinter = 'Printers'; PortPrinter = 'Printers'; LocalPrinter = 'Printers'
    Shortcut = 'Shortcuts'; File = 'Files'; Folder = 'Folders'; EnvironmentVariable = 'Environment'; Group = 'Local Users and Groups'
    User = 'Local Users and Groups'; NTService = 'Services'; Task = 'Scheduled Tasks'; TaskV2 = 'Scheduled Tasks'
    ImmediateTask = 'Scheduled Tasks'; ImmediateTaskV2 = 'Scheduled Tasks'; DataSource = 'Data Sources'; IniFile = 'Ini Files'
    Device = 'Devices'; NetworkShare = 'Network Shares'; GlobalPowerOptions = 'Power Options'; PowerScheme = 'Power Options'
    FolderOptions = 'Folder Options'; RegionalOptions = 'Regional Options'; StartMenu = 'Start Menu'; InternetSettings = 'Internet Settings'
    VPN = 'Network Options'; DUN = 'Network Options'; Application = 'Applications'
}

function New-Setting {
    param($Side, $ExtName, $Kind, $Category, $Name, $Value, $Key, [bool]$Comparable = $true, [string]$Targeted = '')
    return [pscustomobject]@{ Side = $Side; Extension = $ExtName; Kind = $Kind; Category = $Category; Name = $Name; Value = "$Value"
                              Key = $Key; Comparable = $Comparable; Targeted = $Targeted; Legacy = '' }
}

# Parse one <Extension> node from a GPO XML report into normalized settings.
function Get-ExtensionSettings {
    param([string]$Side, [string]$ExtName, $Ext)
    $r = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Ext) { return ,$r }

    # Administrative Templates (ADMX-backed)
    foreach ($p in (Get-Children $Ext 'Policy')) {
        $name = Get-Text $p 'Name'; if (-not $name) { continue }
        $cat = Get-Text $p 'Category'; $state = Get-Text $p 'State'
        $opts = @()
        foreach ($c in $p.ChildNodes) {
            if ($c.LocalName -in 'EditText', 'Numeric', 'CheckBox', 'DropDownList', 'ListBox', 'MultiText') {
                $vn = Get-Child $c 'Value'
                $ov = if ($null -ne $vn) { ($vn.InnerText -replace '\s+', ' ').Trim() } else { Get-Text $c 'State' }
                $opts += ('{0}={1}' -f (Get-Text $c 'Name'), $ov)
            }
        }
        $val = $state; if ($opts.Count -gt 0) { $val = "$state [" + ($opts -join '; ') + ']' }
        $r.Add((New-Setting $Side $ExtName 'AdminTemplate' "Administrative Templates/$cat" $name $val "AT|$Side|$cat/$name"))
    }
    # Extra registry settings (no ADMX available when the report was generated)
    foreach ($rs in (Get-Children $Ext 'RegistrySetting')) {
        $kp = Get-Text $rs 'KeyPath'; $v = Get-Child $rs 'Value'; $vn = Get-Text $v 'Name'; $vv = ''
        if ($null -ne $v) { $vv = (@($v.ChildNodes | Where-Object { $_.LocalName -ne 'Name' } | ForEach-Object { $_.InnerText }) -join ',') }
        $r.Add((New-Setting $Side $ExtName 'ExtraRegistry' 'Administrative Templates/Extra Registry Settings' "$kp\$vn" $vv "XREG|$Side|$kp\$vn"))
    }
    # Security settings
    foreach ($a in (Get-Children $Ext 'Account')) {
        $n = Get-Text $a 'Name'; $t = Get-Text $a 'Type'
        $val = Get-Text $a 'SettingNumber'; if ($val -eq '') { $val = Get-Text $a 'SettingBoolean' }
        $r.Add((New-Setting $Side $ExtName 'Account' "Account Policies/$t" $n $val "SEC|Account|$n"))
    }
    foreach ($so in (Get-Children $Ext 'SecurityOptions')) {
        $k = Get-Text $so 'KeyName'; if (-not $k) { $k = Get-Text $so 'SystemAccessPolicyName' }
        $disp = Get-Text (Get-Child $so 'Display') 'Name'; if (-not $disp) { $disp = $k }
        $val = Get-Text $so 'SettingNumber'
        if ($val -eq '') { $val = Get-Text $so 'SettingString' }
        if ($val -eq '') { $ss = Get-Child $so 'SettingStrings'; if ($null -ne $ss) { $val = (@($ss.ChildNodes | ForEach-Object { $_.InnerText }) -join ';') } }
        $r.Add((New-Setting $Side $ExtName 'SecurityOption' 'Security Options' $disp $val "SEC|Option|$k"))
    }
    foreach ($u in (Get-Children $Ext 'UserRightsAssignment')) {
        $n = Get-Text $u 'Name'
        $mem = @(foreach ($mb in (Get-Children $u 'Member')) { $mn = Get-Text $mb 'Name'; if (-not $mn) { $mn = Get-Text $mb 'SID' }; $mn }) | Sort-Object
        $r.Add((New-Setting $Side $ExtName 'UserRight' 'User Rights Assignment' $n (@($mem) -join '; ') "SEC|URA|$n"))
    }
    foreach ($au in (Get-Children $Ext 'Audit')) {
        $n = Get-Text $au 'Name'
        $r.Add((New-Setting $Side $ExtName 'Audit' 'Audit Policy (legacy categories)' $n ("Success={0}; Failure={1}" -f (Get-Text $au 'SuccessAttempts'), (Get-Text $au 'FailureAttempts')) "SEC|Audit|$n"))
    }
    foreach ($sv in (Get-Children $Ext 'SystemServices')) {
        $n = Get-Text $sv 'Name'
        $r.Add((New-Setting $Side $ExtName 'Service' 'System Services' $n (Get-Text $sv 'StartupMode') "SEC|Service|$n"))
    }
    foreach ($rg in (Get-Children $Ext 'RestrictedGroups')) {
        $g = Get-Text (Get-Child $rg 'GroupName') 'Name'
        $mem = @(foreach ($mb in (Get-Children $rg 'Member')) { Get-Text $mb 'Name' }) | Sort-Object
        $mof = @(foreach ($mb in (Get-Children $rg 'Memberof')) { Get-Text $mb 'Name' }) | Sort-Object
        $r.Add((New-Setting $Side $ExtName 'RestrictedGroup' 'Restricted Groups' $g ("Members={0} | MemberOf={1}" -f (@($mem) -join ';'), (@($mof) -join ';')) "SEC|RG|$g"))
    }
    foreach ($el in (Get-Children $Ext 'EventLog')) {
        $n = Get-Text $el 'Name'; $lg = Get-Text $el 'Log'
        $val = Get-Text $el 'SettingNumber'; if ($val -eq '') { $val = Get-Text $el 'SettingBoolean' }
        $r.Add((New-Setting $Side $ExtName 'EventLog' 'Event Log' "$lg/$n" $val "SEC|EventLog|$lg|$n"))
    }
    if ($ExtName -eq 'Security') {
        foreach ($f in (Get-Children $Ext 'File'))     { $r.Add((New-Setting $Side $ExtName 'FileSystemACL' 'File System ACLs' (Get-Text $f 'Path') '' "SEC|File|$(Get-Text $f 'Path')" $false)) }
        foreach ($f in (Get-Children $Ext 'Registry')) { $r.Add((New-Setting $Side $ExtName 'RegistryACL' 'Registry ACLs' (Get-Text $f 'Path') '' "SEC|RegACL|$(Get-Text $f 'Path')" $false)) }
    }
    # Advanced audit policy
    foreach ($as in (Get-Children $Ext 'AuditSetting')) {
        $n = Get-Text $as 'SubcategoryName'
        $sv = Get-Text $as 'SettingValue'
        $txt = switch ($sv) { '0' { 'No Auditing' } '1' { 'Success' } '2' { 'Failure' } '3' { 'Success and Failure' } default { $sv } }
        $r.Add((New-Setting $Side $ExtName 'AdvancedAudit' 'Advanced Audit Policy' $n $txt "AUDIT|$n"))
    }
    # Firewall rules
    foreach ($dir in 'InboundFirewallRules', 'OutboundFirewallRules') {
        foreach ($fw in (Get-Desc $Ext $dir)) {
            $n = Get-Text $fw 'Name'; if (-not $n) { continue }
            $r.Add((New-Setting $Side $ExtName 'FirewallRule' 'Windows Firewall Rules' "$dir/$n" (Get-Text $fw 'Action') "FW|$dir|$n"))
        }
    }
    # Scripts
    foreach ($sc in (Get-Children $Ext 'Script')) {
        $type = Get-Text $sc 'Type'
        $r.Add((New-Setting $Side $ExtName 'Script' "Scripts/$type" (Get-Text $sc 'Command') (Get-Text $sc 'Parameters') "SCRIPT|$Side|$type|$(Get-Text $sc 'Command')" $false))
    }
    # Software installation
    foreach ($msi in (Get-Desc $Ext 'MsiApplication')) {
        $r.Add((New-Setting $Side $ExtName 'SoftwareInstallation' 'Software Installation' (Get-Text $msi 'Name') (Get-Text $msi 'Path') "SWI|$Side|$(Get-Text $msi 'Name')" $false))
    }
    # Folder redirection
    if ($ExtName -match 'Redirection') {
        foreach ($fo in (Get-Desc $Ext 'Folder')) {
            $dest = ''; $dp = Get-Desc $fo 'DestinationPath'; if ($dp.Count -gt 0) { $dest = $dp[0].InnerText }
            $r.Add((New-Setting $Side $ExtName 'FolderRedirection' 'Folder Redirection' (Get-Text $fo 'Id') $dest "FR|$(Get-Text $fo 'Id')"))
        }
    }
    # Group Policy Preferences (any item that carries a <Properties> node)
    foreach ($p in (Get-Desc $Ext 'Properties')) {
        $item = $p.ParentNode; if ($null -eq $item) { continue }
        $type = $item.LocalName; $iname = $item.GetAttribute('name')
        $friendly = if ($GppFriendly.ContainsKey($type)) { $GppFriendly[$type] } else { $type }
        $filters = Get-Child $item 'Filters'
        $targeted = if ($null -ne $filters -and $filters.HasChildNodes) { 'Item-level targeting' } else { '' }
        $action = $p.GetAttribute('action')
        switch ($type) {
            'Registry' {
                $path = '{0}\{1}\{2}' -f $p.GetAttribute('hive'), $p.GetAttribute('key'), $p.GetAttribute('name')
                $s = New-Setting $Side $ExtName 'GPPRegistry' 'Preferences/Registry' $path ("{0} {1}={2}" -f $action, $p.GetAttribute('type'), $p.GetAttribute('value')) "GPPREG|$Side|$path" $true $targeted
            }
            'Drive' {
                $letter = $p.GetAttribute('letter')
                $s = New-Setting $Side $ExtName 'GPPDrive' 'Preferences/Drive Maps' "$($letter):" ("{0} {1}" -f $action, $p.GetAttribute('path')) "GPPDRIVE|$Side|$letter" $true $targeted
            }
            default {
                $tgt = $p.GetAttribute('path'); if (-not $tgt) { $tgt = $p.GetAttribute('targetPath') }
                $s = New-Setting $Side $ExtName 'GPP' "Preferences/$friendly" $iname ("{0} {1}" -f $action, $tgt).Trim() "GPP|$Side|$type|$iname" $false $targeted
            }
        }
        if ($p.GetAttribute('cpassword')) { $s.Legacy = 'GPP cpassword present (MS14-025) - password is recoverable by any domain user from SYSVOL' }
        $r.Add($s)
    }
    if ($r.Count -eq 0) {
        $r.Add((New-Setting $Side $ExtName 'Other' "Other/$ExtName" '(settings present - see XML report)' "$($Ext.ChildNodes.Count) elements" "OTHER|$Side|$ExtName" $false))
    }
    return ,$r
}

function Get-LegacyReason {
    param($S)
    switch ($S.Kind) {
        'AdminTemplate' {
            if ($S.Category -match '/Windows Components/Internet Explorer') { return 'Internet Explorer 11 is retired - keep only what Edge IE mode / zone mapping still needs' }
            if ($S.Category -match '/Windows Components/Microsoft Edge(/|$)') { return 'Legacy (EdgeHTML) Edge policy - superseded by Chromium Edge ADMX' }
            if ($S.Category -match '/Windows Components/(NetMeeting|Windows Messenger|Windows Media Center|Windows Mail|Desktop Gadgets|Windows Anytime Upgrade|Windows Meeting Space|Windows Sidebar|Windows Live)') { return 'Policy for a component removed from current Windows' }
            if ($S.Category -match '/Microsoft (Office|Word|Excel|Outlook|PowerPoint|Access|Visio|Project|Publisher|OneNote|InfoPath) (2003|2007|2010|2013)') { return 'Policy for an out-of-support Office version' }
        }
        'ExtraRegistry' { return 'Extra registry setting - no ADMX found (legacy .adm or removed template); verify still needed' }
        'SecurityOption' {
            if ($S.Key -match 'LmCompatibilityLevel$' -and $S.Value -match '^\d+$' -and [int]$S.Value -lt 5) { return "LAN Manager authentication level $($S.Value) permits LM/NTLMv1 (current baseline: 5)" }
            if ($S.Key -match 'NoLMHash$' -and $S.Value -eq '0') { return 'LM hash storage allowed' }
        }
        'Account' {
            if ($S.Name -eq 'ClearTextPassword' -and $S.Value -match '^(1|true)$') { return 'Store passwords using reversible encryption is enabled' }
        }
        'SoftwareInstallation' { return 'GPO Software Installation is a legacy deployment method - plan a replacement' }
    }
    if ($S.Extension -match 'Internet Explorer Maintenance') { return 'Internet Explorer Maintenance (IEM) is not processed by current Windows/IE' }
    return ''
}
#endregion

#region ---------- Phase 0: forest context ----------
Log "Reading forest information"
$forest   = Get-ADForest
$rootName = $forest.RootDomain
$rootDom  = Get-ADDomain -Identity $rootName -Server $rootName
$rootSid  = $rootDom.DomainSID.Value
$configNC = (Get-ADRootDSE -Server $rootName).configurationNamingContext
if (-not $Domain -or $Domain.Count -eq 0) { $Domain = @($forest.Domains) }
$DomainKeys = @($Domain | ForEach-Object { $_.ToLower() })
$extraT0 = @($AdditionalTier0 | ForEach-Object { Resolve-NameSid $_ } | Where-Object { $_ })
if ($AdditionalTier0.Count -gt $extraT0.Count) { Add-Err '(forest)' 'AdditionalTier0' 'One or more -AdditionalTier0 names could not be resolved to a SID' }

$Dom         = @{}     # domain context
$GpoIndex    = @{}     # "domain|guid" -> state
$LinksByGpo  = @{}     # "domain|guid" -> list of link records
$UserCount   = @{}     # SOM DN (lower) -> users beneath it
$CompCount   = @{}     # SOM DN (lower) -> computers beneath it
$Backups     = @{}     # "domain|guid" -> latest backup time

function Add-Link {
    param($Rec)
    $out.Links.Add($Rec)
    $k = "$($Rec.GPODomain)|$($Rec.GPOGuid)"
    if (-not $LinksByGpo.ContainsKey($k)) { $LinksByGpo[$k] = New-Object System.Collections.Generic.List[object] }
    $LinksByGpo[$k].Add($Rec)
}
#endregion

#region ---------- Phase 1: structure, links, delegation per domain; sites ----------
Log "Collecting site links from $configNC"
try {
    $sites = @(Get-ADObject -SearchBase "CN=Sites,$configNC" -SearchScope OneLevel -LDAPFilter '(objectClass=site)' -Properties gPLink, gPOptions -Server $rootName)
    foreach ($s in $sites) {
        $pl = ConvertFrom-GPLink $s.gPLink
        $out.SOMs.Add([pscustomobject]@{ Domain = '(forest)'; Type = 'Site'; Name = $s.Name; DistinguishedName = $s.DistinguishedName
                                         BlocksInheritance = $false; LinkCount = $pl.Count; Users = ''; Computers = '' })
        foreach ($l in $pl) {
            Add-Link ([pscustomobject]@{ SOMDomain = '(forest)'; TargetType = 'Site'; TargetName = $s.Name; Target = $s.DistinguishedName
                GPODomain = $l.GpoDomain; GPOGuid = $l.Guid; GPOName = ''; LinkOrder = $l.Order; LinkEnabled = $l.Enabled; Enforced = $l.Enforced
                TargetBlocksInheritance = $false; CrossDomain = $false; Status = '' })
        }
    }
} catch { Add-Err '(forest)' 'Site links' $_.Exception.Message }

foreach ($d in $DomainKeys) {
    Log "=== Domain $d : structure ==="
    try {
        $ad = Get-ADDomain -Identity $d -Server $d
    } catch { Add-Err $d 'Get-ADDomain' $_.Exception.Message; continue }

    $ctx = @{
        Name = $ad.DNSRoot; DN = $ad.DistinguishedName; DC = $ad.PDCEmulator; Sid = $ad.DomainSID.Value
        Tier0 = (New-HashSet); Tier0Members = (New-HashSet); Gpc = @{}; Wmi = @{}; SysvolGuids = (New-HashSet)
        PoliciesPath = "\\$($ad.DNSRoot)\SYSVOL\$($ad.DNSRoot)\Policies"; CentralStoreAdmx = -1; GpoCount = 0
    }
    $Dom[$d] = $ctx
    $dc = $ctx.DC; $dn = $ctx.DN; $dsid = $ctx.Sid

    foreach ($s in @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9', 'S-1-3-0', "$dsid-512", "$dsid-516", "$rootSid-519", "$rootSid-518", "$rootSid-498") + $extraT0) { [void]$ctx.Tier0.Add($s) }
    $t0Groups = @(@{ Id = "$dsid-512"; Server = $dc }, @{ Id = 'S-1-5-32-544'; Server = $dc }, @{ Id = "$rootSid-519"; Server = $rootName })
    foreach ($x in $extraT0) { $t0Groups += @{ Id = $x; Server = $dc } }
    foreach ($g in $t0Groups) {
        try { foreach ($mbr in (Get-ADGroupMember -Identity $g.Id -Recursive -Server $g.Server)) { [void]$ctx.Tier0Members.Add($mbr.SID.Value) } }
        catch { Add-Err $d "Tier0 membership $($g.Id)" $_.Exception.Message }
    }

    # GPO containers (for WMI references and AD/SYSVOL consistency)
    try {
        foreach ($g in (Get-ADObject -SearchBase "CN=Policies,CN=System,$dn" -SearchScope OneLevel -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName, gPCWQLFilter, versionNumber, whenCreated, whenChanged -Server $dc)) {
            $ctx.Gpc[$g.Name.Trim('{}').ToLower()] = $g
        }
    } catch { Add-Err $d 'GPO containers' $_.Exception.Message }

    # WMI filters
    try {
        foreach ($w in (Get-ADObject -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,$dn" -LDAPFilter '(objectClass=msWMI-Som)' -Properties 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2', 'msWMI-Author', 'msWMI-ID', whenCreated, whenChanged -Server $dc)) {
            $id = "$($w.'msWMI-ID')".Trim('{}').ToLower()
            $ctx.Wmi[$id] = @{ Name = $w.'msWMI-Name'; Description = $w.'msWMI-Parm1'; Query = $w.'msWMI-Parm2'; Author = $w.'msWMI-Author'
                               Created = $w.whenCreated; Changed = $w.whenChanged; UsedBy = (New-Object System.Collections.Generic.List[string]) }
        }
    } catch { Add-Err $d 'WMI filters' $_.Exception.Message }

    # SYSVOL folders and central store
    if (-not $SkipSysvol) {
        try {
            foreach ($f in (Get-ChildItem -LiteralPath $ctx.PoliciesPath -Directory -Force)) {
                if ($f.Name -match '^\{([0-9a-fA-F\-]{36})\}$') { [void]$ctx.SysvolGuids.Add($Matches[1].ToLower()) }
                elseif ($f.Name -eq 'PolicyDefinitions') { $ctx.CentralStoreAdmx = @(Get-ChildItem -LiteralPath $f.FullName -Filter '*.admx' -File).Count }
            }
        } catch { Add-Err $d 'SYSVOL enumeration' $_.Exception.Message }
    }

    # Object counts per SOM (used to check that user/computer settings land where users/computers exist)
    if (-not $SkipObjectCounts) {
        Log "  Counting users and computers per OU"
        try {
            foreach ($o in (Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user))' -SearchBase $dn -Server $dc -ResultPageSize 2000)) { Add-AncestorCount $o.DistinguishedName $UserCount }
            foreach ($o in (Get-ADObject -LDAPFilter '(objectCategory=computer)' -SearchBase $dn -Server $dc -ResultPageSize 2000)) { Add-AncestorCount $o.DistinguishedName $CompCount }
        } catch { Add-Err $d 'Object counts' $_.Exception.Message }
    }

    # Domain + OUs: links, block inheritance, link delegation
    Log "  Reading OUs, links and OU permissions"
    $linkDelegates = @{}
    try {
        $soms = @(Get-ADObject -LDAPFilter '(|(objectClass=organizationalUnit)(objectClass=domainDNS))' -SearchBase $dn -Properties gPLink, gPOptions, nTSecurityDescriptor -Server $dc)
    } catch { Add-Err $d 'OU enumeration' $_.Exception.Message; $soms = @() }

    foreach ($som in $soms) {
        $somDN = $som.DistinguishedName; $somKey = $somDN.ToLower()
        $type = if ($som.ObjectClass -eq 'domainDNS') { 'Domain' } else { 'OU' }
        $blocked = ("$($som.gPOptions)" -eq '1')
        $pl = ConvertFrom-GPLink $som.gPLink
        $uc = if ($UserCount.ContainsKey($somKey)) { $UserCount[$somKey] } else { 0 }
        $cc = if ($CompCount.ContainsKey($somKey)) { $CompCount[$somKey] } else { 0 }
        $out.SOMs.Add([pscustomobject]@{ Domain = $d; Type = $type; Name = $som.Name; DistinguishedName = $somDN; BlocksInheritance = $blocked
                                         LinkCount = $pl.Count; Users = $(if ($SkipObjectCounts) { '' } else { $uc }); Computers = $(if ($SkipObjectCounts) { '' } else { $cc }) })
        if ($blocked) {
            Add-Finding '1' 'Low' $d '' "Block inheritance on $type" $somDN 'Document why; in the target design prefer OU placement and security filtering over block inheritance.'
        }
        if ($pl.Count -gt $ManyLinksPerSom) {
            Add-Finding '4' 'Low' $d '' "$($pl.Count) GPOs linked to one $type" $somDN 'Candidate for consolidation into fewer, purpose-based GPOs.'
        }

        $gplOrder = @{}
        if ($pl.Count -gt 0) {
            try {
                $inh = Get-GPInheritance -Target $somDN -Domain $ctx.Name -Server $dc
                foreach ($gl in $inh.GpoLinks) { $gplOrder[$gl.GpoId.ToString().ToLower()] = $gl.Order }
            } catch { Add-Err $d "Get-GPInheritance $somDN" $_.Exception.Message }
        }
        foreach ($l in $pl) {
            $order = if ($gplOrder.ContainsKey($l.Guid)) { $gplOrder[$l.Guid] } else { $l.Order }
            Add-Link ([pscustomobject]@{ SOMDomain = $d; TargetType = $type; TargetName = $som.Name; Target = $somDN
                GPODomain = $l.GpoDomain; GPOGuid = $l.Guid; GPOName = ''; LinkOrder = $order; LinkEnabled = $l.Enabled; Enforced = $l.Enforced
                TargetBlocksInheritance = $blocked; CrossDomain = ($l.GpoDomain -ne $d); Status = '' })
        }

        $sd = $som.nTSecurityDescriptor
        if ($null -ne $sd) {
            foreach ($rule in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                $right = Get-LinkRight $rule; if (-not $right) { continue }
                $sid = $rule.IdentityReference.Value
                if ($ctx.Tier0.Contains($sid)) { continue }
                if (-not $linkDelegates.ContainsKey($sid)) { $linkDelegates[$sid] = @{ Rights = (New-HashSet); DNs = (New-HashSet) } }
                [void]$linkDelegates[$sid].Rights.Add($right); [void]$linkDelegates[$sid].DNs.Add($somKey)
            }
        }
    }
    foreach ($sid in $linkDelegates.Keys) {
        $dns = $linkDelegates[$sid].DNs
        $top = @($dns | Where-Object { $anc = Get-AncestorDNs $_; -not (@($anc | Where-Object { $dns.Contains($_) }).Count) })
        $name = Resolve-SidName $sid
        $out.Delegation.Add([pscustomobject]@{ Domain = $d; Scope = 'Link GPOs / set inheritance on OUs'; Principal = $name; SID = $sid
            Class = (Get-PrincipalClass $ctx $sid); Rights = (@($linkDelegates[$sid].Rights) -join '; '); ObjectCount = $dns.Count
            TopmostObjects = (@($top | Select-Object -First 5) -join ' || ') })
        $sev = if (@($top | Where-Object { $_ -eq $dn.ToLower() -or $_ -like 'ou=domain controllers,*' }).Count) { 'High' } else { 'Medium' }
        Add-Finding '2' $sev $d '' "Non-Tier0 principal can link/unlink GPOs on $($dns.Count) OU(s)" "$name : $(@($linkDelegates[$sid].Rights) -join '; ') | top: $(@($top | Select-Object -First 3) -join ' || ')" 'Confirm the delegation is intended; restrict link rights at Tier 0 OUs and domain root.'
    }

    # GPO creation rights
    try {
        $pol = Get-ADObject -Identity "CN=Policies,CN=System,$dn" -Properties nTSecurityDescriptor -Server $dc
        $creators = @{}
        foreach ($rule in $pol.nTSecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $right = Get-CreateGpoRight $rule; if (-not $right) { continue }
            $sid = $rule.IdentityReference.Value
            if ($ctx.Tier0.Contains($sid) -or $sid -eq "$dsid-520") { continue }
            $creators[$sid] = $right
        }
        foreach ($sid in $creators.Keys) {
            $name = Resolve-SidName $sid
            $out.Delegation.Add([pscustomobject]@{ Domain = $d; Scope = 'Create GPOs (Policies container ACL)'; Principal = $name; SID = $sid
                Class = (Get-PrincipalClass $ctx $sid); Rights = $creators[$sid]; ObjectCount = 1; TopmostObjects = "CN=Policies,CN=System,$dn" })
            Add-Finding '2' 'High' $d '' 'Non-Tier0 principal can create GPOs' "$name : $($creators[$sid])" 'Remove unless explicitly part of the delegation model.'
        }
    } catch { Add-Err $d 'Policies container ACL' $_.Exception.Message }
    try {
        $gpco = @(Get-ADGroupMember -Identity "$dsid-520" -Recursive -Server $dc)
        foreach ($mbr in $gpco) {
            $out.Delegation.Add([pscustomobject]@{ Domain = $d; Scope = 'Create GPOs (Group Policy Creator Owners member)'; Principal = $mbr.SamAccountName; SID = $mbr.SID.Value
                Class = (Get-PrincipalClass $ctx $mbr.SID.Value); Rights = 'Create GPOs; full control of GPOs they create'; ObjectCount = 1; TopmostObjects = '' })
        }
        if ($gpco.Count -gt 0) {
            Add-Finding '2' 'Medium' $d '' "Group Policy Creator Owners has $($gpco.Count) member(s)" (@($gpco | Select-Object -ExpandProperty SamAccountName) -join ', ') 'Review membership; members can create GPOs and edit those they create.'
        }
    } catch { Add-Err $d 'Group Policy Creator Owners' $_.Exception.Message }

    # Password policy: effective default + FGPPs
    try {
        $pp = Get-ADDefaultDomainPasswordPolicy -Identity $ctx.Name -Server $dc
        foreach ($prop in 'MinPasswordLength', 'ComplexityEnabled', 'PasswordHistoryCount', 'MaxPasswordAge', 'MinPasswordAge', 'LockoutThreshold', 'LockoutDuration', 'LockoutObservationWindow', 'ReversibleEncryptionEnabled') {
            $out.PasswordPolicy.Add([pscustomobject]@{ Domain = $d; Source = 'Default domain password policy (effective)'; SourceType = 'Domain'; AppliesTo = 'All domain accounts without a PSO'; Setting = $prop; Value = "$($pp.$prop)" })
        }
        if ($pp.MinPasswordLength -lt 14) { Add-Finding '3' 'Medium' $d '' "Domain minimum password length is $($pp.MinPasswordLength)" '' 'Current Microsoft/CIS baselines use 14+; plan the target value for the consolidated domain.' }
        if (-not $pp.ComplexityEnabled) { Add-Finding '3' 'Medium' $d '' 'Domain password complexity is disabled' '' 'Acceptable only with long passphrase policy and banned-password protection.' }
        if ($pp.LockoutThreshold -eq 0) { Add-Finding '3' 'High' $d '' 'No account lockout threshold in the domain policy' '' 'Define a lockout threshold (baselines: 5-10) for the target domain.' }
        if ($pp.ReversibleEncryptionEnabled) { Add-Finding '3' 'High' $d '' 'Reversible password encryption enabled domain-wide' '' 'Disable; reset affected passwords.' }
        if ($pp.MaxPasswordAge.TotalDays -gt 0) { Add-Finding '3' 'Info' $d '' "Periodic password expiry configured ($([int]$pp.MaxPasswordAge.TotalDays) days)" '' 'Current Microsoft and NIST guidance no longer recommends forced periodic expiry; decide target policy.' }
    } catch { Add-Err $d 'Default password policy' $_.Exception.Message }
    try {
        foreach ($f in (Get-ADFineGrainedPasswordPolicy -Filter * -Server $dc)) {
            foreach ($prop in 'Precedence', 'MinPasswordLength', 'ComplexityEnabled', 'PasswordHistoryCount', 'MaxPasswordAge', 'LockoutThreshold', 'LockoutDuration', 'ReversibleEncryptionEnabled') {
                $out.PasswordPolicy.Add([pscustomobject]@{ Domain = $d; Source = "FGPP: $($f.Name)"; SourceType = 'Fine-grained (PSO)'; AppliesTo = (@($f.AppliesTo) -join '; '); Setting = $prop; Value = "$($f.$prop)" })
            }
            if (@($f.AppliesTo).Count -eq 0) { Add-Finding '3' 'Low' $d '' "Fine-grained password policy '$($f.Name)' applies to nobody" '' 'Remove or assign.' }
        }
    } catch { Add-Err $d 'Fine-grained password policies' $_.Exception.Message }
}
#endregion

#region ---------- Phase 2: GPOs (content, permissions) ----------
foreach ($d in $DomainKeys) {
    $ctx = $Dom[$d]; if (-not $ctx) { continue }
    $xmlDir = Join-Path $xmlRoot $d
    $null = New-Item -ItemType Directory -Path $xmlDir -Force
    Log "=== Domain $d : GPOs ==="
    try { $gpos = @(Get-GPO -All -Domain $ctx.Name -Server $ctx.DC) } catch { Add-Err $d 'Get-GPO -All' $_.Exception.Message; continue }
    $ctx.GpoCount = $gpos.Count
    $i = 0
    foreach ($gpo in $gpos) {
        $i++
        Write-Progress -Activity "Analyzing GPOs in $d" -Status "$i / $($gpos.Count): $($gpo.DisplayName)" -PercentComplete ([int](100 * $i / [math]::Max(1, $gpos.Count)))
        $guid = $gpo.Id.ToString().ToLower(); $key = "$d|$guid"
        $st = @{
            Key = $key; Domain = $d; Guid = $guid; Gpo = $gpo; Name = $gpo.DisplayName
            Settings = (New-Object System.Collections.Generic.List[object])
            SideEnabled = @{ Computer = [bool]$gpo.Computer.Enabled; User = [bool]$gpo.User.Enabled }
            SideCount = @{ Computer = 0; User = 0 }; SideVer = @{}; Exts = @{ Computer = @(); User = @() }; ReportOK = $false
        }
        $GpoIndex[$key] = $st

        $xml = $null
        try {
            $raw = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $ctx.Name -Server $ctx.DC
            $raw | Out-File -LiteralPath (Join-Path $xmlDir "$guid.xml") -Encoding Unicode
            $xml = [xml]$raw; $st.ReportOK = $true
        } catch { Add-Err $d "Get-GPOReport $($gpo.DisplayName)" $_.Exception.Message }

        foreach ($side in 'Computer', 'User') {
            $node = $null
            if ($null -ne $xml) { $node = $xml.DocumentElement.SelectSingleNode("./*[local-name()='$side']") }
            $st.SideVer[$side] = @{ AD = (Get-Text $node 'VersionDirectory'); Sysvol = (Get-Text $node 'VersionSysvol') }
            $extNames = @()
            foreach ($ed in (Get-Children $node 'ExtensionData')) {
                $en = Get-Text $ed 'Name'; $extNames += $en
                foreach ($s in (Get-ExtensionSettings -Side $side -ExtName $en -Ext (Get-Child $ed 'Extension'))) {
                    if (-not $s.Legacy) { $s.Legacy = Get-LegacyReason $s }
                    $st.Settings.Add($s); $st.SideCount[$side]++
                    $out.Settings.Add([pscustomobject]@{ Domain = $d; GPO = $gpo.DisplayName; GUID = $guid; Side = $side; SideEnabled = $st.SideEnabled[$side]
                        Category = $s.Category; Kind = $s.Kind; Name = $s.Name; Value = $(if ($s.Value.Length -gt 1000) { $s.Value.Substring(0, 1000) + '...' } else { $s.Value })
                        Targeting = $s.Targeted; Legacy = $s.Legacy })
                    if ($s.Kind -eq 'Script') {
                        $out.Scripts.Add([pscustomobject]@{ Domain = $d; GPO = $gpo.DisplayName; Side = $side; Type = ($s.Category -replace '^Scripts/', ''); Command = $s.Name; Parameters = $s.Value })
                    }
                }
            }
            $st.Exts[$side] = $extNames
        }

        # Permissions and security filtering (as GPMC reports them)
        $apply = @(); $broad = @(); $denyApply = @(); $editorsOther = @(); $editorsIndiv = @(); $unresolved = @()
        $computerRead = $false; $agpm = $false
        try { $perms = @(Get-GPPermission -Guid $gpo.Id -All -DomainName $ctx.Name -Server $ctx.DC) } catch { Add-Err $d "Get-GPPermission $($gpo.DisplayName)" $_.Exception.Message; $perms = @() }
        foreach ($p in $perms) {
            $sid = "$($p.Trustee.Sid)"
            $tn = if ($p.Trustee.Name) { if ($p.Trustee.Domain) { "$($p.Trustee.Domain)\$($p.Trustee.Name)" } else { "$($p.Trustee.Name)" } } else { $sid }
            $perm = "$($p.Permission)"; $denied = [bool]$p.Denied
            $class = Get-PrincipalClass $ctx $sid
            $out.Permissions.Add([pscustomobject]@{ Domain = $d; GPO = $gpo.DisplayName; GUID = $guid; Trustee = $tn; SID = $sid; TrusteeType = "$($p.TrusteeType)"
                                                    Permission = $perm; Denied = $denied; Inherited = [bool]$p.Inherited; PrincipalClass = $class })
            if ($denied) { if ($perm -eq 'GpoApply') { $denyApply += $tn }; continue }
            if (-not $p.Trustee.Name -and "$($p.TrusteeType)" -match 'Unknown') { $unresolved += "$sid ($perm)" }
            if ($perm -in 'GpoRead', 'GpoApply', 'GpoEdit', 'GpoEditDeleteModifySecurity' -and $sid -in 'S-1-5-11', 'S-1-1-0', "$($ctx.Sid)-515") { $computerRead = $true }
            if ($perm -eq 'GpoApply') { $apply += $tn; if ($class -eq 'Broad group') { $broad += $tn } }
            if ($perm -in 'GpoEdit', 'GpoEditDeleteModifySecurity', 'GpoCustom') {
                if ($tn -match 'agpm') { $agpm = $true }
                if ($class -eq 'Tier0 member (individual ACE)') { $editorsIndiv += "$tn ($perm)" }
                elseif ($class -ne 'Tier0 group') { $editorsOther += "$tn ($perm)" }
            }
        }
        $st.Apply = $apply; $st.Broad = $broad; $st.DenyApply = $denyApply; $st.EditorsOther = $editorsOther; $st.EditorsIndiv = $editorsIndiv
        $st.ComputerRead = $computerRead; $st.AGPM = $agpm; $st.Unresolved = $unresolved; $st.PermsRead = ($perms.Count -gt 0)
        $ownerSid = Resolve-NameSid $gpo.Owner
        $st.OwnerClass = if ($ownerSid) { Get-PrincipalClass $ctx $ownerSid } else { 'Unresolved' }

        $st.HasAdm = $false
        if (-not $SkipSysvol) { try { $st.HasAdm = Test-Path -Path (Join-Path $ctx.PoliciesPath "{$guid}\Adm\*.adm") } catch {} }

        # Loopback
        $lb = @($st.Settings | Where-Object { $_.Kind -eq 'AdminTemplate' -and $_.Name -match 'loopback processing mode' -and $_.Value -match '^Enabled' })
        $st.Loopback = ''
        if ($lb.Count -gt 0) { $st.Loopback = if ($lb[0].Value -match 'Replace') { 'Replace' } elseif ($lb[0].Value -match 'Merge') { 'Merge' } else { 'Enabled' } }
    }
    Write-Progress -Activity "Analyzing GPOs in $d" -Completed
}
#endregion

#region ---------- Phase 3: analysis and findings ----------
Log "Analyzing links, scope and content"

# Resolve link GPO names, broken links
foreach ($l in $out.Links) {
    $k = "$($l.GPODomain)|$($l.GPOGuid)"
    if ($GpoIndex.ContainsKey($k)) { $l.GPOName = $GpoIndex[$k].Name; $l.Status = 'OK' }
    elseif ($Dom.ContainsKey($l.GPODomain)) {
        $l.Status = 'BROKEN - GPO does not exist'
        Add-Finding '1' 'Medium' $l.SOMDomain '' "Broken link to non-existent GPO {$($l.GPOGuid)}" "$($l.TargetType): $($l.Target)" 'Remove the stale link.'
    } else { $l.Status = 'GPO domain not assessed' }
    if ($l.CrossDomain -and $l.Status -eq 'OK') {
        Add-Finding '1' 'Medium' $l.SOMDomain $l.GPOName 'Cross-domain GPO link' "GPO from $($l.GPODomain) linked to $($l.Target)" 'Cross-domain links slow processing and must be re-designed during consolidation.'
    }
}

$now = Get-Date
$ddpGuid = '31b2f340-016d-11d2-945f-00c04fb984f9'; $ddcpGuid = '6ac1786c-016f-11d2-945f-00c04fb984f9'
$prefixCount = @{}
$sizeStats = @{}

foreach ($st in $GpoIndex.Values) {
    $d = $st.Domain; $ctx = $Dom[$d]; $gpo = $st.Gpo; $name = $st.Name
    $links = if ($LinksByGpo.ContainsKey($st.Key)) { @($LinksByGpo[$st.Key]) } else { @() }
    $enabledLinks = @($links | Where-Object { $_.LinkEnabled })
    $st.Scope = @($enabledLinks | ForEach-Object { @{ DN = $_.Target.ToLower(); Site = ($_.TargetType -eq 'Site') } })
    $st.LinkedEnabled = ($enabledLinks.Count -gt 0)
    $rootLinked = @($enabledLinks | Where-Object { $_.TargetType -eq 'Domain' }).Count -gt 0
    $dcLinked = @($enabledLinks | Where-Object { $_.Target -like 'OU=Domain Controllers,DC=*' }).Count -gt 0
    $siteLinked = @($enabledLinks | Where-Object { $_.TargetType -eq 'Site' }).Count -gt 0
    $days = [int]($now - $gpo.ModificationTime).TotalDays
    $total = $st.Settings.Count
    $isEmpty = $st.ReportOK -and ($st.Exts.Computer.Count -eq 0) -and ($st.Exts.User.Count -eq 0)
    $sizeClass = if ($isEmpty) { 'Empty' } elseif ($total -le $SmallGpoThreshold) { 'Small' } elseif ($total -ge $LargeGpoThreshold) { 'Large' } else { 'Normal' }
    if (-not $sizeStats.ContainsKey($d)) { $sizeStats[$d] = @{ Total = 0; Empty = 0; Small = 0; Large = 0; Settings = 0; Mixed = 0; NoDesc = 0 } }
    $sizeStats[$d].Total++; $sizeStats[$d].Settings += $total
    switch ($sizeClass) { 'Empty' { $sizeStats[$d].Empty++ } 'Small' { $sizeStats[$d].Small++ } 'Large' { $sizeStats[$d].Large++ } }
    if ($st.SideCount.Computer -gt 0 -and $st.SideCount.User -gt 0) { $sizeStats[$d].Mixed++ }
    if (-not $gpo.Description) { $sizeStats[$d].NoDesc++ }
    $legacy = @($st.Settings | Where-Object { $_.Legacy })
    $cpass = @($legacy | Where-Object { $_.Legacy -like 'GPP cpassword*' })

    # WMI
    $wmiName = 'None'
    if ($ctx.Gpc.ContainsKey($st.Guid) -and $ctx.Gpc[$st.Guid].gPCWQLFilter -match '\{([0-9a-fA-F\-]{36})\}') {
        $wid = $Matches[1].ToLower()
        if ($ctx.Wmi.ContainsKey($wid)) { $wmiName = $ctx.Wmi[$wid].Name; $ctx.Wmi[$wid].UsedBy.Add($name) }
        else { $wmiName = "MISSING {$wid}"; Add-Finding '1' 'Medium' $d $name 'GPO references a WMI filter that no longer exists' "{$wid}" 'Re-assign or clear the WMI filter.' }
    }

    $out.GPOInventory.Add([pscustomobject][ordered]@{
        Domain = $d; DisplayName = $name; GUID = $st.Guid; Status = "$($gpo.GpoStatus)"
        Created = $gpo.CreationTime.ToString('yyyy-MM-dd'); Modified = $gpo.ModificationTime.ToString('yyyy-MM-dd'); DaysSinceModified = $days
        Owner = $gpo.Owner; OwnerClass = $st.OwnerClass; Description = $gpo.Description; WmiFilter = $wmiName
        ComputerSettings = $st.SideCount.Computer; UserSettings = $st.SideCount.User; SizeClass = $sizeClass
        ComputerExtensions = ($st.Exts.Computer -join '; '); UserExtensions = ($st.Exts.User -join '; ')
        ComputerVersion = "AD $($st.SideVer.Computer.AD) / SYSVOL $($st.SideVer.Computer.Sysvol)"; UserVersion = "AD $($st.SideVer.User.AD) / SYSVOL $($st.SideVer.User.Sysvol)"
        LinkCount = $links.Count; EnabledLinks = $enabledLinks.Count; EnforcedLinks = @($links | Where-Object { $_.Enforced }).Count
        LinkedTo = (@($links | ForEach-Object { "$($_.Target)$(if (-not $_.LinkEnabled) { ' [disabled]' })$(if ($_.Enforced) { ' [enforced]' })" }) -join ' || ')
        ApplyTo = ($st.Apply -join '; '); AppliesToBroadGroup = ($st.Broad.Count -gt 0); DenyApply = ($st.DenyApply -join '; ')
        NonTier0Editors = ($st.EditorsOther -join '; '); IndividualAdminEditors = ($st.EditorsIndiv -join '; ')
        Loopback = $st.Loopback; LegacySettings = $legacy.Count; GPPcpassword = ($cpass.Count -gt 0); LegacyAdmFiles = $st.HasAdm
    })

    # ---- Section 1: inventory & structure
    if ($links.Count -eq 0) {
        if ($days -gt $StaleDays) { Add-Finding '1' 'Medium' $d $name "Unlinked and not modified for $days days" '' 'Back up, then delete/archive (confirm it is not a template).' }
        else { Add-Finding '1' 'Low' $d $name 'Unlinked GPO' "Modified $days days ago" 'Confirm purpose (work in progress/template) or remove.' }
    } elseif ($enabledLinks.Count -eq 0) {
        Add-Finding '1' 'Medium' $d $name 'All links are disabled' (@($links | ForEach-Object { $_.Target }) -join ' || ') 'Effectively unlinked - remove or re-enable deliberately.'
    }
    if ($isEmpty) { Add-Finding '1' 'Low' $d $name 'Empty GPO (no settings configured)' "Links: $($links.Count)" 'Delete; empty linked GPOs still cost processing time.' }
    if ("$($gpo.GpoStatus)" -eq 'AllSettingsDisabled') { Add-Finding '1' 'Low' $d $name 'GPO is fully disabled' "Links: $($links.Count)" 'Remove if no longer needed.' }
    foreach ($side in 'Computer', 'User') {
        if (-not $st.SideEnabled[$side] -and $st.SideCount[$side] -gt 0) {
            Add-Finding '1' 'Medium' $d $name "$side settings exist but the $side section is disabled" "$($st.SideCount[$side]) settings are never applied" 'Decide whether these settings are dead configuration or were disabled by mistake.'
        }
        $v = $st.SideVer[$side]
        if ($v.AD -ne '' -and $v.Sysvol -ne '' -and $v.AD -ne $v.Sysvol) {
            Add-Finding '1' 'High' $d $name "$side version mismatch between AD and SYSVOL" "AD $($v.AD) vs SYSVOL $($v.Sysvol)" 'Investigate SYSVOL replication (DFSR) health before backing up or migrating.'
        }
    }
    if ($st.LinkedEnabled -and $days -gt $StaleDays) { Add-Finding '1' 'Low' $d $name "Linked but not modified for $days days" '' 'Validate the settings are still relevant before carrying forward.' }
    foreach ($l in @($links | Where-Object { $_.Enforced })) { Add-Finding '1' 'Info' $d $name 'Enforced (No Override) link' $l.Target 'Document the reason; keep enforcement to a minimum in the target design.' }
    if ($siteLinked) { Add-Finding '1' 'Medium' $d $name 'Linked at site level' (@($enabledLinks | Where-Object { $_.TargetType -eq 'Site' } | ForEach-Object { $_.TargetName }) -join ', ') 'Site links apply across domains and are often overlooked; re-evaluate in the new design.' }
    if ($st.HasAdm) { Add-Finding '3' 'Low' $d $name 'Legacy .adm templates stored in the GPO' '' 'Remove ADM files once an ADMX central store is in place.' }

    # ---- Section 2: permissions & filtering
    if ($st.EditorsOther.Count -gt 0) {
        $sev = if ($rootLinked -or $dcLinked -or $siteLinked) { 'Critical' } else { 'High' }
        Add-Finding '2' $sev $d $name 'GPO editable by non-Tier0 principal(s)' ($st.EditorsOther -join '; ') 'Anyone who can edit a GPO controls every computer/user it applies to. Remove or move into the Tier model.'
    }
    if ($st.EditorsIndiv.Count -gt 0) { Add-Finding '2' 'Low' $d $name 'Edit rights granted to individual admin accounts' ($st.EditorsIndiv -join '; ') 'Grant rights to groups, not individual accounts.' }
    if ($st.OwnerClass -eq 'Other' -or $st.OwnerClass -eq 'Broad group') { Add-Finding '2' 'Medium' $d $name 'GPO owner is not a Tier0 principal' $gpo.Owner 'Owners can modify permissions; reset ownership to Domain Admins.' }
    if ($st.PermsRead -and -not $st.ComputerRead -and ($st.SideCount.User -gt 0)) {
        Add-Finding '2' 'High' $d $name 'No read permission for Authenticated Users or Domain Computers' "Apply: $($st.Apply -join '; ')" 'Since MS16-072, user settings fail to apply unless the computer can read the GPO. Add Read for Authenticated Users or Domain Computers.'
    }
    if ($st.PermsRead -and $st.Apply.Count -eq 0 -and $st.LinkedEnabled) { Add-Finding '2' 'Medium' $d $name 'Linked GPO has no Apply permission for anyone' '' 'GPO applies to nobody - fix filtering or remove.' }
    if ($st.DenyApply.Count -gt 0) { Add-Finding '2' 'Low' $d $name 'Deny Apply ACE(s) used for exclusion' ($st.DenyApply -join '; ') 'Deny-based exclusions are hard to troubleshoot; prefer positive security filtering.' }
    if ($st.Unresolved.Count -gt 0) { Add-Finding '2' 'Low' $d $name 'Permissions granted to unresolvable SIDs' ($st.Unresolved -join '; ') 'Remove ACEs for deleted accounts.' }

    # ---- Section 3: content
    if ($cpass.Count -gt 0) { Add-Finding '3' 'Critical' $d $name 'Group Policy Preferences password (cpassword) present' (@($cpass | ForEach-Object { "$($_.Category): $($_.Name)" }) -join '; ') 'Remove the item, rotate the exposed password immediately, and use LAPS or another method.' }
    $nonCp = @($legacy | Where-Object { $_.Legacy -notlike 'GPP cpassword*' })
    if ($nonCp.Count -gt 0) {
        $detail = (@($nonCp | Group-Object Legacy | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Count) x $($_.Name)" }) -join ' | ')
        Add-Finding '3' 'Medium' $d $name "$($nonCp.Count) legacy/deprecated setting(s)" $detail 'Do not carry forward without validation; see Settings.csv (Legacy column).'
    }
    $acct = @($st.Settings | Where-Object { $_.Kind -eq 'Account' })
    foreach ($a in $acct) {
        $out.PasswordPolicy.Add([pscustomobject]@{ Domain = $d; Source = "GPO: $name"; SourceType = $(if ($rootLinked) { 'GPO linked at domain root' } else { 'GPO not linked at domain root' })
                                                    AppliesTo = (@($enabledLinks | ForEach-Object { $_.Target }) -join ' || '); Setting = "$($a.Category -replace '^Account Policies/', '')/$($a.Name)"; Value = $a.Value })
    }
    if ($acct.Count -gt 0 -and -not $rootLinked) {
        Add-Finding '3' 'Medium' $d $name 'Password/lockout/Kerberos settings in a GPO not linked at the domain root' "$($acct.Count) account settings" 'These only affect local accounts on computers in scope - domain accounts use the domain-root policy or FGPPs. Usually a misunderstanding; review.'
    }
    if ($st.Loopback) {
        $out.Loopback.Add([pscustomobject]@{ Domain = $d; GPO = $name; Mode = $st.Loopback; LinkedTo = (@($enabledLinks | ForEach-Object { $_.Target }) -join ' || ') })
        $sev = if ($rootLinked) { 'Medium' } else { 'Info' }
        Add-Finding '3' $sev $d $name "Loopback processing ($($st.Loopback))" (@($enabledLinks | ForEach-Object { $_.Target }) -join ' || ') 'Confirm intended scope (RDS/kiosk/VDI); loopback linked broadly changes user policy for every user on those computers.'
    }
    if ($st.Guid -eq $ddpGuid) {
        $extra = @($st.Settings | Where-Object { $_.Kind -notin 'Account', 'SecurityOption', 'Other' })
        if ($extra.Count -gt 0) { Add-Finding '4' 'Medium' $d $name 'Default Domain Policy contains settings beyond account policy' "$($extra.Count) settings: $(@($extra | Select-Object -ExpandProperty Category -Unique | Select-Object -First 6) -join ', ')" 'Keep the DDP limited to password/lockout/Kerberos; move other settings to dedicated GPOs.' }
    }
    if ($st.Guid -eq $ddcpGuid -and -not $dcLinked) { Add-Finding '1' 'High' $d $name 'Default Domain Controllers Policy is not linked to the Domain Controllers OU' '' 'Verify DC security baseline is applied from another GPO, or re-link.' }

    # ---- Section 4: design & organization
    if ($sizeClass -eq 'Large') { Add-Finding '4' 'Low' $d $name "Large/monolithic GPO ($total settings)" "Extensions: $((@($st.Exts.Computer) + @($st.Exts.User) | Select-Object -Unique) -join ', ')" 'Split by purpose in the target design.' }
    if ($name -match '^New Group Policy Object' -or $name -match '^Copy of ' -or $name -match '(?i)\b(test|temp|tmp|old|backup|bak|delete|do not use|donotuse|unused|obsolete)\b') {
        Add-Finding '4' 'Low' $d $name 'Name suggests a default, copied, test or obsolete GPO' '' 'Validate and rename to the target convention or remove.'
    }
    $prefix = (($name -split '[\s_\-\.]+') | Where-Object { $_ } | Select-Object -First 1)
    $pk = "$d|$prefix"; if ($prefixCount.ContainsKey($pk)) { $prefixCount[$pk]++ } else { $prefixCount[$pk] = 1 }

    if (-not $SkipObjectCounts) {
        $somLinks = @($enabledLinks | Where-Object { $_.TargetType -ne 'Site' })
        if ($somLinks.Count -gt 0 -and $somLinks.Count -eq $enabledLinks.Count) {
            $u = 0; $c = 0
            foreach ($l in $somLinks) { $t = $l.Target.ToLower(); if ($UserCount.ContainsKey($t)) { $u += $UserCount[$t] }; if ($CompCount.ContainsKey($t)) { $c += $CompCount[$t] } }
            if ($st.SideEnabled.User -and $st.SideCount.User -gt 0 -and $u -eq 0 -and -not $st.Loopback) {
                Add-Finding '4' 'Medium' $d $name 'User settings linked only where no user accounts exist' "$($st.SideCount.User) user settings; effective only via loopback from another GPO" 'Confirm a loopback GPO targets these computers, otherwise the settings never apply.'
            }
            if ($st.SideEnabled.Computer -and $st.SideCount.Computer -gt 0 -and $c -eq 0) {
                Add-Finding '4' 'Medium' $d $name 'Computer settings linked only where no computer accounts exist' "$($st.SideCount.Computer) computer settings never apply" 'Relink to the correct OU or remove the settings.'
            }
            foreach ($l in $somLinks) {
                $t = $l.Target.ToLower()
                $tu = if ($UserCount.ContainsKey($t)) { $UserCount[$t] } else { 0 }; $tc = if ($CompCount.ContainsKey($t)) { $CompCount[$t] } else { 0 }
                if ($tu -eq 0 -and $tc -eq 0) { Add-Finding '4' 'Low' $d $name 'Linked to an OU with no users or computers' $l.Target 'Remove link or the empty OU.' }
            }
        }
    }
    if ($enabledLinks.Count -gt $ManyLinksPerSom) { Add-Finding '4' 'Info' $d $name "Linked to $($enabledLinks.Count) locations" '' 'Consider linking once at a common parent OU in the target design.' }
}

# Domain-level aggregate findings
foreach ($d in $Dom.Keys) {
    $ctx = $Dom[$d]
    $mine = @($GpoIndex.Values | Where-Object { $_.Domain -eq $d })
    if ($mine.Count -eq 0) { continue }
    $broadN = @($mine | Where-Object { $_.Broad.Count -gt 0 }).Count
    Add-Finding '2' 'Info' $d '' "$broadN of $($mine.Count) GPOs apply to a broad group (Authenticated Users / Everyone / Domain Users / Domain Computers)" 'See GPOInventory.csv AppliesToBroadGroup / ApplyTo' 'Review with GPO owners which of these should be security-filtered.'
    $ss = $sizeStats[$d]
    if ($ss) {
        $avg = [math]::Round($ss.Settings / [math]::Max(1, $ss.Total), 1)
        $smallPct = [math]::Round(100 * ($ss.Small + $ss.Empty) / [math]::Max(1, $ss.Total))
        $sev = if ($smallPct -ge 30) { 'Medium' } else { 'Info' }
        Add-Finding '4' $sev $d '' "GPO size profile: $($ss.Total) GPOs, avg $avg settings, $smallPct% empty/small (<= $SmallGpoThreshold), $($ss.Large) large (>= $LargeGpoThreshold)" "$($ss.Mixed) GPOs mix user and computer settings" 'High share of tiny GPOs indicates sprawl; consolidate by purpose.'
        $descPct = [math]::Round(100 * $ss.NoDesc / [math]::Max(1, $ss.Total))
        if ($descPct -ge 50) { Add-Finding '4' 'Low' $d '' "$descPct% of GPOs have no description" '' 'Adopt a documentation standard (purpose, owner, change ref) in the target environment.' }
    }
    $prefixes = @($prefixCount.Keys | Where-Object { $_ -like "$d|*" } | ForEach-Object { [pscustomobject]@{ Domain = $d; Prefix = ($_ -split '\|', 2)[1]; Count = $prefixCount[$_] } } | Sort-Object Count -Descending)
    foreach ($p in $prefixes) { $out.NamingPrefixes.Add($p) }
    if ($mine.Count -ge 10 -and $prefixes.Count -gt 0 -and ($prefixes[0].Count / $mine.Count) -lt 0.5) {
        Add-Finding '4' 'Low' $d '' 'No dominant naming convention' "Top prefix '$($prefixes[0].Prefix)' used by $($prefixes[0].Count) of $($mine.Count) GPOs" 'Define a convention for the target domain (scope-type-purpose-version).'
    }
    # WMI filters
    foreach ($wid in $ctx.Wmi.Keys) {
        $w = $ctx.Wmi[$wid]
        $out.WmiFilters.Add([pscustomobject]@{ Domain = $d; Name = $w.Name; ID = $wid; Description = $w.Description; Query = $w.Query; Author = $w.Author
                                               Created = $w.Created; Changed = $w.Changed; UsedByCount = $w.UsedBy.Count; UsedBy = ($w.UsedBy -join '; ') })
        if ($w.UsedBy.Count -eq 0) { Add-Finding '1' 'Low' $d '' "Unused WMI filter '$($w.Name)'" '' 'Remove.' }
        if ($w.Query -match '(?i)(Version\s*(like|=)\s*["'']?(5\.|6\.0|6\.1|6\.2|6\.3))|Windows XP|Windows 7|Windows 8|Server 2003|Server 2008|Server 2012') {
            Add-Finding '3' 'Low' $d '' "WMI filter '$($w.Name)' targets legacy OS versions" $w.Query 'Rewrite or retire for the target environment.'
        }
    }
    # AD vs SYSVOL consistency
    if ($ctx.SysvolGuids.Count -gt 0) {
        foreach ($g in $ctx.Gpc.Keys) { if (-not $ctx.SysvolGuids.Contains($g)) { Add-Finding '1' 'High' $d $ctx.Gpc[$g].displayName 'GPO exists in AD but its SYSVOL folder is missing' "{$g}" 'Restore from backup or delete; the GPO cannot apply.' } }
        foreach ($g in $ctx.SysvolGuids) { if (-not $ctx.Gpc.ContainsKey($g)) { Add-Finding '1' 'Medium' $d '' 'Orphaned SYSVOL policy folder (no matching GPO in AD)' "$($ctx.PoliciesPath)\{$g}" 'Archive and remove after confirming.' } }
    }
    if (-not $SkipSysvol) {
        if ($ctx.CentralStoreAdmx -lt 0) { Add-Finding '3' 'Low' $d '' 'No ADMX central store in SYSVOL' '' 'Create a central store with current ADMX in the target domain.' }
        else { Add-Finding '3' 'Info' $d '' "ADMX central store present ($($ctx.CentralStoreAdmx) ADMX files)" '' 'Check template versions are current (Windows, Office, Edge).' }
    }
    # Multiple root-linked GPOs carrying account policy
    $rootAcct = @($mine | Where-Object { @($_.Settings | Where-Object { $_.Kind -eq 'Account' }).Count -gt 0 -and @($LinksByGpo[$_.Key] | Where-Object { $_.LinkEnabled -and $_.TargetType -eq 'Domain' -and $_.SOMDomain -eq $d }).Count -gt 0 })
    if ($rootAcct.Count -gt 1) { Add-Finding '3' 'Medium' $d '' "$($rootAcct.Count) domain-root GPOs define account policy" (@($rootAcct | ForEach-Object { $_.Name }) -join '; ') 'The effective value depends on link order; consolidate password policy into one GPO (or FGPPs).' }
    # Change auditing of GPO edits
    $dcOU = "ou=domain controllers,$($ctx.DN.ToLower())"
    $auditing = @($mine | Where-Object {
        $_.LinkedEnabled -and @($_.Scope | Where-Object { $_.Site -or (Test-DNWithin $dcOU $_.DN) }).Count -gt 0 -and
        @($_.Settings | Where-Object { ($_.Kind -eq 'AdvancedAudit' -and $_.Name -eq 'Audit Directory Service Changes' -and $_.Value -match 'Success') -or
                                        ($_.Kind -eq 'Audit' -and $_.Name -eq 'AuditDSAccess' -and $_.Value -match 'Success=true') }).Count -gt 0 })
    if ($auditing.Count -eq 0) { Add-Finding '5' 'Medium' $d '' 'No GPO enables Directory Service Changes auditing on domain controllers' '' 'Without it, GPO edits/links are not traceable in the Security log. Confirm in interview whether auditing is set elsewhere.' }
    else { Add-Finding '5' 'Info' $d '' 'Directory Service Changes auditing is configured for DCs' (@($auditing | ForEach-Object { $_.Name }) -join '; ') 'Confirm events are forwarded/retained and that a SACL exists on CN=Policies.' }
    $recent = @($mine | Where-Object { ($now - $_.Gpo.ModificationTime).TotalDays -le 90 }).Count
    Add-Finding '5' 'Info' $d '' "$recent GPO(s) modified in the last 90 days" '' 'Use as input for change-control interview: were these changes ticketed and approved?'
    if (@($mine | Where-Object { $_.AGPM }).Count -gt 0) { Add-Finding '5' 'Info' $d '' 'An AGPM-like account has GPO edit rights' '' 'AGPM may be in use for change control - confirm (AGPM is out of mainstream support).' }
}

# ---- Conflicts and redundancy (Section 3)
Log "Analyzing duplicate/conflicting settings"
function Test-ScopeOverlap {
    param($A, $B)
    foreach ($x in $A) { foreach ($y in $B) {
        if ($x.Site -or $y.Site) { return $true }
        if ((Test-DNWithin $x.DN $y.DN) -or (Test-DNWithin $y.DN $x.DN)) { return $true }
    } }
    return $false
}
$byKey = @{}
foreach ($st in $GpoIndex.Values) {
    if (-not $st.LinkedEnabled) { continue }
    foreach ($s in $st.Settings) {
        if (-not $s.Comparable -or -not $st.SideEnabled[$s.Side]) { continue }
        if (-not $byKey.ContainsKey($s.Key)) { $byKey[$s.Key] = @{} }
        $byKey[$s.Key][$st.Key] = @{ St = $st; Value = $s.Value; Setting = $s }
    }
}
foreach ($k in $byKey.Keys) {
    $entries = @($byKey[$k].Values)
    if ($entries.Count -lt 2) { continue }
    $conflict = $false; $redundant = $false
    $cap = [math]::Min($entries.Count, 30)
    for ($a = 0; $a -lt $cap; $a++) { for ($b = $a + 1; $b -lt $cap; $b++) {
        if (Test-ScopeOverlap $entries[$a].St.Scope $entries[$b].St.Scope) {
            if ($entries[$a].Value -ne $entries[$b].Value) { $conflict = $true } else { $redundant = $true }
        }
    } }
    $distinct = @($entries | ForEach-Object { $_.Value } | Select-Object -Unique)
    $status = if ($conflict) { 'Conflict - different values, overlapping scope' } elseif ($redundant) { 'Redundant - same value, overlapping scope' }
              elseif ($distinct.Count -gt 1) { 'Variation - different values, separate scopes' } else { 'Duplicate - same value, separate scopes' }
    $s0 = $entries[0].Setting
    $domains = @($entries | ForEach-Object { $_.St.Domain } | Select-Object -Unique)
    $out.Conflicts.Add([pscustomobject]@{ Status = $status; Side = $s0.Side; Category = $s0.Category; Setting = $s0.Name; GPOCount = $entries.Count; DistinctValues = $distinct.Count
        Domains = ($domains -join '; '); GPOs = (@($entries | ForEach-Object { "$($_.St.Name) [$($_.St.Domain)] = $($_.Value)" }) -join ' || ') })
    if ($conflict) { Add-Finding '3' 'Medium' ($domains -join '; ') '' "Conflicting values for '$($s0.Name)'" "$($s0.Category) in $($entries.Count) GPOs" 'Resolve to one authoritative GPO; verify the winning value with GPMC modeling.' }
}
$cs = @($out.Conflicts | Group-Object Status | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ' | '
if ($cs) { Add-Finding '3' 'Info' '(all)' '' 'Setting overlap summary' $cs 'Redundant and duplicate settings are consolidation candidates for the target design.' }

# ---- Near-duplicate GPOs (content similarity, incl. cross-domain)
Log "Finding near-duplicate GPOs"
$kvSets = @{}; $inv = @{}
foreach ($st in $GpoIndex.Values) {
    $set = New-HashSet
    foreach ($s in $st.Settings) { if ($s.Comparable) { [void]$set.Add("$($s.Key)=$($s.Value)") } }
    if ($set.Count -lt 3) { continue }
    $kvSets[$st.Key] = $set
    foreach ($kv in $set) { if (-not $inv.ContainsKey($kv)) { $inv[$kv] = New-Object System.Collections.Generic.List[string] }; $inv[$kv].Add($st.Key) }
}
$pairs = @{}
foreach ($kv in $inv.Keys) {
    $l = $inv[$kv]; if ($l.Count -lt 2 -or $l.Count -gt 200) { continue }
    for ($a = 0; $a -lt $l.Count; $a++) { for ($b = $a + 1; $b -lt $l.Count; $b++) {
        $x = $l[$a]; $y = $l[$b]; if ([string]::CompareOrdinal($x, $y) -gt 0) { $t = $x; $x = $y; $y = $t }
        $pk = "$x`t$y"; if ($pairs.ContainsKey($pk)) { $pairs[$pk]++ } else { $pairs[$pk] = 1 }
    } }
}
foreach ($pk in $pairs.Keys) {
    $x, $y = $pk -split "`t"
    $shared = $pairs[$pk]; $na = $kvSets[$x].Count; $nb = $kvSets[$y].Count
    $sim = $shared / ($na + $nb - $shared)
    if ($sim -ge $SimilarityThreshold) {
        $A = $GpoIndex[$x]; $B = $GpoIndex[$y]
        $out.NearDuplicates.Add([pscustomobject]@{ Similarity = [math]::Round($sim, 2); GPO_A = $A.Name; Domain_A = $A.Domain; Settings_A = $na
            GPO_B = $B.Name; Domain_B = $B.Domain; Settings_B = $nb; SharedSettings = $shared; CrossDomain = ($A.Domain -ne $B.Domain) })
    }
}
if ($out.NearDuplicates.Count -gt 0) {
    $xd = @($out.NearDuplicates | Where-Object { $_.CrossDomain }).Count
    Add-Finding '3' 'Info' '(all)' '' "$($out.NearDuplicates.Count) near-duplicate GPO pairs (>= $([int]($SimilarityThreshold*100))% identical settings), $xd across domains" 'See NearDuplicates.csv' 'Strong candidates to merge into a single GPO in the consolidated domain.'
}

# ---- Catalog of configuration categories
foreach ($grp in ($out.Settings | Group-Object Domain, Side, { ($_.Category -split '/')[0] + $(if ($_.Category -like 'Preferences/*') { '/' + ($_.Category -split '/')[1] } else { '' }) })) {
    $f = $grp.Group[0]
    $out.Catalog.Add([pscustomobject]@{ Domain = $f.Domain; Side = $f.Side; Category = ($grp.Name -split ', ', 3)[2]
        GPOCount = @($grp.Group | Select-Object -ExpandProperty GUID -Unique).Count; SettingCount = $grp.Count })
}

# ---- Backup coverage (Section 5)
if ($BackupPath) {
    Log "Reading GPO backups from $BackupPath"
    try {
        foreach ($bf in (Get-ChildItem -LiteralPath $BackupPath -Recurse -Filter 'bkupInfo.xml' -Force -File)) {
            try {
                $bx = [xml](Get-Content -LiteralPath $bf.FullName -Raw)
                $bg = $bx.SelectSingleNode("//*[local-name()='GPOGuid']").InnerText.Trim('{} ').ToLower()
                $bd = $bx.SelectSingleNode("//*[local-name()='GPODomain']").InnerText.Trim().ToLower()
                $bt = [datetime]$bx.SelectSingleNode("//*[local-name()='BackupTime']").InnerText.Trim()
                $bk = "$bd|$bg"
                if (-not $Backups.ContainsKey($bk) -or $Backups[$bk] -lt $bt) { $Backups[$bk] = $bt }
            } catch { Add-Err '(backup)' $bf.FullName $_.Exception.Message }
        }
    } catch { Add-Err '(backup)' $BackupPath $_.Exception.Message }
    foreach ($st in $GpoIndex.Values) {
        $has = $Backups.ContainsKey($st.Key)
        $last = if ($has) { $Backups[$st.Key] } else { $null }
        $after = $has -and ($st.Gpo.ModificationTime -gt $last)
        $out.BackupCoverage.Add([pscustomobject]@{ Domain = $st.Domain; GPO = $st.Name; GUID = $st.Guid; Modified = $st.Gpo.ModificationTime
            LastBackup = $last; ModifiedAfterLastBackup = $after; DaysSinceBackup = $(if ($has) { [int]($now - $last).TotalDays } else { '' }) })
    }
    foreach ($d in $Dom.Keys) {
        $bc = @($out.BackupCoverage | Where-Object { $_.Domain -eq $d })
        $never = @($bc | Where-Object { -not $_.LastBackup }).Count
        $stale = @($bc | Where-Object { $_.ModifiedAfterLastBackup }).Count
        $sev = if ($never -gt 0 -or $stale -gt 0) { 'Medium' } else { 'Info' }
        Add-Finding '5' $sev $d '' "Backup coverage: $never GPO(s) never backed up, $stale modified since last backup" "Of $($bc.Count) GPOs; source $BackupPath" 'Take a full Backup-GPO -All before any migration work; schedule recurring backups.'
    }
} else {
    Add-Finding '5' 'Info' '(all)' '' 'GPO backup coverage not verified' 'Run again with -BackupPath <backup share> to measure coverage' 'Confirm backup method, frequency, retention and restore testing in interview.'
}
#endregion

#region ---------- Export ----------
Log "Writing output to $OutputPath"
foreach ($n in $out.Keys) {
    if ($out[$n].Count -eq 0 -and $n -in 'BackupCoverage', 'Errors') { continue }
    $out[$n] | Export-Csv -LiteralPath (Join-Path $OutputPath "$n.csv") -NoTypeInformation -Encoding UTF8
}

$sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$sevs = 'Critical', 'High', 'Medium', 'Low', 'Info'
function H { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
$sb = New-Object System.Text.StringBuilder
[void]$sb.Append(@"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>GPO Assessment Summary</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}h1{margin-bottom:4px}
table{border-collapse:collapse;margin:12px 0;font-size:13px;width:100%}th,td{border:1px solid #ccc;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#f0f0f0}.Critical{background:#f8d0d0}.High{background:#fde2cc}.Medium{background:#fff4c2}.Low{background:#e8f2fb}.Info{background:#f4f4f4}
.small{color:#666;font-size:12px}td.num{text-align:right}
</style></head><body>
<h1>Group Policy Assessment - Discovery Summary</h1>
<div class="small">Forest: $(H $forest.Name) | Domains: $(H ($DomainKeys -join ', ')) | Generated $(H $startTime.ToString('yyyy-MM-dd HH:mm')) | GPOs analyzed: $($GpoIndex.Count) | Errors: $($out.Errors.Count)</div>
<h2>Findings by section</h2><table><tr><th>Section</th>
"@)
foreach ($s in $sevs) { [void]$sb.Append("<th>$s</th>") }
[void]$sb.Append('</tr>')
foreach ($sec in ($SectionNames.Keys | Sort-Object)) {
    $sn = $SectionNames[$sec]
    [void]$sb.Append("<tr><td>$(H $sn)</td>")
    foreach ($s in $sevs) { [void]$sb.Append("<td class='num'>$(@($out.Findings | Where-Object { $_.Section -eq $sn -and $_.Severity -eq $s }).Count)</td>") }
    [void]$sb.Append('</tr>')
}
[void]$sb.Append('</table><h2>Domains</h2><table><tr><th>Domain</th><th>GPOs</th><th>Unlinked</th><th>Empty</th><th>Links</th><th>Block inheritance</th><th>Non-Tier0 editable</th><th>Central store</th></tr>')
foreach ($d in ($Dom.Keys | Sort-Object)) {
    $inv = @($out.GPOInventory | Where-Object { $_.Domain -eq $d })
    [void]$sb.Append("<tr><td>$(H $d)</td><td class='num'>$($inv.Count)</td><td class='num'>$(@($inv | Where-Object { $_.LinkCount -eq 0 }).Count)</td><td class='num'>$(@($inv | Where-Object { $_.SizeClass -eq 'Empty' }).Count)</td>")
    [void]$sb.Append("<td class='num'>$(@($out.Links | Where-Object { $_.SOMDomain -eq $d }).Count)</td><td class='num'>$(@($out.SOMs | Where-Object { $_.Domain -eq $d -and $_.BlocksInheritance }).Count)</td>")
    [void]$sb.Append("<td class='num'>$(@($inv | Where-Object { $_.NonTier0Editors }).Count)</td><td>$(if ($Dom[$d].CentralStoreAdmx -ge 0) { "$($Dom[$d].CentralStoreAdmx) ADMX" } else { 'No' })</td></tr>")
}
[void]$sb.Append('</table><h2>All findings</h2><table><tr><th>Severity</th><th>Section</th><th>Domain</th><th>GPO</th><th>Finding</th><th>Detail</th><th>Recommendation</th></tr>')
foreach ($f in ($out.Findings | Sort-Object @{ e = { $sevOrder[$_.Severity] } }, Section, Domain, GPO)) {
    [void]$sb.Append("<tr class='$($f.Severity)'><td>$($f.Severity)</td><td>$(H $f.Section)</td><td>$(H $f.Domain)</td><td>$(H $f.GPO)</td><td>$(H $f.Finding)</td><td>$(H $f.Detail)</td><td>$(H $f.Recommendation)</td></tr>")
}
[void]$sb.Append('</table><p class="small">Read-only discovery output. Items in section 5 and the intent behind security filtering require confirmation through administrator interviews.</p></body></html>')
$sb.ToString() | Out-File -LiteralPath (Join-Path $OutputPath 'Summary.html') -Encoding UTF8

$el = (Get-Date) - $startTime
Log ("Done in {0:mm\:ss}. GPOs: {1}; findings: {2}; errors: {3}" -f $el, $GpoIndex.Count, $out.Findings.Count, $out.Errors.Count)
Log "Open $(Join-Path $OutputPath 'Summary.html')"
#endregion
