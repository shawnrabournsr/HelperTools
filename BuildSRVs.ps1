<#
===============================================================================
 DNS RESTORE / REBUILD SCRIPT  - - Shawn Rabourn, Quest Software
-------------------------------------------------------------------------------
 This script rebuilds DNS zones and Active Directory locator records on a 
 non–domain-joined Microsoft DNS server. It is designed for restore, migration,
 lab rebuilds, and workgroup DNS scenarios where AD-integrated DNS is not used.

 PARAMETERS
   -Domain        (Required)  The domain name (e.g., corp.example.com)
   -DC            (Required)  The DC hostname (short name)
   -IP            (Required)  The IPv4 address of the DC
   -Site          (Required)  The AD site name
   -GUID          (Required)  The DC's NTDS Settings object GUID
   -ParentDomain  (Optional)  Parent DNS zone for child-domain delegation
   -GC            (Switch)    Register Global Catalog SRV records
   -PDC           (Switch)    Register PDC Emulator SRV record
   -ForestRoot    (Optional)  Forest root domain (for multi-domain forests)
   -DomainGUID    (Optional)  Domain GUID (required when ForestRoot is used)

-------------------------------------------------------------------------------
 USAGE
   Run this script on a Microsoft DNS server (workgroup or standalone) to 
   recreate all required DNS records for a domain controller.

-------------------------------------------------------------------------------
 EXAMPLE 1: Standard single-domain environment
-------------------------------------------------------------------------------
   .\Restore-DNS.ps1 `
       -Domain "corp.example.com" `
       -DC "DC01" `
       -IP "10.20.30.40" `
       -Site "Default-First-Site-Name" `
       -GUID "a1b2c3d4-e5f6-1122-3344-556677889900"

-------------------------------------------------------------------------------
 EXAMPLE 2: Child domain with parent delegation
-------------------------------------------------------------------------------
   .\Restore-DNS.ps1 `
       -Domain "child.corp.example.com" `
       -ParentDomain "corp.example.com" `
       -DC "CHILD-DC01" `
       -IP "10.50.60.70" `
       -Site "Branch01" `
       -GUID "11223344-5566-7788-99aa-bbccddeeff00"

   This will:
     • Create/repair child.corp.example.com zone
     • Create/repair _msdcs.child.corp.example.com
     • Register all SRV, A, CNAME, PTR, and GUID records
     • Add NS delegation under corp.example.com

-------------------------------------------------------------------------------
 EXAMPLE 3: Net-new forest root with DomainGUID
-------------------------------------------------------------------------------
   .\Restore-DNS.ps1 `
       -Domain "root.example.net" `
       -DC "ROOT-DC01" `
       -IP "172.16.10.5" `
       -Site "HQ" `
       -GUID "99887766-5544-3322-1100-aabbccddeeff" `
       -ForestRoot "root.example.net" `
       -DomainGUID "12345678-90ab-cdef-1234-567890abcdef" `
       -GC `
       -PDC

   This will:
     • Create/repair root.example.net and _msdcs.root.example.net
     • Register forest-wide GC and PDC SRVs
     • Register domain-GUID SRV under _msdcs.root.example.net

===============================================================================
#>
param(
    [Parameter(Mandatory)]
    [string]$Domain,        # Target domain / FLZ

    [Parameter(Mandatory)]
    [string]$DC,            # DC hostname (short name)

    [Parameter(Mandatory)]
    [string]$IP,            # IP of the DC

    [Parameter(Mandatory)]
    [string]$Site,          # AD site name

    [Parameter(Mandatory)]
    [string]$GUID,          # DC GUID

    [string]$ParentDomain,  # Optional: parent DNS zone (for child domains)

    [switch]$GC,            # Optional: GC SRVs
    [switch]$PDC,           # Optional: PDC SRV

    [string]$ForestRoot,    # Optional: forest root domain
    [string]$DomainGUID     # Optional: domain GUID (required if ForestRoot is used)
)

# ================================
# HELPER: VALUE OR <none>
# ================================
function Show-ValueOrNone {
    param([string]$Value)
    if ($Value) { return $Value }
    return "<none>"
}

# ================================
# EXECUTION BANNER
# ================================
Write-Host ""
Write-Host "========================================="
Write-Host " DNS RESTORE / REBUILD SCRIPT"
Write-Host " Executing with parameters:"
Write-Host "-----------------------------------------"
Write-Host (" Domain:        {0}" -f $Domain)
Write-Host (" DC:            {0}" -f $DC)
Write-Host (" IP:            {0}" -f $IP)
Write-Host (" Site:          {0}" -f $Site)
Write-Host (" DC GUID:       {0}" -f $GUID)
Write-Host (" ParentDomain:  {0}" -f (Show-ValueOrNone $ParentDomain))
Write-Host (" ForestRoot:    {0}" -f (Show-ValueOrNone $ForestRoot))
Write-Host (" DomainGUID:    {0}" -f (Show-ValueOrNone $DomainGUID))
Write-Host (" GC Enabled:    {0}" -f $GC.IsPresent)
Write-Host (" PDC Enabled:   {0}" -f $PDC.IsPresent)
Write-Host "========================================="
Write-Host ""
# ================================
# PARAMETER VALIDATION
# ================================
function Test-Parameters {

    Write-Host "Validating parameters..." -ForegroundColor Cyan

    # --- Domain ---
    if ($Domain -notmatch '^[a-zA-Z0-9.-]+$') {
        throw "Invalid Domain: '$Domain'"
    }

    # --- DC hostname ---
    if ($DC -notmatch '^[a-zA-Z0-9-]+$') {
        throw "Invalid DC hostname: '$DC'"
    }

    # --- IPv4 ---
    if ($IP -notmatch '^(\d{1,3}\.){3}\d{1,3}$') {
        throw "Invalid IPv4 address: '$IP'"
    }
    $oct = $IP.Split('.')
    if ($oct | Where-Object { [int]$_ -gt 255 }) {
        throw "Invalid IPv4 address (octet out of range): '$IP'"
    }

    # --- Site ---
    if ($Site -notmatch '^[a-zA-Z0-9._-]+$') {
        throw "Invalid Site name: '$Site'"
    }

    # --- DC GUID ---
    if ($GUID -notmatch '^[0-9a-fA-F-]{36}$') {
        throw "Invalid DC GUID: '$GUID'"
    }

    # --- Parent Domain ---
    if ($ParentDomain -and ($ParentDomain -notmatch '^[a-zA-Z0-9.-]+$')) {
        throw "Invalid ParentDomain: '$ParentDomain'"
    }

    # --- Forest Root ---
    if ($ForestRoot -and ($ForestRoot -notmatch '^[a-zA-Z0-9.-]+$')) {
        throw "Invalid ForestRoot: '$ForestRoot'"
    }

    # --- Domain GUID (only if ForestRoot is used) ---
    if ($ForestRoot -and -not $DomainGUID) {
        throw "DomainGUID is required when ForestRoot is specified."
    }

    if ($DomainGUID -and ($DomainGUID -notmatch '^[0-9a-fA-F-]{36}$')) {
        throw "Invalid DomainGUID: '$DomainGUID'"
    }

    Write-Host "Parameter validation passed." -ForegroundColor Green
}

# ================================
# FUNCTIONS
# ================================

function Ensure-PrimaryZone {
    param([string]$ZoneName)
    if (-not (Get-DnsServerZone -Name $ZoneName -ErrorAction SilentlyContinue)) {
        Write-Host "Creating zone: $ZoneName"
        Add-DnsServerPrimaryZone -Name $ZoneName -DynamicUpdate NonsecureAndSecure -ZoneFile "$ZoneName.dns"
    } else {
        Write-Host "Zone exists: $ZoneName"
    }
}

function Ensure-ARecord {
    param([string]$Zone,[string]$Name,[string]$IP)
    if (-not (Get-DnsServerResourceRecord -ZoneName $Zone -Name $Name -RRType "A" -ErrorAction SilentlyContinue)) {
        Add-DnsServerResourceRecordA -ZoneName $Zone -Name $Name -IPv4Address $IP
        Write-Host "Added A: $Name --> $IP"
    } else {
        Write-Host "A exists: $Name"
    }
}

function Ensure-CNAME {
    param([string]$Zone,[string]$Name,[string]$Target)
    if (-not (Get-DnsServerResourceRecord -ZoneName $Zone -Name $Name -RRType "CNAME" -ErrorAction SilentlyContinue)) {
        Add-DnsServerResourceRecordCName -ZoneName $Zone -Name $Name -HostNameAlias $Target
        Write-Host "Added CNAME: $Name --> $Target"
    } else {
        Write-Host "CNAME exists: $Name"
    }
}

function Ensure-SRV {
    param([string]$Zone,[string]$Name,[int]$Port,[string]$Target)

    $existing = Get-DnsServerResourceRecord -ZoneName $Zone -Name $Name -RRType SRV -ErrorAction SilentlyContinue

    if ($existing) {
        $match = $existing | Where-Object {
            $_.RecordData.Port -eq $Port -and
            $_.RecordData.DomainName.TrimEnd('.') -eq $Target
        }
        if ($match) {
            Write-Host "SRV exists: $Name for $Port --> $Target"
            return
        }

        Add-DnsServerResourceRecord -ZoneName $Zone -Srv -Name $Name -DomainName $Target -Priority 0 -Weight 100 -Port $Port
        Write-Host "Added additional SRV: $Name --> $Target for $Port"
    }
    else {
        Add-DnsServerResourceRecord -ZoneName $Zone -Srv -Name $Name -DomainName $Target -Priority 0 -Weight 100 -Port $Port
        Write-Host "Added SRV: $Name --> $Target for $Port"
    }
}

function Ensure-PTR {
    param([string]$IP,[string]$FQDN)

    $octets = $IP.Split('.')
    if ($octets.Count -ne 4) {
        Write-Warning "Invalid IP for PTR: $IP"
        return
    }

    $o1 = $octets[0]
    $o2 = $octets[1]
    $o3 = $octets[2]
    $o4 = $octets[3]

    $zones = @(
        "$o3.$o2.$o1.in-addr.arpa",
        "$o2.$o1.in-addr.arpa",
        "$o1.in-addr.arpa"
    )

    $zone = $null
    foreach ($z in $zones) {
        if (Get-DnsServerZone -Name $z -ErrorAction SilentlyContinue) {
            $zone = $z
            break
        }
    }

    if (-not $zone) {
        $zone = "$o3.$o2.$o1.in-addr.arpa"
        Write-Host "Creating reverse zone: $zone"
        Add-DnsServerPrimaryZone -Name $zone -ZoneFile "$zone.dns" -DynamicUpdate NonsecureAndSecure
    }

    $existing = Get-DnsServerResourceRecord -ZoneName $zone -Name $o4 -RRType PTR -ErrorAction SilentlyContinue

    if ($existing) {
        Write-Host "PTR exists: $IP --> $FQDN"
        return
    }

    Add-DnsServerResourceRecord -ZoneName $zone -Ptr -Name $o4 -PtrDomainName $FQDN
    Write-Host "Added PTR: $IP --> $FQDN in $zone"
}

function Ensure-Delegation {
    param([string]$ParentZone,[string]$ChildLabel,[string]$ChildDC_FQDN)

    $existing = Get-DnsServerResourceRecord -ZoneName $ParentZone -Name $ChildLabel -RRType NS -ErrorAction SilentlyContinue

    if ($existing) {
        Write-Host "Delegation exists: $ChildLabel.$ParentZone"
        return
    }

    Add-DnsServerResourceRecord -ZoneName $ParentZone -NS -Name $ChildLabel -NameServer $ChildDC_FQDN
    Write-Host "Created delegation (NS record): $ChildLabel.$ParentZone --> $ChildDC_FQDN"
}

# ================================
# NORMALIZE
# ================================
$Domain   = $Domain.ToLower()
$DC_FQDN  = "$DC.$Domain"
$MSDCS    = "_msdcs.$Domain"

$Tcp      = "_tcp"
$Udp      = "_udp"
$SitePath = "_sites.$Site"

# Validate everything before touching DNS
Test-Parameters
# ================================
# ENSURE ZONES
# ================================
Ensure-PrimaryZone -ZoneName $Domain
Ensure-PrimaryZone -ZoneName $MSDCS

# ================================
# DOMAIN RECORDS
# ================================
Ensure-ARecord -Zone $Domain -Name $DC -IP $IP
Ensure-PTR    -IP $IP -FQDN $DC_FQDN

Ensure-CNAME -Zone $MSDCS -Name $GUID -Target $DC_FQDN

Ensure-SRV $Domain "_ldap.$Tcp"      389 $DC_FQDN
Ensure-SRV $Domain "_kerberos.$Tcp"   88 $DC_FQDN
Ensure-SRV $Domain "_kpasswd.$Tcp"   464 $DC_FQDN

Ensure-SRV $Domain "_ldap.$SitePath.$Tcp"      389 $DC_FQDN
Ensure-SRV $Domain "_kerberos.$SitePath.$Tcp"  88 $DC_FQDN

Ensure-SRV $MSDCS "_ldap._tcp.dc"      389 $DC_FQDN
Ensure-SRV $MSDCS "_kerberos._tcp.dc"   88 $DC_FQDN

if ($GC) {
    Ensure-SRV $Domain   "_gc.$Tcp"              3268 $DC_FQDN
    Ensure-SRV $Domain   "_gc.$SitePath.$Tcp"    3268 $DC_FQDN
    Ensure-SRV $MSDCS    "_gc.$Tcp"              3268 $DC_FQDN
}

if ($PDC) {
    Ensure-SRV $MSDCS "_ldap._tcp.pdc" 389 $DC_FQDN
}

# ================================
# OPTIONAL PARENT DOMAIN DELEGATION
# ================================
if ($ParentDomain) {
    $ChildLabel = ($Domain -replace "\.$ParentDomain$", "")
    Ensure-Delegation -ParentZone $ParentDomain -ChildLabel $ChildLabel -ChildDC_FQDN $DC_FQDN
}

# ================================
# OPTIONAL FOREST ROOT RECORDS
# ================================
if ($ForestRoot) {

    $ForestMSDCS = "_msdcs.$ForestRoot"
    Ensure-PrimaryZone -ZoneName $ForestMSDCS

    if ($DomainGUID) {
        Ensure-SRV $ForestMSDCS "_ldap._tcp.$DomainGUID.domains" 389 $DC_FQDN
    }

    if ($GC) {
        Ensure-SRV $ForestMSDCS "_gc.$Tcp"              3268 $DC_FQDN
        Ensure-SRV $ForestMSDCS "_gc.$SitePath.$Tcp"    3268 $DC_FQDN
    }

    if ($PDC) {
        Ensure-SRV $ForestMSDCS "_ldap._tcp.pdc" 389 $DC_FQDN
    }
}
