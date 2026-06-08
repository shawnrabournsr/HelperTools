
#########################################################################################################################################################
#
# This script was written by Shawn Rabourn of Quest Software June 2026
#
# This script comes with no warranties, guarantees or any other feel-good devices, use at own risk.
# 
# The purpose of this script is to create SRV records on a workgroup DNS server for tactical recoveries
# 
# 
#
#########################################################################################################################################################



param(

    
    [Parameter(Mandatory)]
    [string]$Domain,      # Target domain / FLZ

    [Parameter(Mandatory)]
    [string]$DC,          # DC 

    [Parameter(Mandatory)]
    [string]$IP,          # IP of the DC

    [Parameter(Mandatory)]
    [string]$Site,         # the site name

    [Parameter(Mandatory)]
    [string]$GUID,          # DC GUID

    [string]$ParentDomain,  # Optional - if you are a child with a parent DNS zone

    [switch]$GC,            # Optional GC SRVs
    [switch]$PDC,           # Optional PDC SRV

    [string]$ForestRoot,    # Optional: forest root domain 
    [string]$DomainGUID     # Optional: domain GUID (required if ForestRoot is used)
)

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

# ================================
# PTR SUPPORT (NEW)
# ================================
function Ensure-PTR {
    param(
        [string]$IP,
        [string]$FQDN
    )

    # Split IP
    $octets = $IP.Split('.')
    $o1 = $octets[0]
    $o2 = $octets[1]
    $o3 = $octets[2]
    $o4 = $octets[3]

    # Candidate reverse zones (most specific first)
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

    # If no reverse zone exists, create the /24
    if (-not $zone) {
        $zone = "$o3.$o2.$o1.in-addr.arpa"
        Write-Host "Creating reverse zone: $zone"
        Add-DnsServerPrimaryZone -Name $zone -ZoneFile "$zone.dns" -DynamicUpdate NonsecureAndSecure
    }

    # Check if PTR already exists
    $existing = Get-DnsServerResourceRecord `
        -ZoneName $zone `
        -Name $o4 `
        -RRType PTR `
        -ErrorAction SilentlyContinue

    if ($existing) {
        Write-Host "PTR exists: $IP --> $FQDN"
        return
    }

    # Create PTR
    Add-DnsServerResourceRecord `
        -ZoneName $zone `
        -Ptr `
        -Name $o4 `
        -PtrDomainName $FQDN

    Write-Host "Added PTR: $IP --> $FQDN in $zone"
}

# ================================
# DELEGATION (OLD DNS MODULE SAFE)
# ================================
function Ensure-Delegation {
    param(
        [string]$ParentZone,
        [string]$ChildLabel,
        [string]$ChildDC_FQDN
    )

    $existing = Get-DnsServerResourceRecord `
        -ZoneName $ParentZone `
        -Name $ChildLabel `
        -RRType NS `
        -ErrorAction SilentlyContinue

    if ($existing) {
        Write-Host "Delegation exists: $ChildLabel.$ParentZone"
        return
    }

    Add-DnsServerResourceRecord `
        -ZoneName $ParentZone `
        -NS `
        -Name $ChildLabel `
        -NameServer $ChildDC_FQDN

    Write-Host "Created delegation (NS record): $ChildLabel.$ParentZone --> $ChildDC_FQDN"
}

# ================================
# NORMALIZE
# ================================
$Domain = $Domain.ToLower()
$DC_FQDN = "$DC.$Domain"
$MSDCS = "_msdcs.$Domain"

$Tcp = "_tcp"
$Udp = "_udp"
$SitePath = "_sites.$Site"

# ================================
# ENSURE ZONES
# ================================
Ensure-PrimaryZone -ZoneName $Domain
Ensure-PrimaryZone -ZoneName $MSDCS

# ================================
# DOMAIN RECORDS
# ================================
Ensure-ARecord -Zone $Domain -Name $DC -IP $IP

# NEW: PTR for the DC
Ensure-PTR -IP $IP -FQDN $DC_FQDN

# DC GUID CNAME
Ensure-CNAME -Zone $MSDCS -Name $GUID -Target $DC_FQDN

# Domain-wide SRV
Ensure-SRV $Domain "_ldap.$Tcp"     389 $DC_FQDN
Ensure-SRV $Domain "_kerberos.$Tcp"  88 $DC_FQDN
Ensure-SRV $Domain "_kpasswd.$Tcp"  464 $DC_FQDN

# Site-specific SRV
Ensure-SRV $Domain "_ldap.$SitePath.$Tcp"     389 $DC_FQDN
Ensure-SRV $Domain "_kerberos.$SitePath.$Tcp"  88 $DC_FQDN

# Forest-wide SRV (for this domain)
Ensure-SRV $MSDCS "_ldap._tcp.dc"     389 $DC_FQDN
Ensure-SRV $MSDCS "_kerberos._tcp.dc"  88 $DC_FQDN

# Optional GC SRVs
if ($GC) {
    Ensure-SRV $Domain "_gc.$Tcp" 3268 $DC_FQDN
    Ensure-SRV $Domain "_gc.$SitePath.$Tcp" 3268 $DC_FQDN
    Ensure-SRV $MSDCS "_gc.$Tcp" 3268 $DC_FQDN
}

# Optional PDC SRV
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

    # Domain-GUID SRV
    if ($DomainGUID) {
        Ensure-SRV $ForestMSDCS "_ldap._tcp.$DomainGUID.domains" 389 $DC_FQDN
    }

    # Forest-wide GC SRVs
    if ($GC) {
        Ensure-SRV $ForestMSDCS "_gc.$Tcp" 3268 $DC_FQDN
        Ensure-SRV $ForestMSDCS "_gc.$SitePath.$Tcp" 3268 $DC_FQDN
    }

    # Forest-wide PDC SRV
    if ($PDC) {
        Ensure-SRV $ForestMSDCS "_ldap._tcp.pdc" 389 $DC_FQDN
    }
}
