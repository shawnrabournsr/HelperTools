<#
.SYNOPSIS
    Provides functions for parsing and hashing HOSTS and LMHOSTS files.

.DESCRIPTION
    This module includes four functions:
        - Get-HostsMapping
        - Get-LmHostsMapping
        - Get-HostsHash
        - Get-LmHostsHash

    These functions allow you to extract name/IP mappings and compute
    SHA-256 hashes for integrity monitoring.
#>
function Get-HostsMapping {
    [CmdletBinding()]
    param()

    $path = "$env:SystemRoot\System32\drivers\etc\hosts"

    if (-not (Test-Path $path)) {
        throw "HOSTS file not found at $path"
    }

    $lines = Get-Content $path
    $lineNumber = 0

    foreach ($line in $lines) {
        $lineNumber++

        # Skip comments and blank lines
        if ($line -match '^\s*$' -or $line.Trim().StartsWith('#')) {
            continue
        }

        # Must start with an IP address
        if ($line -notmatch '^\s*\d') {
            throw "HOSTS syntax error at line $lineNumber: '$line'"
        }

        $parts = $line -split '\s+'

        # Must have at least IP + hostname
        if ($parts.Count -lt 2) {
            throw "HOSTS syntax error at line $lineNumber: Missing hostname"
        }

        # Validate IP
        if (-not ([System.Net.IPAddress]::TryParse($parts[0], [ref]$null))) {
            throw "HOSTS syntax error at line $lineNumber: Invalid IP '$($parts[0])'"
        }

        # Validate hostname (basic check)
        if ($parts[1] -match '\s') {
            throw "HOSTS syntax error at line $lineNumber: Hostname contains spaces"
        }

        [PSCustomObject]@{
            IPAddress = $parts[0]
            Hostname  = $parts[1]
            Source    = $path
            Line      = $lineNumber
        }
    }
}

function Get-LmHostsMapping {
    [CmdletBinding()]
    param()

    $path = "$env:SystemRoot\System32\drivers\etc\lmhosts"

    if (-not (Test-Path $path)) {
        throw "LMHOSTS file not found at $path"
    }

    $lines = Get-Content $path
    $lineNumber = 0

    foreach ($line in $lines) {
        $lineNumber++

        # Skip comments and blank lines
        if ($line -match '^\s*$' -or $line.Trim().StartsWith('#')) {
            continue
        }

        # Must start with an IP address
        if ($line -notmatch '^\s*\d') {
            throw "LMHOSTS syntax error at line $lineNumber: '$line'"
        }

        $parts = $line -split '\s+'

        if ($parts.Count -lt 2) {
            throw "LMHOSTS syntax error at line $lineNumber: Missing NetBIOS name"
        }

        # Validate IP
        if (-not ([System.Net.IPAddress]::TryParse($parts[0], [ref]$null))) {
            throw "LMHOSTS syntax error at line $lineNumber: Invalid IP '$($parts[0])'"
        }

        # NetBIOS name must be a single token
        if ($parts[1] -match '\s') {
            throw "LMHOSTS syntax error at line $lineNumber: NetBIOS name contains spaces"
        }

        # Flags (optional)
        $flags = $parts[2..($parts.Count-1)] -join ' '
        if ($flags -and $flags -notmatch '^#') {
            throw "LMHOSTS syntax error at line $lineNumber: Flags must begin with '#'"
        }

        [PSCustomObject]@{
            IPAddress = $parts[0]
            NetBIOS   = $parts[1]
            Flags     = $flags
            Source    = $path
            Line      = $lineNumber
        }
    }
}

function Get-HostsHash {
    [CmdletBinding()]
    param()

    $path = "$env:SystemRoot\System32\drivers\etc\hosts"

    if (-not (Test-Path $path)) {
        throw "HOSTS file not found at $path"
    }

    $hash = Get-FileHash -Path $path -Algorithm SHA256

    [PSCustomObject]@{
        Path = $path
        Hash = $hash.Hash
    }
}

function Get-LmHostsHash {
    [CmdletBinding()]
    param()

    $path = "$env:SystemRoot\System32\drivers\etc\lmhosts"

    if (-not (Test-Path $path)) {
        throw "LMHOSTS file not found at $path"
    }

    $hash = Get-FileHash -Path $path -Algorithm SHA256

    [PSCustomObject]@{
        Path = $path
        Hash = $hash.Hash
    }
}
