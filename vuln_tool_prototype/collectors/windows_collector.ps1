<#
.SYNOPSIS
Collects local Windows security-relevant inventory into the shared JSON shape.

.DESCRIPTION
All sources are local: CIM, the uninstall registry, services, installed
hotfixes, and listening TCP/UDP sockets. A failed source is written to
collector_errors so a partial result is still useful.

.EXAMPLE
./windows_collector.ps1 -OutFile ./windows_artifacts.json
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutFile = "windows_artifacts.json"
)

$ErrorActionPreference = "Stop"
$collectorErrors = [System.Collections.Generic.List[string]]::new()

function Add-CollectorError {
    param([string]$Source, [System.Management.Automation.ErrorRecord]$ErrorRecord)
    $collectorErrors.Add("$Source failed: $($ErrorRecord.Exception.Message)")
}

function Get-InstalledPrograms {
    $programs = [System.Collections.Generic.List[object]]::new()
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($path in $paths) {
        try {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                ForEach-Object {
                    [void]$programs.Add([ordered]@{
                        name = [string]$_.DisplayName
                        version = if ($_.DisplayVersion) { [string]$_.DisplayVersion } else { 'unknown' }
                        architecture = if ($path -like '*Wow6432Node*') { 'x86' } else { $null }
                        source = 'windows_registry'
                    })
                }
        } catch {
            Add-CollectorError -Source "Uninstall registry ($path)" -ErrorRecord $_
        }
    }
    return @($programs | Sort-Object name, version -Unique)
}

function Get-ListeningPorts {
    $ports = [System.Collections.Generic.List[object]]::new()
    try {
        Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            $process = $null
            if ($_.OwningProcess -gt 0) {
                $process = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            }
            [void]$ports.Add([ordered]@{
                protocol = 'tcp'
                local_address = [string]$_.LocalAddress
                local_port = [int]$_.LocalPort
                process = $process
                pid = [int]$_.OwningProcess
            })
        }
        Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            $process = $null
            if ($_.OwningProcess -gt 0) {
                $process = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            }
            [void]$ports.Add([ordered]@{
                protocol = 'udp'
                local_address = [string]$_.LocalAddress
                local_port = [int]$_.LocalPort
                process = $process
                pid = [int]$_.OwningProcess
            })
        }
    } catch {
        # Some managed Windows devices deny the NetTCPConnection CIM provider
        # even to an administrator. netstat remains a local, read-only fallback.
        try {
            & "$env:SystemRoot\System32\netstat.exe" -ano | ForEach-Object {
                if ($_ -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$') {
                    [void]$ports.Add([ordered]@{
                        protocol = 'tcp'; local_address = [string]$matches[1]
                        local_port = [int]$matches[2]; process = $null; pid = [int]$matches[3]
                    })
                } elseif ($_ -match '^\s*UDP\s+(\S+):(\d+)\s+\S+\s+(\d+)\s*$') {
                    [void]$ports.Add([ordered]@{
                        protocol = 'udp'; local_address = [string]$matches[1]
                        local_port = [int]$matches[2]; process = $null; pid = [int]$matches[3]
                    })
                }
            }
        } catch {
            Add-CollectorError -Source 'Network listener collection' -ErrorRecord $_
        }
    }
    return @($ports)
}

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
} catch {
    $os = $null
}

$packages = @(Get-InstalledPrograms)

$hotfixes = [System.Collections.Generic.List[object]]::new()
try {
    Get-HotFix -ErrorAction Stop | ForEach-Object {
        [void]$hotfixes.Add([ordered]@{
            hotfix_id = [string]$_.HotFixID
            description = [string]$_.Description
            installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { $null }
        })
    }
} catch {
    # systeminfo is a local command fallback for systems that block WMI.
    try {
        & "$env:SystemRoot\System32\systeminfo.exe" | ForEach-Object {
            if ($_ -match '(KB\d+)') {
                [void]$hotfixes.Add([ordered]@{
                    hotfix_id = $matches[1]; description = 'Reported by systeminfo'; installed_on = $null
                })
            }
        }
    } catch {
        Add-CollectorError -Source 'Hotfix collection' -ErrorRecord $_
    }
}

$services = [System.Collections.Generic.List[object]]::new()
try {
    Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
        [void]$services.Add([ordered]@{
            name = [string]$_.Name
            state = [string]$_.State
            start_type = [string]$_.StartMode
        })
    }
} catch {
    # Get-Service does not rely on the CIM service provider, but cannot expose
    # the startup type; retain the useful service name and state nonetheless.
    try {
        Get-Service -ErrorAction Stop | ForEach-Object {
            [void]$services.Add([ordered]@{
                name = [string]$_.Name; state = [string]$_.Status; start_type = $null
            })
        }
    } catch {
        Add-CollectorError -Source 'Service collection' -ErrorRecord $_
    }
}

$result = [ordered]@{
    schema_version = '1.0'
    host = [ordered]@{
        hostname = $env:COMPUTERNAME
        os_family = 'windows'
        os_version = if ($os) { "$($os.Caption) $($os.Version)" } else { [System.Environment]::OSVersion.VersionString }
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }
    # Values are captured with @() above so JSON retains arrays both when
    # there is one item and when there are none.
    packages = $packages
    hotfixes = @($hotfixes)
    listening_ports = @(Get-ListeningPorts)
    services = @($services)
    suid_binaries = @()
    kernel_params = @()
    containers = @()
    collector_errors = @($collectorErrors)
}

$destination = [System.IO.Path]::GetFullPath($OutFile)
$parent = Split-Path -Parent $destination
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $destination -Encoding utf8
Write-Host "Collected $($packages.Count) packages, $($hotfixes.Count) hotfixes, $($result.listening_ports.Count) listening ports and $($services.Count) services."
Write-Host "Written to $destination"
