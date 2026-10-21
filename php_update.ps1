[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Apply,
    [switch]$RestartServices
)

$ErrorActionPreference = 'Stop'
$ProvidedCves = 'CVE-2026-109618, CVE-2026-109619'
$ProvidedFixedVersions = @{
    '8.5' = [version]'8.5.12'
    '8.4' = [version]'8.4.27'
    '8.3' = [version]'8.3.36'
    '8.2' = [version]'8.2.35'
}

function Get-PhpExecutables {
    $candidates = @()
    $command = Get-Command php.exe -ErrorAction SilentlyContinue
    if ($command) {
        $candidates += $command.Source
    }

    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:LOCALAPPDATA,
        'C:\php'
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $roots) {
        $candidates += Get-ChildItem -Path $root -Filter php.exe -File -Recurse -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName
    }

    $candidates | Sort-Object -Unique
}

function Get-PhpVersion {
    param([Parameter(Mandatory)][string]$Path)

    $output = & $Path -r 'echo PHP_VERSION;' 2>$null
    if ($LASTEXITCODE -eq 0 -and $output -match '^\d+\.\d+\.\d+') {
        return [version]$output
    }
    return $null
}

function Get-PackageManager {
    foreach ($name in 'winget.exe', 'choco.exe', 'scoop.cmd') {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }
    return $null
}

Write-Host "PHP host inventory for supplied CVEs: $ProvidedCves"
Write-Warning 'Verify the CVE claims and fixed versions against official PHP and package-provider advisories.'

$phpExecutables = @(Get-PhpExecutables)
if ($phpExecutables.Count -eq 0) {
    Write-Host 'No php.exe was found in PATH or common installation paths.'
} else {
    foreach ($php in $phpExecutables) {
        $version = Get-PhpVersion -Path $php
        if (-not $version) {
            Write-Warning "$($php): version could not be read."
            continue
        }

        $branch = '{0}.{1}' -f $version.Major, $version.Minor
        $target = $ProvidedFixedVersions[$branch]
        if ($target -and $version -ge $target) {
            Write-Host "$($php) : $version (meets supplied target $target)"
        } elseif ($target) {
            Write-Warning "$($php) : $version (below supplied target $target)"
        } else {
            Write-Warning "$($php) : $version (no supplied target for PHP $branch)"
        }
    }
}

if ($Apply) {
    $packageManager = Get-PackageManager
    if (-not $packageManager) {
        throw 'No supported Windows package manager (winget, Chocolatey, Scoop) was found. Use the PHP distribution or application vendor update procedure.'
    }

    if ($PSCmdlet.ShouldProcess('installed PHP package', "Update using $packageManager")) {
        switch -Wildcard ($packageManager) {
            '*winget.exe' { & $packageManager upgrade --id PHP.PHP --exact --accept-source-agreements --accept-package-agreements }
            '*choco.exe'  { & $packageManager upgrade php -y }
            '*scoop.cmd'  { & $packageManager update php }
        }
        if ($LASTEXITCODE -ne 0) {
            throw "Package-manager update failed with exit code $LASTEXITCODE."
        }
    }
}

if ($RestartServices) {
    $iis = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    if ($iis -and $iis.Status -eq 'Running') {
        if ($PSCmdlet.ShouldProcess('W3SVC', 'Restart IIS web service')) {
            Restart-Service -Name W3SVC
            Write-Host 'Restarted IIS World Wide Web Publishing Service (W3SVC).'
        }
    } else {
        Write-Warning 'IIS W3SVC is not running. Restart the web server or PHP process manager used by this host manually.'
    }
}

Write-Warning 'This script does not update PHP bundled in Docker images, XAMPP/WampServer, IIS application deployments, or manually extracted ZIP installations.'
