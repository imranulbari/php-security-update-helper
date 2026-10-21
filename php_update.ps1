[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Apply,
    [switch]$RestartServices,
    [switch]$DeepScan
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

    $candidatePaths = @(
        'C:\php\php.exe',
        'C:\tools\php\php.exe',
        'C:\xampp\php\php.exe',
        (Join-Path $env:ProgramFiles 'PHP\php.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'PHP\php.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\PHP\php.exe'),
        (Join-Path $env:USERPROFILE 'scoop\apps\php\current\php.exe'),
        'C:\ProgramData\chocolatey\lib\php\tools\php.exe'
    ) | Where-Object { $_ }

    $bundleRoots = @(
        'C:\wamp64\bin\php',
        'C:\wamp\bin\php',
        'C:\laragon\bin\php'
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }

    foreach ($bundleRoot in $bundleRoots) {
        $candidatePaths += Get-ChildItem -LiteralPath $bundleRoot -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName 'php.exe' }
    }

    Write-Host 'Discovering php.exe in PATH and common installation locations...'
    $index = 0
    foreach ($candidatePath in $candidatePaths) {
        $index++
        Write-Progress -Activity 'Discovering PHP installations' `
            -Status "Checking $candidatePath" `
            -PercentComplete (($index / $candidatePaths.Count) * 100)
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
            $candidates += (Resolve-Path -LiteralPath $candidatePath).Path
        }
    }

    if ($DeepScan) {
        $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA) |
            Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }
        $index = 0
        foreach ($root in $roots) {
            $index++
            Write-Progress -Activity 'Deep scanning for PHP installations' `
                -Status "Scanning $root; this can take several minutes" `
                -PercentComplete (($index / $roots.Count) * 100)
            $candidates += Get-ChildItem -LiteralPath $root -Filter php.exe -File -Recurse -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName
        }
    }

    Write-Progress -Activity 'Discovering PHP installations' -Completed
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
