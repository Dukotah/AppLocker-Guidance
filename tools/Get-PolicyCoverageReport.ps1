#Requires -Version 5.1
<#
.SYNOPSIS
Writes a Markdown coverage report for a starter policy against the Microsoft recommended
block list and the LOLBAS project.

.DESCRIPTION
Static columns come from the policy XML (is there a deny rule naming the file that reaches
standard users). When the AppLocker module is present and -User is given, every candidate
binary that exists on this machine is also run through Test-AppLockerPolicy -XmlPolicy,
which evaluates the file offline and does not apply anything.

LOLBAS is report-only: the starter policy deliberately leaves many LOLBAS entries allowed.

.EXAMPLE
.\tools\Get-PolicyCoverageReport.ps1 -Policy '.\AppLocker Starter Policy\Windows11_AppLocker Starter Policy.xml' -LolbasJson .\lolbas.json -User testuser -OutFile report.md
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Policy,
    [string]$LolbasJson,
    [string]$User,
    [Parameter(Mandatory)][string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\tests\AppLockerPolicy.psm1') -Force

$runtime = $User -and (Get-Command Test-AppLockerPolicy -ErrorAction SilentlyContinue)

function Get-Decision([string]$File) {
    if (-not $runtime -or -not $File -or -not (Test-Path -LiteralPath $File -PathType Leaf)) { return '' }
    try { return (Test-AppLockerPolicy -XmlPolicy $Policy -Path $File -User $User).PolicyDecision.ToString() }
    catch { return 'error: ' + $_.Exception.Message }
}

function Find-Binary([string]$Name, [string[]]$Candidates) {
    foreach ($c in $Candidates) {
        $p = [Environment]::ExpandEnvironmentVariables(($c -replace '^C:\\Windows', '%windir%' -replace '^C:\\Program Files \(x86\)', '%ProgramFiles(x86)%' -replace '^C:\\Program Files', '%ProgramFiles%'))
        # LOLBAS paths can hold placeholders such as C:\Users\<username>\... ; skip those.
        if ($p -match '[\*\?<>"|]') { continue }
        if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    }
    return $null
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# Coverage report: $(Split-Path -Leaf $Policy)")
$lines.Add('')
$lines.Add("Runtime decisions: $(if ($runtime) { "Test-AppLockerPolicy -User $User on $([Environment]::OSVersion.VersionString)" } else { 'not run (no AppLocker module or no -User)' })")
$lines.Add('')

# Microsoft recommended block list
$bl = Get-MsRecommendedBlockList
$cov = @(Get-BlockListCoverage -PolicyPath $Policy -FileName $bl.files)
$msDirs = @('C:\Windows\System32', 'C:\Windows\SysWOW64', 'C:\Windows\Microsoft.NET\Framework\v4.0.30319',
    'C:\Windows\Microsoft.NET\Framework64\v4.0.30319', 'C:\Program Files\dotnet', 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64')
$lines.Add("## Microsoft recommended block list ($(@($cov | Where-Object Covered).Count)/$($cov.Count) denied by a rule)")
$lines.Add('')
$lines.Add("Source: $($bl.source) (ms.date $($bl.msDate), retrieved $($bl.retrieved))")
$lines.Add('')
$lines.Add('| File | Deny rule | Rule types | Found at | Test-AppLockerPolicy |')
$lines.Add('|---|---|---|---|---|')
foreach ($c in $cov) {
    $p = Find-Binary $c.FileName ($msDirs | ForEach-Object { Join-Path $_ $c.FileName })
    $lines.Add(('| {0} | {1} | {2} | {3} | {4} |' -f $c.FileName, $(if ($c.Covered) { 'yes' } else { '**no**' }), $c.RuleTypes, $p, (Get-Decision $p)))
}
$lines.Add('')

# LOLBAS
if ($LolbasJson) {
    $lol = Get-Content -LiteralPath $LolbasJson -Raw | ConvertFrom-Json
    $rows = foreach ($e in $lol) {
        $cat = if ($e.url -match '/lolbas/([^/]+)/') { $Matches[1] } else { '' }
        $paths = @($e.Full_Path | Where-Object { $_ } | ForEach-Object { $_.Path })
        $c = Get-BlockListCoverage -PolicyPath $Policy -FileName $e.Name
        $p = Find-Binary $e.Name $paths
        [pscustomobject]@{ Name = $e.Name; Category = $cat; Covered = $c.Covered; Path = $p; Decision = (Get-Decision $p) }
    }
    $present = @($rows | Where-Object Path)
    $lines.Add("## LOLBAS ($(@($rows | Where-Object Covered).Count)/$(@($rows).Count) entries named by a deny rule; $($present.Count) present on this machine)")
    $lines.Add('')
    if ($runtime) {
        $lines.Add('Decisions for entries present on this machine: ' +
            (($present | Group-Object Decision | Sort-Object Name | ForEach-Object { '{0} {1}' -f $_.Name, $_.Count }) -join ', '))
        $lines.Add('')
    }
    $lines.Add('| Entry | Category | Deny rule | Found at | Test-AppLockerPolicy |')
    $lines.Add('|---|---|---|---|---|')
    foreach ($r in ($rows | Sort-Object Category, Name)) {
        $lines.Add(('| {0} | {1} | {2} | {3} | {4} |' -f $r.Name, $r.Category, $(if ($r.Covered) { 'yes' } else { 'no' }), $r.Path, $r.Decision))
    }
}

[System.IO.File]::WriteAllLines($OutFile, $lines)
Write-Host "Wrote $OutFile"
