#Requires -Version 5.1
<#
.SYNOPSIS
Converts the deny rules of an AppLocker policy into an App Control for Business (WDAC)
deny-list policy in audit mode.

.DESCRIPTION
App Control has no per-user rules and no path-based allow model like AppLocker, so this
does not try to reproduce the whole AppLocker policy. It follows the shape of Microsoft's
recommended user-mode block rules: allow everything (FileName="*"), then deny by original
file name. What is converted, and what is skipped:

  converted  Deny FilePublisherRule with a specific BinaryName that reaches standard users
             (Everyone, BUILTIN\Users, Authenticated Users) -> <Deny FileName=... /> with the
             rule's BinaryVersionRange.
  skipped    Deny FilePublisherRule for BUILTIN\Administrators only (App Control has no
             per-user scope), Deny FilePathRule, Deny FileHashRule, all Allow rules.

The App Control FileName attribute matches the file's OriginalFileName, the same version
resource field AppLocker's BinaryName uses. An App Control FileName deny is broader than the
AppLocker publisher rule: it does not check the signer or product name.

The output is XML only. Compile it with ConvertFrom-CIPolicy (ConfigCI module, Windows
Pro/Enterprise/Server) before deploying. This script never deploys anything.

.EXAMPLE
.\tools\ConvertTo-AppControlPolicy.ps1 -AppLockerPolicy '.\AppLocker Starter Policy\Windows11_AppLocker Starter Policy.xml' -OutFile .\out\Win11-AppControl-Audit.xml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AppLockerPolicy,
    [Parameter(Mandatory)][string]$OutFile,
    [string]$PolicyName = 'AppLocker-Guidance deny rules (converted)'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\tests\AppLockerPolicy.psm1') -Force

$standardUserSids = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11')
$doc = Read-AppLockerPolicyXml -Path $AppLockerPolicy

function ConvertTo-WdacVersion([string]$v, [string]$fallback) {
    if ([string]::IsNullOrEmpty($v) -or $v -eq '*') { return $fallback }
    return $v
}

$denies = [ordered]@{}   # key: lower-case file name; one App Control rule per name
$skipped = New-Object System.Collections.Generic.List[object]

foreach ($collection in $doc.AppLockerPolicy.RuleCollection) {
    foreach ($rule in @($collection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.Action -eq 'Deny' })) {
        $reason = $null
        if ($rule.LocalName -ne 'FilePublisherRule') {
            $reason = "$($rule.LocalName) not converted"
        } elseif ($standardUserSids -notcontains $rule.UserOrGroupSid) {
            $reason = "scoped to $($rule.UserOrGroupSid); App Control has no per-user rules"
        }
        $cond = $null
        if (-not $reason) {
            $cond = $rule.Conditions.FilePublisherCondition
            if ($cond.BinaryName -eq '*') { $reason = 'publisher-wide rule (BinaryName="*")' }
        }
        if ($reason) {
            $skipped.Add([pscustomobject]@{ Collection = $collection.Type; Type = $rule.LocalName; Name = $rule.Name; Reason = $reason })
            continue
        }
        $key = $cond.BinaryName.ToLowerInvariant()
        $min = ConvertTo-WdacVersion $cond.BinaryVersionRange.LowSection '0.0.0.0'
        $max = ConvertTo-WdacVersion $cond.BinaryVersionRange.HighSection '65535.65535.65535.65535'
        if ($denies.Contains($key)) {
            # Same binary in two collections or rules: keep the widest range.
            $e = $denies[$key]
            if ([version]$min -lt [version]$e.Min) { $e.Min = $min }
            if ([version]$max -gt [version]$e.Max) { $e.Max = $max }
            continue
        }
        $denies[$key] = [pscustomobject]@{ FileName = $cond.BinaryName; Min = $min; Max = $max; Source = $rule.Name }
    }
}

$ns = 'urn:schemas-microsoft-com:sipolicy'
$sb = New-Object System.Text.StringBuilder
$w = [System.Xml.XmlWriter]::Create($sb, (New-Object System.Xml.XmlWriterSettings -Property @{ Indent = $true; OmitXmlDeclaration = $false }))
$w.WriteStartDocument()
$w.WriteStartElement('SiPolicy', $ns)
$w.WriteElementString('VersionEx', $ns, '10.0.0.0')
$w.WriteElementString('PolicyTypeID', $ns, '{A244370E-44C9-4C06-B551-F6016E563076}')
$w.WriteElementString('PlatformID', $ns, '{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}')
$w.WriteStartElement('Rules', $ns)
foreach ($opt in 'Enabled:Unsigned System Integrity Policy', 'Enabled:Audit Mode', 'Enabled:Advanced Boot Options Menu', 'Enabled:UMCI') {
    $w.WriteStartElement('Rule', $ns); $w.WriteElementString('Option', $ns, $opt); $w.WriteEndElement()
}
$w.WriteEndElement()
$w.WriteStartElement('EKUs', $ns); $w.WriteEndElement()
$w.WriteStartElement('FileRules', $ns)
$w.WriteStartElement('Allow', $ns)
$w.WriteAttributeString('ID', 'ID_ALLOW_A_1'); $w.WriteAttributeString('FriendlyName', 'Allow Kernel Drivers'); $w.WriteAttributeString('FileName', '*')
$w.WriteEndElement()
$w.WriteStartElement('Allow', $ns)
$w.WriteAttributeString('ID', 'ID_ALLOW_A_2'); $w.WriteAttributeString('FriendlyName', 'Allow User mode components'); $w.WriteAttributeString('FileName', '*')
$w.WriteEndElement()
$i = 0
$ids = @()
foreach ($d in $denies.Values) {
    $i++
    $id = 'ID_DENY_D_{0}' -f $i
    $ids += $id
    $w.WriteStartElement('Deny', $ns)
    $w.WriteAttributeString('ID', $id)
    $w.WriteAttributeString('FriendlyName', $d.Source)
    $w.WriteAttributeString('FileName', $d.FileName)
    $w.WriteAttributeString('MinimumFileVersion', $d.Min)
    $w.WriteAttributeString('MaximumFileVersion', $d.Max)
    $w.WriteEndElement()
}
$w.WriteEndElement() # FileRules
$w.WriteStartElement('Signers', $ns); $w.WriteEndElement()
$w.WriteStartElement('SigningScenarios', $ns)
foreach ($s in @(@{ Value = '131'; ID = 'ID_SIGNINGSCENARIO_DRIVERS_1'; Name = 'Driver Signing Scenarios'; Refs = @('ID_ALLOW_A_1') },
                 @{ Value = '12'; ID = 'ID_SIGNINGSCENARIO_WINDOWS'; Name = 'User Mode Signing Scenarios'; Refs = @('ID_ALLOW_A_2') + $ids })) {
    $w.WriteStartElement('SigningScenario', $ns)
    $w.WriteAttributeString('Value', $s.Value); $w.WriteAttributeString('ID', $s.ID); $w.WriteAttributeString('FriendlyName', $s.Name)
    $w.WriteStartElement('ProductSigners', $ns)
    $w.WriteStartElement('FileRulesRef', $ns)
    foreach ($r in $s.Refs) { $w.WriteStartElement('FileRuleRef', $ns); $w.WriteAttributeString('RuleID', $r); $w.WriteEndElement() }
    $w.WriteEndElement(); $w.WriteEndElement(); $w.WriteEndElement()
}
$w.WriteEndElement() # SigningScenarios
$w.WriteStartElement('UpdatePolicySigners', $ns); $w.WriteEndElement()
$w.WriteStartElement('CiSigners', $ns); $w.WriteEndElement()
$w.WriteElementString('HvciOptions', $ns, '0')
$w.WriteStartElement('Settings', $ns)
foreach ($kv in @(@('Name', $PolicyName), @('Id', '10.0.0.0'))) {
    $w.WriteStartElement('Setting', $ns)
    $w.WriteAttributeString('Provider', 'PolicyInfo'); $w.WriteAttributeString('Key', 'Information'); $w.WriteAttributeString('ValueName', $kv[0])
    $w.WriteStartElement('Value', $ns); $w.WriteElementString('String', $ns, $kv[1]); $w.WriteEndElement()
    $w.WriteEndElement()
}
$w.WriteEndElement() # Settings
$w.WriteEndElement() # SiPolicy
$w.WriteEndDocument()
$w.Flush()

$outDir = Split-Path -Parent $OutFile
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
# XmlWriter over a StringBuilder declares utf-16; write the bytes to match.
[System.IO.File]::WriteAllText($OutFile, $sb.ToString(), [System.Text.Encoding]::Unicode)

[pscustomobject]@{
    OutFile   = (Resolve-Path -LiteralPath $OutFile).Path
    Converted = $denies.Count
    Skipped   = $skipped.Count
    SkippedBy = ($skipped | Group-Object Reason | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join '; '
}
