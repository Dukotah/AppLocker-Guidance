#Requires -Version 5.1
# Helpers for testing the starter policies as code. Works in Windows PowerShell 5.1
# and PowerShell 7. Nothing here applies or changes any AppLocker policy.

Set-StrictMode -Version Latest

# SIDs whose deny rules reach a standard (non-admin) user.
$script:StandardUserSids = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11')

function Read-AppLockerPolicyXml {
    param([Parameter(Mandatory)][string]$Path)
    # Get-Content honours the BOM, so the UTF-16LE Win11 file and the UTF-8 Win10 file both load.
    $doc = New-Object System.Xml.XmlDocument
    $doc.LoadXml((Get-Content -LiteralPath $Path -Raw))
    return $doc
}

function Get-AppLockerRule {
    <# Flattens a policy file into one object per rule. #>
    param([Parameter(Mandatory)][string]$Path)
    $doc = Read-AppLockerPolicyXml -Path $Path
    foreach ($collection in $doc.AppLockerPolicy.RuleCollection) {
        foreach ($rule in @($collection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })) {
            $names = @()
            $paths = @()
            $publisher = $null
            foreach ($cond in @($rule.Conditions.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })) {
                switch ($cond.LocalName) {
                    'FilePublisherCondition' {
                        $publisher = $cond.PublisherName
                        if ($cond.BinaryName -ne '*') { $names += $cond.BinaryName }
                    }
                    'FilePathCondition' {
                        $paths += $cond.Path
                        $leaf = ($cond.Path -split '\\')[-1]
                        if ($leaf -notmatch '[\*:]') { $names += $leaf }
                    }
                    'FileHashCondition' {
                        foreach ($h in @($cond.FileHash)) { $names += $h.SourceFileName }
                    }
                }
            }
            [pscustomobject]@{
                File          = Split-Path -Leaf $Path
                Collection    = $collection.Type
                Mode          = $collection.EnforcementMode
                Type          = $rule.LocalName
                Id            = $rule.Id
                Name          = $rule.Name
                Action        = $rule.Action
                Sid           = $rule.UserOrGroupSid
                Publisher     = $publisher
                Paths         = $paths
                FileNames     = @($names | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
            }
        }
    }
}

function Get-BlockListCoverage {
    <#
    For each binary name, reports the deny rules in the policy that name it (by publisher
    BinaryName, path leaf, or hash SourceFileName) and whether any of them reaches a
    standard user. Name matching is case-insensitive.
    #>
    param(
        [Parameter(Mandatory)][string]$PolicyPath,
        [Parameter(Mandatory)][string[]]$FileName
    )
    $deny = @(Get-AppLockerRule -Path $PolicyPath | Where-Object { $_.Action -eq 'Deny' })
    foreach ($name in $FileName) {
        $n = $name.ToLowerInvariant()
        $hits = @($deny | Where-Object { $_.FileNames -contains $n })
        $reach = @($hits | Where-Object { $script:StandardUserSids -contains $_.Sid })
        [pscustomobject]@{
            FileName  = $name
            Covered   = $reach.Count -gt 0
            RuleTypes = (@($hits | ForEach-Object { $_.Type } | Select-Object -Unique) -join ',')
            Sids      = (@($hits | ForEach-Object { $_.Sid } | Select-Object -Unique) -join ',')
        }
    }
}

function Get-MsRecommendedBlockList {
    param([string]$Path = (Join-Path $PSScriptRoot 'data/ms-recommended-block-rules.json'))
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

Export-ModuleMember -Function Read-AppLockerPolicyXml, Get-AppLockerRule, Get-BlockListCoverage, Get-MsRecommendedBlockList
