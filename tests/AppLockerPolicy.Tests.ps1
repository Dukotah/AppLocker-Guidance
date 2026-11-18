#Requires -Version 5.1
# Pester 5 tests for the starter policies.
#
#   Invoke-Pester ./tests                     static checks run anywhere (Windows PowerShell 5.1 or PowerShell 7)
#   $env:APPLOCKER_TEST_USER = 'someuser'     plus Test-AppLockerPolicy decisions, which need the AppLocker
#                                             module (Windows Pro/Enterprise/Server); CI runs them on windows-latest
#
# Nothing here applies a policy: Test-AppLockerPolicy -XmlPolicy evaluates the XML file offline.

BeforeDiscovery {
    $repo = Split-Path -Parent $PSScriptRoot
    $policyFiles = @(Get-ChildItem -LiteralPath (Join-Path $repo 'AppLocker Starter Policy') -Filter *.xml |
            ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
    $haveAppLocker = [bool](Get-Command Test-AppLockerPolicy -ErrorAction SilentlyContinue)
    $testUser = $env:APPLOCKER_TEST_USER
}

BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $PSScriptRoot 'AppLockerPolicy.psm1') -Force
    $blockList = (Get-MsRecommendedBlockList).files
    $win11 = Join-Path $repo 'AppLocker Starter Policy\Windows11_AppLocker Starter Policy.xml'

    # Microsoft recommended block list entries that the Windows 11 starter policy has no deny rule for.
    # Keep this in sync with the policy: the coverage test fails if a gap is closed or a new one appears.
    $knownWin11Gaps = @(
        'dbghost.exe', 'dbgsvc.exe', 'dbgsrv.exe', 'dnx.exe', 'dotnet.exe', 'kd.exe', 'lxrun.exe',
        'ntkd.exe', 'ntsd.exe', 'powershellcustomhost.exe', 'rcsi.exe', 'webclnt.dll'
    )

    function Find-BlockListBinary([string]$Name) {
        $dirs = @(
            "$env:windir\System32", "$env:windir\SysWOW64",
            "$env:windir\Microsoft.NET\Framework\v4.0.30319", "$env:windir\Microsoft.NET\Framework64\v4.0.30319",
            "$env:ProgramFiles\dotnet",
            "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64"
        )
        foreach ($d in $dirs) {
            $p = Join-Path $d $Name
            if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
        }
        return $null
    }
}

Describe 'Policy file <Name>' -ForEach $policyFiles {
    BeforeAll {
        $doc = Read-AppLockerPolicyXml -Path $Path
        $rules = @(Get-AppLockerRule -Path $Path)
    }

    It 'is an AppLocker policy, version 1' {
        $doc.DocumentElement.LocalName | Should -Be 'AppLockerPolicy'
        $doc.AppLockerPolicy.Version | Should -Be '1'
    }

    It 'has all five rule collections, each in AuditOnly' {
        $c = @($doc.AppLockerPolicy.RuleCollection)
        ($c.Type | Sort-Object) -join ',' | Should -Be 'Appx,Dll,Exe,Msi,Script'
        $c | ForEach-Object { $_.EnforcementMode | Should -Be 'AuditOnly' -Because "$($_.Type) collection" }
    }

    It 'uses unique GUID rule ids' {
        $rules.Count | Should -BeGreaterThan 0
        @($rules.Id | Select-Object -Unique).Count | Should -Be $rules.Count
        $rules | ForEach-Object { $_.Id | Should -Match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' }
    }

    It 'uses only Allow/Deny actions and well-formed SIDs' {
        $rules | ForEach-Object {
            $_.Action | Should -BeIn @('Allow', 'Deny')
            $_.Sid | Should -Match '^S-1-\d+(-\d+)+$'
        }
    }

    It 'has the expected number of Administrators-only deny rules' {
        # Deny rules scoped to BUILTIN\Administrators are deliberate (browser/mail on admin accounts);
        # this pins their number so a SID typo shows up in review.
        @($rules | Where-Object { $_.Action -eq 'Deny' -and $_.Sid -eq 'S-1-5-32-544' }).Count | Should -Be 7
    }

    It 'is accepted by Test-AppLockerPolicy' -Skip:(-not $haveAppLocker) {
        $r = Test-AppLockerPolicy -XmlPolicy $Path -Path "$env:windir\System32\notepad.exe" -User Everyone
        $r.PolicyDecision | Should -Not -BeNullOrEmpty
    }
}

Describe 'Microsoft recommended block list coverage (Windows 11 policy)' {
    It 'denies every entry except the known gaps' {
        $cov = @(Get-BlockListCoverage -PolicyPath $win11 -FileName $blockList)
        $gaps = @($cov | Where-Object { -not $_.Covered } | ForEach-Object { $_.FileName.ToLowerInvariant() } | Sort-Object)
        $gaps -join ',' | Should -Be (($knownWin11Gaps | Sort-Object) -join ',')
    }
}

Describe 'Test-AppLockerPolicy decisions for a standard user (Windows 11 policy)' -Skip:(-not ($haveAppLocker -and $testUser)) {
    BeforeAll {
        $user = $env:APPLOCKER_TEST_USER
        function Get-Decision([string]$File) {
            (Test-AppLockerPolicy -XmlPolicy $win11 -Path $File -User $user).PolicyDecision.ToString()
        }
    }

    It 'allows a Windows binary' {
        Get-Decision "$env:windir\System32\notepad.exe" | Should -Be 'Allowed'
    }

    It 'blocks by default an executable copied to a user-writable folder' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) 'applocker-test'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Copy-Item "$env:windir\System32\notepad.exe" $dir -Force
        Get-Decision (Join-Path $dir 'notepad.exe') | Should -Be 'DeniedByDefault'
    }

    It 'denies mshta.exe from System32' {
        Get-Decision "$env:windir\System32\mshta.exe" | Should -Be 'Denied'
    }

    It 'gives the expected decision for every block list binary present on this machine' {
        $results = foreach ($name in $blockList) {
            $p = Find-BlockListBinary $name
            if (-not $p) { continue }
            $expected = if ($knownWin11Gaps -contains $name.ToLowerInvariant()) { 'not Denied' } else { 'Denied' }
            [pscustomobject]@{ Name = $name; Path = $p; Decision = (Get-Decision $p); Expected = $expected }
        }
        $results | Format-Table -AutoSize | Out-String -Width 300 | Write-Host
        @($results).Count | Should -BeGreaterThan 0
        $wrong = @($results | Where-Object {
                ($_.Expected -eq 'Denied' -and $_.Decision -ne 'Denied') -or
                ($_.Expected -eq 'not Denied' -and $_.Decision -eq 'Denied') })
        ($wrong | ForEach-Object { '{0}: {1}, expected {2}' -f $_.Path, $_.Decision, $_.Expected }) -join '; ' | Should -BeNullOrEmpty
    }
}
