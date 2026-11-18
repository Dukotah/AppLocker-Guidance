# LANE 2 report: AppLocker-Guidance

## 1. Upstream contribution rules

- No CONTRIBUTING.md, no PR template, no CLA/DCO. LICENSE.md: US Government work (17 USC 105), CC0 1.0 worldwide.
  The sibling nsacyber repos' CONTRIBUTING.md says outside contributions are released under CC0; assume the same.
- Only two PRs ever merged, both outsider one-liners: #2 (README links, merged next day, 2019) and #5 (pwetzel,
  "Add missing attribute quotes", one commit, two-line diff, merged 2025-10-31 after ~102 days by iadgovuser49).
- Style to match (from #5): short imperative title, one-sentence body saying what was broken and what the change
  does, one commit, touch nothing else.
- The PowerShell scripts are UTF-16 **big-endian** with BOM and CRLF (git treats them as binary). Edits must keep
  that encoding byte-for-byte or the whole file shows as rewritten.

## 2. Branches

| Branch | Base | Bound for | Commits |
|---|---|---|---|
| `fix/events-csv-scripts` | upstream/master `773e006` | upstream PR | `7913074` Fix default lookback and leftover debug code in event scripts |
| `lane/policy-as-code` | `fix/events-csv-scripts` | fork only | tests, tools, CI workflow, this report |

### A: `fix/events-csv-scripts` (one commit, 4 files)

Textual diff (the files are UTF-16BE, so GitHub shows them as binary):
```
AppLocker Event Forwarding/AppLocker Events to CSV.ps1
-$daysToGet = 7500
+$daysToGet = 1
Create AppLocker Meta Events/AppLocker Meta Events to CSV.ps1
-$daysToGet = 7500
+$daysToGet = 1
Create AppLocker Meta Events/Create AppLocker Meta Event.ps1
-$filePath = $xd.Event.UserData.RuleAndFileData.FilePath
-"Filepath: ".$filePath  >> C:\temp\script.log
-  $callingProcess = "Unknnown"
+  $callingProcess = "Unknown"
-$log = Get-EventLog -LogName "AppLocker" -ErrorAction SilentlyContinue
+$log = Get-WinEvent -ListLog "AppLocker" -ErrorAction SilentlyContinue
rename: ...Meta Event Query Filter xml -> ...Meta Event Query Filter.xml
```
Why:
- Both "Events to CSV" headers say "By default, without any arguments specified, the script will retrieve one
  day's events", but the default was 7500 days. The two "grouped by File" siblings already use 1.
- The `C:\temp\script.log` line is leftover debugging. It writes an error on every trigger when `C:\temp` is
  missing, and `"Filepath: ".$filePath` is a property lookup on a string, not concatenation, so it never logged the
  path anyway. `$filePath` was only used by that line.
- "Unknnown" is written into every meta event that has no matching 4688 event.
- `Get-EventLog -LogName AppLocker` reads every entry of the meta log on each trigger just to see if the log exists,
  and returns nothing for a log that exists but is empty (so `New-EventLog` is retried and errors on the second
  run). `Get-WinEvent -ListLog` checks the log itself and works in 5.1 and 7.
- Deliberately NOT changed (behavioural, out of scope for a minimal PR): `New-EventLog`/`Write-EventLog` (still
  5.1-only; the shipped scheduled task runs `WindowsPowerShell\v1.0\powershell.exe`, so this works as deployed),
  meta events reusing ID 8020 (collides with the real AppLocker 8020 "packaged app allowed"), the unused
  `Import-Module AppLocker` in the CSV scripts, reading all of ForwardedEvents before filtering.

### B: `lane/policy-as-code` (fork only)

- `tests/AppLockerPolicy.psm1`: flattens a policy into rule objects (publisher BinaryName, path leaf, hash
  SourceFileName) and computes deny coverage for a list of file names (only rules for Everyone, Users or
  Authenticated Users count). 5.1 and 7.
- `tests/data/ms-recommended-block-rules.json`: the 43 names from Microsoft's recommended block list bullets
  (Learn page ms.date 2026-03-29, retrieved 2026-11-17; `webclnt.dll/davsvc.dll` split in two).
- `tests/AppLockerPolicy.Tests.ps1` (Pester 5):
  - static, anywhere: both policies parse, `Version=1`, five collections all `AuditOnly`, unique GUID ids,
    Allow/Deny only, well-formed SIDs, 7 Administrators-only deny rules;
  - coverage ratchet: the Windows 11 policy denies every block-list entry except a named list of 12 gaps; the test
    fails if a gap is closed or a new one appears;
  - with the AppLocker module and `APPLOCKER_TEST_USER` (CI only): `Test-AppLockerPolicy -XmlPolicy` accepts both
    files; for a real standard user, notepad.exe is `Allowed`, a copy of notepad.exe in %TEMP% is
    `DeniedByDefault`, mshta.exe is `Denied`, and every block-list binary present on the runner gets the expected
    decision (`Denied`/`DeniedByDefault` = blocked; known gaps must stay `Allowed`).
- `tools/Get-PolicyCoverageReport.ps1`: Markdown report of the MS list plus all LOLBAS entries (live
  `lolbas.json`), with static coverage and, when available, the `Test-AppLockerPolicy` decision for every binary
  present on the machine. CI writes the Windows 11 report to the job summary and uploads both.
- `tools/ConvertTo-AppControlPolicy.ps1`: AppLocker -> App Control for Business (WDAC) converter. Emits an audit-mode
  SiPolicy in the same shape as Microsoft's recommended user-mode block rules (allow `*`, then `<Deny FileName=...>`
  per publisher deny rule with its version range). Skips, with a reason count: hash rules, path rules,
  Administrators-only rules (no per-user scope in App Control), allow rules. CI compiles both outputs with
  `ConvertFrom-CIPolicy`. It never deploys anything.
- `.github/workflows/policy-tests.yml`: windows-latest; push, PR, manual and weekly (for new LOLBAS entries).
  Creates a throwaway local standard user on the runner only. Nothing is applied to any machine;
  `Test-AppLockerPolicy -XmlPolicy` evaluates offline.

## 3. Evidence

### Local (Windows 11 Home 26200, pwsh 7.7.0 and Windows PowerShell 5.1.26100; no AppLocker/ConfigCI modules)

Parse check, A branch: `[Parser]::ParseFile` -> 0 errors for all 3 changed scripts. Encoding round-trip was checked
byte-for-byte before editing (UTF-16BE + BOM + CRLF preserved; diffs above are the only changes).

PSScriptAnalyzer 1.25.0, default rules, before (upstream/master) vs after (branch A): identical counts
(19 / 20 / 9 findings: trailing whitespace, Write-Host, `$event` automatic variable, aliases). The default rules do
not see these bugs. With `PSUseCompatibleCommands` targeting PS 7.0 and 5.1 on Create AppLocker Meta Event.ps1:
```
before: L39 'Get-EventLog' not available by default in PowerShell 7.0.0
        L42 'New-EventLog' ...   L48 'Write-EventLog' ...
after:  L40 'New-EventLog' ...   L46 'Write-EventLog' ...      (Get-EventLog finding gone)
```

Fixed CSV scripts run read-only against this box's ForwardedEvents log (empty here), both shells:
```
> AppLocker Events to CSV.ps1   (pwsh 7 and powershell.exe 5.1)
The specified module 'AppLocker' was not loaded ...            (pre-existing import; module absent on Home)
Event Creation Time,Event Level,EventID,EventRecordID,Computer,Username,PolicyName,FilePath,FileHash,fqbn
No events were found that match the specified selection criteria.
No AppLocker events found in the requested time range.
> AppLocker Meta Events to CSV.ps1  -> same, with the "Calling Process" header
```
Changed check, both shells: `Get-WinEvent -ListLog AppLocker -EA SilentlyContinue` -> `$null` (log absent),
`Get-WinEvent -ListLog Application` -> log object. The meta-event script itself was NOT run end to end: it needs a
real AppLocker event and would create an event log/source (a system change), which this lane must not make.

Branch B static suite, local: `Invoke-Pester ./tests` -> `Passed: 11, Failed: 0, Skipped: 6` (the 6 need the
AppLocker module). Converter runs in 5.1 and 7 with byte-identical output.

### GitHub Actions, windows-latest (Microsoft Windows Server 2025, 10.0.26100, PS 5.1.26100.33648)

Runs on the fork: https://github.com/Dukotah/AppLocker-Guidance/actions (final green run linked in section 7).
```
AppLocker 2.0.0.0 C:\Windows\system32\WindowsPowerShell\v1.0\Modules\AppLocker\AppLocker.psd1
ConfigCI  1.0     C:\Windows\system32\WindowsPowerShell\v1.0\Modules\ConfigCI\ConfigCI.psd1
Pester (Windows PowerShell 5.1, with Test-AppLockerPolicy): Tests Passed: 17, Failed: 0, Skipped: 0
Pester (PowerShell 7, static checks):                       Tests Passed: 13, Failed: 0, Skipped: 4
PSScriptAnalyzer -Severity Error over the repo: none
```
`Test-AppLockerPolicy` decisions, Windows 11 policy, local standard user `altest`, block-list binaries present on
the runner:
```
addinprocess / addinprocess32 / addinutil / aspnet_compiler (.NET 4)  Denied
bash, cscript, infdefaultinstall, mshta, wscript, wsl (System32)    Denied
cdb, windbg (Windows Kits Debuggers)                                 Denied
Microsoft.Workflow.Compiler.exe                                      Denied
msbuild.exe (.NET 4)                                                 DeniedByDefault  (exception on the Windows-folder allow rule)
dbgsrv, kd, ntkd, ntsd (Windows Kits Debuggers), dotnet.exe          Allowed  (no rule: the 12 static gaps)
kill.exe (Debuggers), wslconfig.exe (System32)                       Allowed  (FileHashRule of one specific build)
Microsoft.Build.dll (.NET 4)                                         Allowed  (rule scoped to ProductName "MICROSOFT(R) BUILD TOOLS(R)")
```
The first CI run failed exactly on those last three; they are now named in `$knownRuntimeGaps` with reasons.

LOLBAS (246 entries, live JSON): Windows 11 policy names 96 in a deny rule; of 163 present on the runner,
`Allowed 50, Denied 79, DeniedByDefault 32` (2 are .cpl/.wsf, which AppLocker rejects as unsupported types).
Windows 10 policy: 105/246 named; `Allowed 61, Denied 100`.

Core Windows DLLs, Windows 11 policy (`Dll` collection deny rules for Everyone, `BinaryVersionRange * - *`):
```
altest       C:\Windows\System32\shell32.dll   Denied  SHELL32.DLL version 10.0.22000.527 exactly in ...
altest       ...setupapi.dll / zipfldr.dll / url.dll / ieframe.dll  Denied
runneradmin  shell32.dll / setupapi.dll / zipfldr.dll / url.dll / ieframe.dll                 Denied
```

App Control conversion + `ConvertFrom-CIPolicy` on the runner:
```
Windows10: Converted 107, Skipped 22 (FileHashRule x15; Administrators-only x7)  Get-CIPolicy: Allow=2 Deny=107  -> Windows10-AppControl-Audit.cip 12952 bytes
Windows11: Converted 99,  Skipped 59 (FilePathRule x34; FileHashRule x18; Administrators-only x7)  Get-CIPolicy: Allow=2 Deny=99  -> Windows11-AppControl-Audit.cip 12144 bytes
```
What this proves: the generated XML is accepted and compiled by ConfigCI. NOT proven: runtime App Control behaviour
(no policy was deployed anywhere; CI never calls `CiTool`/`Set-RuleOption` on a live system).

## 4. Competing work check

- `gh pr list -R nsacyber/AppLocker-Guidance --state all -L 50` at start and at finish: only #2 and #5 (both
  merged). No AI-PR spray accounts (theyottaboy, rudycelekli, arpitjain099, arthurianresolve, ravisastryk, r3vpwnx).
- Issues: #1 and #3 closed 2025-03; only #4 open (servers question, 0 comments). Nothing filed on the script bugs,
  the block-list gaps, the hash-rule fragility or the DLL rules.

## 5. Draft upstream text

### PR (branch `fix/events-csv-scripts`)

**Title:** Fix default lookback and leftover debug code in event scripts

**Body:**
```
The two "Events to CSV" scripts say they retrieve one day's events by default, but $daysToGet defaulted to 7500, so a run with no arguments returned the whole ForwardedEvents log. This sets it to 1, matching the comment and the "grouped by File" scripts.

Create AppLocker Meta Event.ps1 still had a debug line appending to C:\temp\script.log (it errors on every trigger when C:\temp does not exist), and the fallback calling process was spelled "Unknnown". The log check used Get-EventLog, which reads the whole AppLocker log on every trigger; Get-WinEvent -ListLog only checks that the log exists and works in Windows PowerShell 5.1 and PowerShell 7.

Also renames "AppLocker Event Forwarding Subscription Meta Event Query Filter xml" to end in ".xml".

The scripts are UTF-16 so GitHub shows them as binary; the full text diff is:

-$daysToGet = 7500                                   (both "Events to CSV" scripts)
+$daysToGet = 1
-$filePath = $xd.Event.UserData.RuleAndFileData.FilePath
-"Filepath: ".$filePath  >> C:\temp\script.log
-  $callingProcess = "Unknnown"
+  $callingProcess = "Unknown"
-$log = Get-EventLog -LogName "AppLocker" -ErrorAction SilentlyContinue
+$log = Get-WinEvent -ListLog "AppLocker" -ErrorAction SilentlyContinue

Encoding (UTF-16 BE, CRLF) is unchanged.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

### Issue: Windows 11 starter policy gaps against the Microsoft recommended block list

**Title:** Windows 11 starter policy: block-list binaries with no rule, and rules that don't match current builds

**Body:**
```
I checked the Windows 11 starter policy against the bulleted list on Microsoft's "Applications that can bypass App Control" page (ms.date 2026-03-29) and ran Test-AppLockerPolicy -XmlPolicy for a standard local user on Windows Server 2025 (10.0.26100).

1. No rule at all for 12 entries: dbghost.exe, dbgsvc.exe, dbgsrv.exe, dnx.exe, dotnet.exe, kd.exe, lxrun.exe, ntkd.exe, ntsd.exe, powershellcustomhost.exe, rcsi.exe, webclnt.dll. On the test machine kd, ntkd, ntsd and dbgsrv (Windows Kits\10\Debuggers\x64) and dotnet.exe (Program Files\dotnet) return Allowed through the Program Files allow rule, while cdb.exe and windbg.exe in the same folder are Denied. Some of these may be intentional (dotnet.exe), but the debugger ones look like an oversight next to cdb/windbg.

2. Rules that exist but don't match current files:
   - kill.exe and wslconfig.exe are denied only by FileHashRule, so any other build is Allowed (both were Allowed on 10.0.26100). A publisher rule on BinaryName, like the other entries, would survive updates.
   - The Microsoft.Build.dll and MSBuild.exe deny rules are scoped to ProductName "MICROSOFT® BUILD TOOLS®" (the Visual Studio copies). The .NET Framework copies in C:\Windows\Microsoft.NET\Framework*\v4.0.30319 have a different product name. MSBuild.exe is still blocked there because it's an exception on the Windows-folder allow rule, but Microsoft.Build.dll is Allowed.

3. Dll collection rules deny core Windows DLLs for Everyone, all versions: SHELL32.DLL, SETUPAPI.DLL, ZIPFLDR.DLL, URL.DLL, IEFRAME.DLL (plus ADVPACK, SHDOCVW, SHIMGVW, SYSSETUP, PCWUTL and others). The rule names say "version X exactly" but every BinaryVersionRange is * to *. Test-AppLockerPolicy returns Denied for these for both a standard user and an administrator. In AuditOnly this means an 8003 event for nearly every process that loads shell32; if someone switches the Dll collection to Enforce, Windows will not work. If the intent is to stop "rundll32 shell32.dll,ShellExec_RunDLL"-style abuse, these rules probably belong somewhere other than an all-versions Dll deny for Everyone.

Happy to send a PR for any of these if you say which direction you want.
```

### Answer the owner could post on issue #4 ("Can the Windows 10 xml be used for servers?")

```
AppLocker itself works on Windows Server (2008 R2 and later; the Application Identity service must be running), so the XML imports and evaluates there. But the starter policies here are written for workstations, and several rules will get in the way on a server:

- In the current Windows 11 policy, many deny rules target Everyone, which includes administrators, and AppLocker deny rules win over allow rules. That covers tools admins use on servers all the time: cscript.exe (slmgr.vbs and lots of vendor scripts), wmic.exe, schtasks.exe, netsh.exe, fsutil.exe, pnputil.exe, regsvr32.exe, certreq.exe, msbuild.exe.
- The Windows 11 policy also has Dll rules that deny shell32.dll, setupapi.dll and others for Everyone. That's harmless in AuditOnly but can't be enforced on any machine.
- The browser/mail "Prevent administrators from easily running ..." rules assume a workstation admin account.
- Packaged app (Appx) rules don't matter on Server Core.

So: use it as a starting point, keep every collection in AuditOnly, collect 8003/8006 events (the forwarding subscription and scripts in this repo do that), and remove or rescope (e.g. to BUILTIN\Users instead of Everyone) any deny rule your server roles need before you switch to Enforce. The current file in the repo is Windows11_AppLocker Starter Policy.xml; the Windows 10 file is older.
```

## 6. Land probability

- A (`fix/events-csv-scripts`): **Medium-High.** It's the same kind of small, obviously-correct fix this maintainer
  merged from an outsider in 2025, but expect a wait of about 3 months. The binary-looking UTF-16 diff is the main
  risk, which is why the PR body carries the text diff.
- Issue: Medium. The maintainer added these LOLBAS/MS denies in 2025 and is likely to care, especially about item 3.
- B is fork-only.

Owner next steps: review A and open the PR from `Dukotah:fix/events-csv-scripts`; post the #4 answer; file the
issue (decide first whether to include item 3, the most consequential one). Enable Issues on the fork if you want
people to report against the CI report there.

## 7. Final CI run

Last code change (`39ae89d`) green: https://github.com/Dukotah/AppLocker-Guidance/actions/runs/44247594858 (job `test`, 4m54s, artifact `policy-test-output` has both coverage reports, the generated App Control XML and .cip, and Pester NUnit XML). The commit that adds this report triggers one more run of the same workflow.
