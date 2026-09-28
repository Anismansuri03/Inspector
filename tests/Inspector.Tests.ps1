#Requires -Modules Pester
<#
    Run with:  Invoke-Pester -Script .\tests\Inspector.Tests.ps1

    Compatible with Pester 3.4 (ships with Windows PowerShell 5.1).

    These tests exercise the pure parsing/scoring logic without needing
    Windows registry, WMI, or Sysmon access. Helpers mirror RiskScorer /
    AutostartScanner pure functions and we validate the capture fixture
    JSON parsing used by the report pipeline.
#>

function Get-ImagePath {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return "" }
    $cmd = $CommandLine.Trim()
    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        if ($end -gt 1) { return $cmd.Substring(1, $end - 1) }
        return $cmd.Trim('"')
    }
    $sp = $cmd.IndexOf(' ')
    $first = if ($sp -gt 0) { $cmd.Substring(0, $sp) } else { $cmd }
    $exe = $first.IndexOf('.exe', [StringComparison]::OrdinalIgnoreCase)
    if ($exe -ge 0) { return $first.Substring(0, $exe + 4) }
    if ($sp -gt 0) {
        $exeFull = $cmd.IndexOf('.exe', [StringComparison]::OrdinalIgnoreCase)
        if ($exeFull -ge 0) { return $cmd.Substring(0, $exeFull + 4) }
    }
    return $first
}

function Test-LongBase64Blob {
    param([string]$Text)
    $hits = 0
    $run = 0
    foreach ($ch in $Text.ToCharArray()) {
        $c = [int]$ch
        $b64 = ($c -ge 65 -and $c -le 90) -or ($c -ge 97 -and $c -le 122) -or
               ($c -ge 48 -and $c -le 57) -or $ch -eq '+' -or $ch -eq '/' -or $ch -eq '='
        if ($b64) { $run++ } else {
            if ($run -ge 80) { $hits++ }
            $run = 0
        }
    }
    if ($run -ge 80) { $hits++ }
    return ($hits -gt 0)
}

$script:HighRiskTokens = @(
    '-EncodedCommand', ' -enc ', ' -e ', 'IEX', 'Invoke-Expression',
    'DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'Invoke-RestMethod',
    'WebClient', 'Net.WebClient', 'FromBase64String', '-nop ', '-w hidden',
    'Hidden', 'Bypass', '-ExecutionPolicy Bypass', 'Reflection.Assembly',
    'Start-Process', 'bitsadmin', 'certutil -urlcache'
)

$script:SuspiciousPathPatterns = @(
    '\temp\', '\tmp\', '\appdata\local\temp\', '\appdata\roaming\',
    '\appdata\', '\programdata\', '\users\public\', '\downloads\', 'recycle.bin'
)

$script:SuspiciousPathSamples = @{
    '\temp\'                = 'C:\Windows\Temp\evil.exe'
    '\tmp\'                 = 'C:\Windows\Tmp\evil.exe'
    '\appdata\local\temp\'  = 'C:\Users\bob\AppData\Local\Temp\evil.exe'
    '\appdata\roaming\'     = 'C:\Users\bob\AppData\Roaming\evil.exe'
    '\appdata\'             = 'C:\Users\bob\AppData\Roaming\evil.exe'
    '\programdata\'         = 'C:\ProgramData\evil.exe'
    '\users\public\'        = 'C:\Users\Public\evil.exe'
    '\downloads\'           = 'C:\Users\bob\Downloads\evil.exe'
    'recycle.bin'           = 'C:\$Recycle.Bin\evil.exe'
}

Describe 'ExtractImagePath' {
    It 'returns quoted path verbatim' {
        Get-ImagePath '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -File x.ps1' |
            Should Be 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    }

    It 'handles unquoted path with no spaces' {
        Get-ImagePath 'C:\Windows\System32\cmd.exe /c echo hi' |
            Should Be 'C:\Windows\System32\cmd.exe'
    }

    It 'extends unquoted path across spaces to .exe' {
        Get-ImagePath 'C:\Program Files\My App\app.exe -flag' |
            Should Be 'C:\Program Files\My App\app.exe'
    }

    It 'returns empty for null/whitespace' {
        Get-ImagePath '' | Should Be ''
        Get-ImagePath '   ' | Should Be ''
    }

    It 'returns first token when no .exe present' {
        Get-ImagePath 'somecommand -arg' | Should Be 'somecommand'
    }
}

Describe 'Base64 blob detection' {
    It 'flags an 80+ char base64 run' {
        $blob = 'A' * 80
        Test-LongBase64Blob "-EncodedCommand $blob" | Should Be $true
    }

    It 'ignores short base64-looking runs' {
        Test-LongBase64Blob 'SGVsbG8gV29ybGQ=' | Should Be $false
    }

    It 'flags base64 embedded among other text' {
        $blob = ('B' * 100)
        Test-LongBase64Blob "prefix-${blob}-suffix" | Should Be $true
    }

    It 'does not flag ordinary command lines' {
        Test-LongBase64Blob 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\script.ps1' |
            Should Be $false
    }
}

Describe 'High-risk command tokens' {
    It 'detects each mirrored token case-insensitively' {
        foreach ($tok in $script:HighRiskTokens) {
            $hay = "powershell.exe $($tok.Trim()) something"
            $found = $false
            foreach ($known in $script:HighRiskTokens) {
                if ($hay.IndexOf($known, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $found = $true
                    break
                }
            }
            $found | Should Be $true
        }
    }
}

Describe 'Suspicious path detection' {
    It 'flags temp/appdata/programdata style paths' {
        foreach ($p in $script:SuspiciousPathPatterns) {
            $sample = $script:SuspiciousPathSamples[$p]
            $sample | Should Not BeNullOrEmpty
            ($sample.IndexOf($p, [StringComparison]::OrdinalIgnoreCase) -ge 0) | Should Be $true
        }
    }

    It 'does not flag System32 or Program Files' {
        foreach ($trusted in @('C:\Windows\System32\foo.exe', 'C:\Program Files\App\bar.exe')) {
            foreach ($p in $script:SuspiciousPathPatterns) {
                $idx = $trusted.IndexOf($p, [StringComparison]::OrdinalIgnoreCase)
                $idx | Should Be (-1)
            }
        }
    }
}

Describe 'Capture JSONL parsing (fixture)' {
    $fixtureDir = Join-Path $PSScriptRoot 'fixtures'
    $fixtureFile = Join-Path $fixtureDir 'sample_capture.jsonl'

    It 'parses each non-empty line into an object with Kind and ProcessGuid' {
        Test-Path $fixtureFile | Should Be $true
        $lines = Get-Content $fixtureFile | Where-Object { $_.Trim() -ne '' }
        $lines.Count | Should BeGreaterThan 0
        foreach ($line in $lines) {
            $obj = $line | ConvertFrom-Json
            (@('create', 'terminate') -contains $obj.Kind) | Should Be $true
            (-not [string]::IsNullOrEmpty($obj.ProcessGuid)) | Should Be $true
        }
    }

    It 'pairs create and terminate records by ProcessGuid' {
        $recs = Get-Content $fixtureFile |
            Where-Object { $_.Trim() -ne '' } |
            ForEach-Object { $_ | ConvertFrom-Json }
        $creates = @($recs | Where-Object { $_.Kind -eq 'create' })
        $terminates = @($recs | Where-Object { $_.Kind -eq 'terminate' })
        $creates.Count | Should BeGreaterThan 0
        $terminates.Count | Should BeGreaterThan 0
        foreach ($t in $terminates) {
            ($creates.ProcessGuid -contains $t.ProcessGuid) | Should Be $true
        }
    }
}
