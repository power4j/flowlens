$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot 'verify-capture.ps1'
$fakeFlowLens = [System.IO.Path]::GetTempFileName()
$fakeRefcap = [System.IO.Path]::GetTempFileName()
$missingIperf = Join-Path ([System.IO.Path]::GetTempPath()) 'flowlens-missing-iperf3.exe'
$missingRefcap = Join-Path ([System.IO.Path]::GetTempPath()) 'flowlens-missing-refcap.exe'
$outputDir = Join-Path ([System.IO.Path]::GetTempPath()) 'flowlens-verify-capture-preflight'

function Get-FailureMessage {
    param([scriptblock]$Command)

    try {
        & $Command
        throw 'Expected command to fail.'
    } catch {
        $_.Exception.Message
    }
}

function Import-ScriptFunction {
    param([string]$Path, [string]$Name)

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) {
        throw "Could not parse ${Path}: $($parseErrors[0].Message)"
    }

    $functionAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $Name
    }, $true)
    if (-not $functionAst) {
        throw "Function '$Name' not found in $Path."
    }

    Set-Item -Path "Function:script:$Name" -Value $functionAst.Body.GetScriptBlock()
}

function Assert-ThrowsLike {
    param([scriptblock]$Command, [string]$Pattern, [string]$Message)

    $actual = Get-FailureMessage -Command $Command
    if ($actual -eq 'Expected command to fail.') {
        throw $Message
    }
    if ($actual -notlike $Pattern) {
        throw "Unexpected error. Expected '$Pattern', actual '$actual'."
    }
}

try {
    Import-ScriptFunction -Path $scriptPath -Name 'Get-NpcapInterfaceGuid'
    Import-ScriptFunction -Path $scriptPath -Name 'Select-RefcapDevice'
    Import-ScriptFunction -Path $scriptPath -Name 'Select-WindowsAdapter'
    Import-ScriptFunction -Path $scriptPath -Name 'Get-FlowLensArguments'
    Import-ScriptFunction -Path $scriptPath -Name 'Get-LatestDiagnosticsSnapshot'

    $flowlensArgs = @(Get-FlowLensArguments `
        -DeviceName '\Device\NPF_{TEST}' `
        -OutputPath 'flowlens.json' `
        -DiagnosticsPath 'flowlens-diagnostics.jsonl')
    $expectedFlowLensArgs = @(
        '\Device\NPF_{TEST}',
        '--format', 'json',
        '--output', 'flowlens.json',
        '--top-n', '5',
        '--diagnostics',
        '--diagnostics-output', 'flowlens-diagnostics.jsonl'
    )
    if (($flowlensArgs -join "|") -ne ($expectedFlowLensArgs -join "|")) {
        throw "FlowLens verification arguments must enable diagnostics. Actual: $flowlensArgs"
    }

    $diagnosticsPath = Join-Path ([System.IO.Path]::GetTempPath()) 'flowlens-verify-diagnostics.jsonl'
    @(
        '{"kind":"snapshot","seq":1,"counters":{"capture_read_packets":10}}',
        '{"kind":"lookup_miss_sample","seq":1}',
        '{"kind":"snapshot","seq":2,"counters":{"capture_read_packets":20}}'
    ) | Set-Content -LiteralPath $diagnosticsPath -Encoding utf8
    $latestDiagnostics = Get-LatestDiagnosticsSnapshot -Path $diagnosticsPath
    if ($latestDiagnostics.seq -ne 2 -or $latestDiagnostics.counters.capture_read_packets -ne 20) {
        throw 'The latest FlowLens diagnostics snapshot should be selected.'
    }
    Remove-Item -LiteralPath $diagnosticsPath -Force

    $virtioGuid = '8A8121CE-B85E-4602-BB53-05412604BE26'
    $devices = @(
        [pscustomobject]@{
            Index = 1
            Name = '\Device\NPF_{A3DD7255-AF83-44BC-8844-A22C5C16C1F2}'
            Description = 'WAN Miniport (Network Monitor)'
            Addresses = ''
        },
        [pscustomobject]@{
            Index = 2
            Name = "\Device\NPF_{$virtioGuid}"
            Description = 'Red Hat VirtIO Ethernet Adapter'
            Addresses = '10.11.12.31'
        }
    )

    Assert-ThrowsLike `
        -Command { Select-RefcapDevice -Devices $devices -Selector '' -AdapterGuid '' } `
        -Pattern '*Cannot safely select an Npcap device*' `
        -Message 'Missing adapter GUID must not fall back to an unrelated Npcap device.'

    Assert-ThrowsLike `
        -Command { Select-RefcapDevice -Devices $devices -Selector '' -AdapterGuid '11111111-1111-1111-1111-111111111111' } `
        -Pattern '*No Npcap device matches Windows adapter GUID*' `
        -Message 'An unmatched adapter GUID must not fall back to an unrelated Npcap device.'

    $automaticDevice = Select-RefcapDevice `
        -Devices $devices `
        -Selector '' `
        -AdapterGuid "{$($virtioGuid.ToLowerInvariant())}"
    if ($automaticDevice.Description -ne 'Red Hat VirtIO Ethernet Adapter') {
        throw 'Automatic selection must use the default Windows adapter GUID, not Npcap list order.'
    }

    $explicitDevice = Select-RefcapDevice `
        -Devices $devices `
        -Selector "\Device\NPF_{$virtioGuid}" `
        -AdapterGuid ''
    if ($explicitDevice.Description -ne 'Red Hat VirtIO Ethernet Adapter') {
        throw 'Explicit Npcap GUID should select the Red Hat VirtIO adapter.'
    }

    $windowsAdapters = @(
        [pscustomobject]@{
            Name = '以太网'
            InterfaceGuid = [guid]$virtioGuid
            InterfaceDescription = 'Localized VirtIO description'
        },
        [pscustomobject]@{
            Name = 'WAN'
            InterfaceGuid = [guid]'A3DD7255-AF83-44BC-8844-A22C5C16C1F2'
            InterfaceDescription = 'WAN Miniport (Network Monitor)'
        }
    )
    $virtioAdapter = Select-WindowsAdapter `
        -Adapters $windowsAdapters `
        -DeviceName $explicitDevice.Name
    if ($virtioAdapter.Name -ne '以太网') {
        throw 'The selected Npcap device must map back to the Windows adapter with the same GUID.'
    }

    $wanAdapter = Select-WindowsAdapter `
        -Adapters $windowsAdapters `
        -DeviceName $devices[0].Name
    if ($wanAdapter.Name -ne 'WAN') {
        throw 'An explicitly selected WAN Npcap device must not retain the default Ethernet counters.'
    }

    if ($null -ne (Get-NpcapInterfaceGuid -DeviceName '\Device\NPF_Loopback')) {
        throw 'Loopback must not be treated as a physical adapter GUID.'
    }

    Assert-ThrowsLike `
        -Command {
            Select-WindowsAdapter `
                -Adapters $windowsAdapters `
                -DeviceName '\Device\NPF_Loopback'
        } `
        -Pattern '*Cannot extract an interface GUID*' `
        -Message 'Loopback must not be mapped to unrelated Windows adapter counters.'

    Assert-ThrowsLike `
        -Command {
            Select-WindowsAdapter `
                -Adapters $windowsAdapters `
                -DeviceName '\Device\NPF_{11111111-1111-1111-1111-111111111111}'
        } `
        -Pattern '*No Windows adapter matches Npcap device GUID*' `
        -Message 'An unmatched Npcap device must not retain counters from an unrelated Windows adapter.'

    $manualMessage = Get-FailureMessage {
        & $scriptPath `
            -ManualMode `
            -DurationSec 0 `
            -IperfPath $missingIperf `
            -FlowLensPath $fakeFlowLens `
            -RefcapPath $missingRefcap `
            -OutputDir $outputDir
    }
    if ($manualMessage -ne "Tool not found: $missingRefcap") {
        throw "ManualMode should ignore a missing iperf3 executable. Actual error: $manualMessage"
    }

    $iperfMessage = Get-FailureMessage {
        & $scriptPath `
            -IperfServer '127.0.0.1' `
            -DurationSec 0 `
            -IperfPath $missingIperf `
            -FlowLensPath $fakeFlowLens `
            -RefcapPath $fakeRefcap `
            -OutputDir $outputDir
    }
    if ($iperfMessage -ne "Tool not found: $missingIperf") {
        throw "Iperf mode should require the iperf3 executable. Actual error: $iperfMessage"
    }

    Write-Host 'verify-capture tests passed.'
} finally {
    Remove-Item -LiteralPath $fakeFlowLens -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fakeRefcap -Force -ErrorAction SilentlyContinue
}
