<#
.SYNOPSIS
    Automated capture-parity verification for Delray.

.DESCRIPTION
    Runs Delray and a raw reference capture counter (refcap) concurrently on the
    same Npcap device, generates high-rate TCP traffic (iperf3) or an SMB file
    copy, and compares three layers:

      1. Windows adapter counters  (ground truth, same source as Task Manager)
      2. refcap wire/IP bytes      (raw pcap read path + Npcap dropped stats)
      3. Delray in+out totals      (full parse/attribution pipeline)

    Each ratio isolates a different failure layer; see
    docs/research/capture-parity-verification.md for interpretation.

.EXAMPLE
    # Requires an iperf3 server reachable at 192.168.1.10 (iperf3 -s)
    .\scripts\verify-capture.ps1 -IperfServer 192.168.1.10 -DurationSec 30 -Bandwidth 400M

.EXAMPLE
    # Reproduce the SMB scenario: copy a large file from a LAN share
    .\scripts\verify-capture.ps1 -SmbCopySource \\nas\share\4k-movie.mkv -DurationSec 60

.EXAMPLE
    # Test whether a larger Npcap kernel buffer changes capture-side loss
    .\scripts\verify-capture.ps1 -IperfServer 192.168.1.10 -BufferSize 16777216 -Snaplen 65535
#>
[CmdletBinding()]
param(
    [string]$Interface,
    [string]$IperfServer,
    [string]$SmbCopySource,
    [string]$Bandwidth = '400M',
    [int]$DurationSec = 30,
    [int]$Parallel = 1,
    [string]$IperfPath,
    [string]$DelrayPath,
    [string]$RefcapPath,
    [int]$BufferSize = 2000000,
    [int]$Snaplen = 65535,
    [double]$TolerancePercent = 10,
    [double]$AdapterTolerancePercent = 15,
    [string]$OutputDir,
    [switch]$KeepProcesses,
    [switch]$StartLocalIperfServer,
    [switch]$ManualMode
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

if (-not $IperfServer -and -not $SmbCopySource -and -not $ManualMode) {
    throw 'Provide -IperfServer, -SmbCopySource, or -ManualMode.'
}
if ($IperfServer -and $SmbCopySource) {
    throw 'Provide only one of -IperfServer or -SmbCopySource.'
}
if ($StartLocalIperfServer -and -not $IperfServer) {
    throw '-StartLocalIperfServer requires -IperfServer (use 127.0.0.1 for a loopback smoke test).'
}
if ($ManualMode -and ($IperfServer -or $SmbCopySource -or $StartLocalIperfServer)) {
    throw '-ManualMode cannot be combined with -IperfServer/-SmbCopySource/-StartLocalIperfServer.'
}

if (-not $IperfPath) { $IperfPath = Join-Path $repoRoot 'temp\iperf-3.21-win64\iperf3.exe' }
if (-not $DelrayPath) { $DelrayPath = Join-Path $repoRoot 'target\release\delray.exe' }
if (-not $RefcapPath) { $RefcapPath = Join-Path $repoRoot 'target\release\refcap.exe' }
if (-not $OutputDir) { $OutputDir = Join-Path $repoRoot ("temp\verify-capture-" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }

foreach ($tool in @($IperfPath, $DelrayPath, $RefcapPath)) {
    if (-not (Test-Path -LiteralPath $tool)) {
        throw "Tool not found: $tool"
    }
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Convert-BandwidthBytesPerSec {
    param([string]$Value)
    $match = [regex]::Match($Value, '^(\d+(?:\.\d+)?)\s*([KMG]?)$')
    if (-not $match.Success) { throw "Cannot parse bandwidth: $Value" }
    $number = [double]$match.Groups[1].Value
    $factor = switch ($match.Groups[2].Value) {
        'K' { 1e3 }
        'M' { 1e6 }
        'G' { 1e9 }
        default { 1 }
    }
    [long][math]::Round($number * $factor / 8)
}

function Get-RefcapDevices {
    param([string]$Exe)
    $raw = & $Exe --list 2>$null
    $devices = @()
    foreach ($line in $raw) {
        $fields = $line -split "`t"
        if ($fields.Count -lt 3) { continue }
        $addresses = if ($fields.Count -gt 3) { $fields[3..($fields.Count - 1)] -join ',' } else { '' }
        $devices += [pscustomobject]@{
            Index       = [int]$fields[0]
            Name        = $fields[1]
            Description = $fields[2]
            Addresses   = $addresses
        }
    }
    $devices
}

function Select-RefcapDevice {
    param([array]$Devices, [string]$Selector, [string]$AdapterDescription)
    if ($Selector) {
        if ($Selector -match '^\d+$') {
            $device = $Devices | Where-Object Index -eq ([int]$Selector) | Select-Object -First 1
            if (-not $device) { throw "Interface number $Selector not found in refcap --list output." }
            return $device
        }
        $device = $Devices | Where-Object Name -eq $Selector | Select-Object -First 1
        if (-not $device) { throw "Interface name '$Selector' not found in refcap --list output." }
        return $device
    }
    if ($AdapterDescription) {
        $device = $Devices | Where-Object {
            $_.Description -and ($_.Description -like "*$AdapterDescription*" -or $AdapterDescription -like "*$($_.Description)*")
        } | Select-Object -First 1
        if ($device) { return $device }
    }
    $device = $Devices | Where-Object { $_.Description -notmatch 'Loopback' } | Select-Object -First 1
    if (-not $device) { throw 'No capture device available.' }
    $device
}

function Get-AdapterSnapshot {
    param([string]$AdapterName)
    $stats = Get-NetAdapterStatistics -Name $AdapterName -ErrorAction Stop
    [pscustomobject]@{
        ReceivedBytes = [uint64]$stats.ReceivedBytes
        SentBytes     = [uint64]$stats.SentBytes
    }
}

# ---- Device/adapter resolution -------------------------------------------------

$devices = Get-RefcapDevices -Exe $RefcapPath
if ($devices.Count -eq 0) { throw 'refcap --list returned no devices; is Npcap installed?' }

$adapterName = $null
$adapterDescription = $null
try {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric | Select-Object -First 1
    if ($route.InterfaceAlias) {
        $adapter = Get-NetAdapter -Name $route.InterfaceAlias -ErrorAction Stop
        $adapterName = $adapter.Name
        $adapterDescription = $adapter.Description
    }
} catch {
    Write-Warning "Could not resolve default-route adapter: $_"
}

$device = Select-RefcapDevice -Devices $devices -Selector $Interface -AdapterDescription $adapterDescription

# Try to map the chosen pcap device back to a Get-NetAdapter name for counters.
$counterAdapterName = $adapterName
if (-not $counterAdapterName -and $device.Description) {
    $adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Description -eq $device.Description } | Select-Object -First 1
    if ($adapter) { $counterAdapterName = $adapter.Name }
}
$adapterCountersAvailable = $false
$adapterBefore = $null
if ($counterAdapterName) {
    try {
        $adapterBefore = Get-AdapterSnapshot -AdapterName $counterAdapterName
        $adapterCountersAvailable = $true
    } catch {
        Write-Warning "Get-NetAdapterStatistics unavailable for '$counterAdapterName': $_"
    }
}

Write-Host "Device: $($device.Name)"
Write-Host "Description: $($device.Description)"
Write-Host "Adapter counters: $(if ($adapterCountersAvailable) { $counterAdapterName } else { 'unavailable' })"

# ---- Start reference capture and Delray ---------------------------------------

$refcapLog = Join-Path $OutputDir 'refcap.jsonl'
$refcapErr = Join-Path $OutputDir 'refcap.err.txt'
$delrayJson = Join-Path $OutputDir 'delray.json'
$delrayErr = Join-Path $OutputDir 'delray.err.txt'

$refcapSeconds = $DurationSec + 25
$refcapArgs = @(
    $device.Name,
    '--interval', '1',
    '--out', $refcapLog,
    '--seconds', "$refcapSeconds",
    '--snaplen', "$Snaplen",
    '--buffer-size', "$BufferSize"
)
$refcap = Start-Process -FilePath $RefcapPath -ArgumentList $refcapArgs `
    -WindowStyle Hidden -RedirectStandardError $refcapErr -PassThru

$delrayArgs = @($device.Name, '--format', 'json', '--output', $delrayJson, '--top-n', '5')
$delray = Start-Process -FilePath $DelrayPath -ArgumentList $delrayArgs `
    -WindowStyle Hidden -RedirectStandardError $delrayErr -PassThru

# Delray refreshes the JSON file every 5 s; wait for the first frame.
$delrayReady = $false
$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline) {
    if ((Test-Path -LiteralPath $delrayJson) -and (Get-Item -LiteralPath $delrayJson).Length -gt 0) {
        $delrayReady = $true
        break
    }
    Start-Sleep -Milliseconds 500
}
if (-not $delrayReady) {
    Stop-Process -Id $delray.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $refcap.Id -Force -ErrorAction SilentlyContinue
    throw 'Delray did not produce a JSON frame within 20 s.'
}

# ---- Generate traffic ----------------------------------------------------------

$iperfLogOut = Join-Path $OutputDir 'iperf.stdout.txt'
$iperfLogErr = Join-Path $OutputDir 'iperf.stderr.txt'
$expectedBytes = 0
$trafficLabel = ''

if ($IperfServer) {
    $localServer = $null
    if ($StartLocalIperfServer) {
        $localServer = Start-Process -FilePath $IperfPath -ArgumentList @('-s', '-p', '5201') `
            -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 1
    }
    $bwBytes = Convert-BandwidthBytesPerSec -Value $Bandwidth
    $expectedBytes = [long][math]::Round($bwBytes * $DurationSec)
    $trafficLabel = "iperf3 $Bandwidth x$Parallel to $IperfServer"
    $iperfArgs = @('-c', $IperfServer, '-t', "$DurationSec", '-b', $Bandwidth, '-P', "$Parallel", '-i', '1')
    Write-Host "Starting traffic: $trafficLabel"
    $iperf = Start-Process -FilePath $IperfPath -ArgumentList $iperfArgs `
        -WindowStyle Hidden -RedirectStandardOutput $iperfLogOut -RedirectStandardError $iperfLogErr -PassThru
    $iperf | Wait-Process -Timeout ($DurationSec + 60) -ErrorAction SilentlyContinue
    if (-not $iperf.HasExited) {
        Stop-Process -Id $iperf.Id -Force -ErrorAction SilentlyContinue
        Write-Warning 'iperf3 did not finish in time; killed.'
    }
    if ($iperf.ExitCode -ne 0) {
        Write-Warning "iperf3 exited with code $($iperf.ExitCode); check $iperfLogOut / $iperfLogErr"
        Write-Host '--- iperf3 stdout (tail) ---'
        Get-Content -LiteralPath $iperfLogOut -Tail 20 -ErrorAction SilentlyContinue
        Write-Host '--- iperf3 stderr (tail) ---'
        Get-Content -LiteralPath $iperfLogErr -Tail 20 -ErrorAction SilentlyContinue
    }
} elseif ($ManualMode) {
    $expectedBytes = 0
    $trafficLabel = 'manual traffic (video playback)'
    Write-Host ">>> Start the video player now. Capturing for ${DurationSec}s ..."
    Start-Sleep -Seconds $DurationSec
} else {
    $sourceBytes = (Get-Item -LiteralPath $SmbCopySource).Length
    $trafficLabel = "SMB copy of $SmbCopySource"
    $expectedBytes = [long]$sourceBytes
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $copies = 0
    while ($sw.Elapsed.TotalSeconds -lt $DurationSec -and $copies -lt 12) {
        Copy-Item -LiteralPath $SmbCopySource -Destination (Join-Path $OutputDir "smb-copy-$copies.bin") -Force
        $copies++
    }
    $expectedBytes = [long]($sourceBytes * $copies)
    Write-Host "Finished traffic: $trafficLabel ($copies copies)"
}

# ---- Collect results -----------------------------------------------------------

# Let Delray publish one more snapshot after traffic stops (5 s refresh + margin).
Start-Sleep -Seconds 8

$adapterAfter = $null
if ($adapterCountersAvailable) {
    try { $adapterAfter = Get-AdapterSnapshot -AdapterName $counterAdapterName } catch {
        Write-Warning "Adapter counters failed after run: $_"
        $adapterCountersAvailable = $false
    }
}

$delrayBytes = $null
if (Test-Path -LiteralPath $delrayJson) {
    $frame = Get-Content -Raw -LiteralPath $delrayJson | ConvertFrom-Json
    $delrayBytes = [uint64]$frame.totals.in_bytes + [uint64]$frame.totals.out_bytes
}

# Stop captures right after the Delray frame is read so all three layers cover
# the same measurement window (also correct for early traffic failures).
if (-not $KeepProcesses) {
    Stop-Process -Id $delray.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $refcap.Id -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "Keeping processes: delray pid $($delray.Id), refcap pid $($refcap.Id)"
}
if ($localServer) {
    Stop-Process -Id $localServer.Id -Force -ErrorAction SilentlyContinue
}

$refcapLines = @()
if (Test-Path -LiteralPath $refcapLog) {
    $refcapLines = Get-Content -LiteralPath $refcapLog | ForEach-Object { $_ | ConvertFrom-Json }
}

# ---- Compute ratios and verdicts -----------------------------------------------

function Sum-Field([array]$Lines, [string]$Field) {
    ($Lines | Measure-Object -Property $Field -Sum).Sum
}

$refcapWireBytes = [uint64](Sum-Field $refcapLines 'bytes_wire')
$refcapIpBytes = [uint64](Sum-Field $refcapLines 'bytes_ip')
$refcapPackets = [uint64](Sum-Field $refcapLines 'packets')
$refcapDropped = [uint64](Sum-Field $refcapLines 'dropped')
$refcapIfDropped = [uint64](Sum-Field $refcapLines 'if_dropped')
$refcapArp = [uint64](Sum-Field $refcapLines 'arp_packets')
$refcapOther = [uint64](Sum-Field $refcapLines 'other_packets')
$refcapInvalid = [uint64](Sum-Field $refcapLines 'ip_invalid_packets')

$adapterBytes = 0
if ($adapterCountersAvailable -and $adapterBefore -and $adapterAfter) {
    $adapterBytes = ($adapterAfter.ReceivedBytes + $adapterAfter.SentBytes) -
        ($adapterBefore.ReceivedBytes + $adapterBefore.SentBytes)
}

if ($ManualMode) {
    $minAdapterBytes = 20MB
} else {
    $minAdapterBytes = [long][math]::Max(10MB, [long]($expectedBytes * 0.1))
}
$trafficOk = $adapterCountersAvailable -and ($adapterBytes -ge $minAdapterBytes)

$captureRatio = if ($adapterBytes -gt 0) { [double]$refcapWireBytes / [double]$adapterBytes } else { 0 }
$captureOk = $adapterCountersAvailable -and $captureRatio -ge (1 - $AdapterTolerancePercent / 100)

$pipelineRatio = if ($refcapIpBytes -gt 0) { [double]$delrayBytes / [double]$refcapIpBytes } else { 0 }
$pipelineOk = ($null -ne $delrayBytes) -and ($refcapIpBytes -gt 0) -and
    $pipelineRatio -ge (1 - $TolerancePercent / 100)

$overallOk = $trafficOk -and $captureOk -and $pipelineOk

$report = [ordered]@{
    timestamp          = (Get-Date).ToString('o')
    device             = $device.Name
    device_description = $device.Description
    traffic            = $trafficLabel
    duration_sec       = $DurationSec
    adapter_counters   = if ($adapterCountersAvailable) { $counterAdapterName } else { $null }
    adapter_bytes      = $adapterBytes
    refcap             = [ordered]@{
        packets         = $refcapPackets
        bytes_wire      = $refcapWireBytes
        bytes_ip        = $refcapIpBytes
        dropped         = $refcapDropped
        if_dropped      = $refcapIfDropped
        arp_packets     = $refcapArp
        other_packets   = $refcapOther
        ip_invalid      = $refcapInvalid
    }
    delray_bytes       = $delrayBytes
    ratios             = [ordered]@{
        refcap_wire_over_adapter = [math]::Round($captureRatio, 4)
        delray_over_refcap_ip    = [math]::Round($pipelineRatio, 4)
    }
    verdicts           = [ordered]@{
        traffic_generated   = $trafficOk
        capture_ok          = $captureOk
        pipeline_ok         = $pipelineOk
        overall             = $overallOk
    }
}

$reportJson = Join-Path $OutputDir 'report.json'
$reportTxt = Join-Path $OutputDir 'report.txt'
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportJson -Encoding utf8

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("Capture parity verification report")
[void]$sb.AppendLine("================================")
[void]$sb.AppendLine("Device        : $($device.Name)")
[void]$sb.AppendLine("Description   : $($device.Description)")
[void]$sb.AppendLine("Traffic       : $trafficLabel")
[void]$sb.AppendLine("Duration      : ${DurationSec}s")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("Layer                  Bytes         Packets      Ratio")
[void]$sb.AppendLine("---------------------  ------------  -----------  -------")
[void]$sb.AppendLine(("Windows adapter       {0,14:N0}" -f $adapterBytes))
[void]$sb.AppendLine(("refcap wire           {0,14:N0}  {1,11:N0}  {2:P1}" -f $refcapWireBytes, $refcapPackets, $captureRatio))
[void]$sb.AppendLine(("refcap IP             {0,14:N0}" -f $refcapIpBytes))
[void]$sb.AppendLine(("Delray in+out         {0,14:N0}  {1,11}  {2:P1}" -f $delrayBytes, 'n/a', $pipelineRatio))
[void]$sb.AppendLine("")
[void]$sb.AppendLine("Npcap dropped      : $refcapDropped packets, if_dropped: $refcapIfDropped")
[void]$sb.AppendLine("Non-IP frames      : ARP $refcapArp, other $refcapOther, invalid IP $refcapInvalid")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("Traffic generated  : $trafficOk (adapter bytes >= $minAdapterBytes)")
[void]$sb.AppendLine("Capture layer OK   : $captureOk (refcap/adapter >= $((1 - $AdapterTolerancePercent / 100).ToString('P0')))")
[void]$sb.AppendLine("Pipeline layer OK  : $pipelineOk (delray/refcap-IP >= $((1 - $TolerancePercent / 100).ToString('P0')))")
[void]$sb.AppendLine("OVERALL            : $overallOk")
$sb.ToString() | Set-Content -LiteralPath $reportTxt -Encoding utf8

Write-Host ""
Get-Content -LiteralPath $reportTxt
Write-Host ""
Write-Host "Artifacts: $OutputDir"

if (-not $overallOk) {
    Write-Host "Verification FAILED. See report.txt for the failing layer."
    exit 1
}
Write-Host "Verification PASSED."
exit 0
