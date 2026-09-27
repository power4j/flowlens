#Requires -Version 7.6
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [ValidateSet('smoke','windows','acceptance')][string]$Profile = 'smoke',
    [int[]]$Seconds = @(),
    [int]$FixedRate = 100,
    [int]$GrowthRate = 200,
    [int]$ReuseRate = 100,
    [int]$SnapshotTopN = 10,
    [int]$SnapshotWindow = 0,
    [switch]$AuditSnapshots,
    [string]$Toolchain = '1.96.0'
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dest = [IO.Path]::GetFullPath($OutputDirectory, (Get-Location).ProviderPath)
if (Test-Path -LiteralPath $dest) { throw "Output directory already exists: $dest" }
New-Item -ItemType Directory -Path $dest | Out-Null
$buildStderr = Join-Path $dest 'build.stderr.txt'
Push-Location -LiteralPath $repo
try {
    $buildMessages = @(& cargo "+$Toolchain" build --locked --release --example tls_runtime_eval --features tls-eval-observe --message-format=json 2> $buildStderr)
    if ($LASTEXITCODE -ne 0) { throw "Runtime example build failed; see $buildStderr" }
} finally {
    Pop-Location
}
$artifact = $buildMessages | ForEach-Object {
    try { $_ | ConvertFrom-Json } catch { $null }
} | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'tls_runtime_eval' -and $_.executable } | Select-Object -Last 1
if (-not $artifact) { throw 'Cargo did not report a tls_runtime_eval executable' }
$exe = [IO.Path]::GetFullPath($artifact.executable)
$si = [Diagnostics.ProcessStartInfo]::new($exe)
$si.UseShellExecute = $false
$si.CreateNoWindow = $true
$si.RedirectStandardOutput = $true
$si.RedirectStandardError = $true
$si.WorkingDirectory = $repo
foreach ($arg in @('--output',$dest,'--profile',$Profile,'--fixed-rate',"$FixedRate",'--growth-rate',"$GrowthRate",'--reuse-rate',"$ReuseRate",'--snapshot-top-n',"$SnapshotTopN",'--snapshot-window',"$SnapshotWindow")) {
    $si.ArgumentList.Add($arg)
}
if ($Seconds.Count -gt 0) { $si.ArgumentList.Add('--seconds'); $si.ArgumentList.Add($Seconds -join ',') }
if ($AuditSnapshots) { $si.ArgumentList.Add('--audit-snapshots') }
$exeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$p = [Diagnostics.Process]::Start($si)
$stdout = $p.StandardOutput.ReadToEndAsync()
$stderr = $p.StandardError.ReadToEndAsync()
$start = [Diagnostics.Stopwatch]::StartNew()
$samples = [IO.StreamWriter]::new((Join-Path $dest 'process-samples.jsonl'), $false, [Text.UTF8Encoding]::new($false))
try {
    while (-not $p.HasExited) {
        $p.Refresh()
        if (-not $p.HasExited) {
            @{ elapsed=$start.Elapsed.TotalSeconds; utc=[DateTime]::UtcNow.ToString('o'); pid=$p.Id;
               working_set=$p.WorkingSet64; private_bytes=$p.PrivateMemorySize64;
               peak_working_set=$p.PeakWorkingSet64; cpu_seconds=$p.TotalProcessorTime.TotalSeconds
            } | ConvertTo-Json -Compress | ForEach-Object { $samples.WriteLine($_) }
            $samples.Flush()
        }
        Start-Sleep -Milliseconds 1000
    }
    $p.WaitForExit()
    $stdout.Result | Set-Content -Encoding utf8 (Join-Path $dest 'stdout.txt')
    $stderr.Result | Set-Content -Encoding utf8 (Join-Path $dest 'stderr.txt')
    @{ exit=$p.ExitCode; elapsed=$start.Elapsed.TotalSeconds; executable=$exe; sha256=$exeHash;
       profile=$Profile; seconds=$Seconds; snapshot_top_n=$SnapshotTopN; snapshot_window=$SnapshotWindow;
       sample_interval_seconds=1; scope='Synthetic parser -> FlowTable -> direct Stats, no NIC/full pipeline';
       limits='1s samples can miss transient private-memory peaks; OS peak working set is also recorded. Full domain export after final cooldown checkpoint is outside measurement phases.'
    } | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $dest 'run.json')
    if ($p.ExitCode -ne 0) { throw "Runtime example failed with exit $($p.ExitCode)" }
} finally { $samples.Dispose(); $p.Dispose() }
