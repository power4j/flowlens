#Requires -Version 7.6
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$Toolchain = '1.96.0',
    [ValidateRange(1, 3)][int]$Repeats = 3
)
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) {
    throw 'The stress oracle requires a 64-bit process (24-byte Segment reservation layout).'
}
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dest = [IO.Path]::GetFullPath($OutputDirectory, (Get-Location).ProviderPath)
if (Test-Path -LiteralPath $dest) { throw "Output directory already exists: $dest" }
New-Item -ItemType Directory -Path $dest | Out-Null

Add-Type -Path (Join-Path $PSScriptRoot 'tls-eval-stress.cs')
$corpus = Join-Path $dest 'corpus'
[TlsStatePressure]::Generate($corpus)
$suites = @(Get-Content -LiteralPath (Join-Path $corpus 'suites.json') -Raw | ConvertFrom-Json)
if ($suites.Count -ne 9) { throw "Expected nine stress suites, got $($suites.Count)" }

$buildStderr = Join-Path $dest 'build.stderr.txt'
Push-Location -LiteralPath $repo
try {
    $buildMessages = @(& cargo "+$Toolchain" build --locked --release --example tls_domain_eval --message-format=json 2> $buildStderr)
    if ($LASTEXITCODE -ne 0) { throw "Stress example build failed; see $buildStderr" }
} finally {
    Pop-Location
}
$artifact = $buildMessages | ForEach-Object {
    try { $_ | ConvertFrom-Json } catch { $null }
} | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'tls_domain_eval' -and $_.executable } | Select-Object -Last 1
if (-not $artifact) { throw 'Cargo did not report a tls_domain_eval executable' }
$exe = [IO.Path]::GetFullPath($artifact.executable)
$binaryHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash

$results = [Collections.Generic.List[object]]::new()
foreach ($suite in $suites) {
    for ($repeat = 1; $repeat -le $Repeats; $repeat++) {
        $run = Join-Path $dest ("runs/{0}/{1}" -f $suite.suite, $repeat)
        New-Item -ItemType Directory -Path $run | Out-Null
        $fixturePath = Join-Path $corpus ($suite.suite + '.pcap')
        $audit = Join-Path $run 'audit.jsonl'
        & $exe $fixturePath $audit 'state-audit' 1> (Join-Path $run 'stdout.txt') 2> (Join-Path $run 'stderr.txt')
        if ($LASTEXITCODE -ne 0) { throw "Candidate failed for $($suite.suite) repeat $repeat (exit $LASTEXITCODE)" }
        $comparison = [TlsStatePressure]::Compare($corpus, $suite.suite, $audit) | ConvertFrom-Json
        $comparison | Add-Member -NotePropertyName repeat -NotePropertyValue $repeat
        $results.Add($comparison)
        Write-Output "$($suite.suite) repeat $repeat : pass"
    }
}
@{
    binary_sha256 = $binaryHash
    compiler_toolchain = $Toolchain
    repeats = $Repeats
    suites = $suites.Count
    comparisons = $results
    generator_sha256 = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'tls-eval-stress.cs') -Algorithm SHA256).Hash
    adapter_sha256 = (Get-FileHash -LiteralPath (Join-Path $repo 'examples/tls_domain_eval.rs') -Algorithm SHA256).Hash
} | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $dest 'results.json') -Encoding utf8
