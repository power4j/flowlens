#!/usr/bin/env bash
set -euo pipefail

binary=${1:-target/debug/flowlens}
interface=${2:-lo}
threshold=${FLOWLENS_TUI_LATENCY_THRESHOLD:-0.100}
cycles=${FLOWLENS_TUI_CYCLES:-100}
key_interval=${FLOWLENS_TUI_KEY_INTERVAL:-0.125}

if [[ ! $cycles =~ ^[1-9][0-9]*$ ]]; then
    printf 'FLOWLENS_TUI_CYCLES must be a positive integer\n' >&2
    exit 2
fi
timeout_seconds=$(perl -MPOSIX=ceil -e 'print ceil(10 + 4 * $ARGV[0] * $ARGV[1])' "$cycles" "$key_interval")

binary=$(realpath "$binary")
if [[ ! -x $binary ]]; then
    printf 'binary is not executable: %s\n' "$binary" >&2
    exit 2
fi

if [[ $interface == lo && ${FLOWLENS_TUI_NETNS:-0} != 1 ]]; then
    exec unshare -Urn env FLOWLENS_TUI_NETNS=1 "$0" "$binary" "$interface"
fi

if ! ip link show dev "$interface" > /dev/null 2>&1; then
    printf 'network interface not found: %s\n' "$interface" >&2
    exit 2
fi

tmpdir=$(mktemp -d)
ping_pid=
cleanup() {
    if [[ -n $ping_pid ]]; then
        kill "$ping_pid" 2>/dev/null || true
    fi
    if [[ ${FLOWLENS_KEEP_TUI_LOGS:-0} == 1 ]]; then
        printf 'TUI logs: %s\n' "$tmpdir" >&2
    else
        rm -rf "$tmpdir"
    fi
}
trap cleanup EXIT

if [[ $interface == lo ]]; then
    ip link set lo up
    ping -q -i 0.01 127.0.0.1 > /dev/null &
    ping_pid=$!
fi

printf -v script_command 'stty rows 24 cols 80 && exec %q %q' "$binary" "$interface"

{
    sleep 2
    for ((cycle = 0; cycle < cycles; cycle++)); do
        for key in 2 3 4 1; do
            printf '%s' "$key"
            sleep "$key_interval"
        done
    done
    printf q
} | timeout "${timeout_seconds}s" script \
    -q \
    -E never \
    -m advanced \
    -I "$tmpdir/input.log" \
    -O "$tmpdir/output.log" \
    -T "$tmpdir/timing.log" \
    -c "$script_command" \
    > /dev/null

perl - "$tmpdir/timing.log" "$tmpdir/output.log" "$threshold" "$cycles" <<'PERL'
use strict;
use warnings;

my ($timing_path, $output_path, $threshold, $cycles) = @ARGV;
open my $timing_fh, '<', $timing_path or die "open timing log: $!\n";
open my $output_fh, '<:raw', $output_path or die "open output log: $!\n";
my $output = do {
    local $/;
    <$output_fh>;
};
my $payload_start = index($output, "\e");
die "terminal output has no escape sequence\n" if $payload_start < 0;
my $payload_offset = $payload_start;

my @keys;
push @keys, qw(2 3 4 1) for 1 .. $cycles;
push @keys, 'q';
my %markers = (
    2 => 'Processes',
    3 => 'Inbound',
    4 => 'Analyzer',
    1 => 'Top',
);
my $key_index = 0;
my ($pending_key, $pending_at, $pending_output);
my $time = 0;
my @latencies;

while (my $line = <$timing_fh>) {
    next unless $line =~ /^([IO])\s+([0-9.]+)\s+(\d+)/;
    my ($stream, $delay, $size) = ($1, $2, $3);
    $time += $delay;

    if ($stream eq 'I') {
        my $key = $keys[$key_index++];
        die "received a new key before page $pending_key rendered\n"
            if defined $pending_key;
        next if !defined($key) || $key eq 'q';
        $pending_key = $key;
        $pending_at = $time;
        $pending_output = '';
        next;
    }

    my $chunk = substr($output, $payload_offset, $size);
    $payload_offset += $size;
    next unless defined $pending_key;
    $pending_output .= $chunk;
    my $plain_output = $pending_output;
    $plain_output =~ s/\e\[[0-?]*[ -\x2f]*[@-~]//g;
    next if index($plain_output, $markers{$pending_key}) < 0;

    my $latency = $time - $pending_at;
    push @latencies, [$pending_key, $latency];
    undef $pending_key;
    undef $pending_at;
    undef $pending_output;
}

die "page $pending_key never rendered\n" if defined $pending_key;
my $expected = 4 * $cycles;
die "expected $expected page transitions, got " . scalar(@latencies) . "\n"
    unless @latencies == $expected;

my $failed = 0;
my $max_latency = 0;
for my $sample (@latencies) {
    my ($key, $latency) = @$sample;
    $max_latency = $latency if $latency > $max_latency;
    printf "page %s: %.3f ms\n", $key, $latency * 1000 if $cycles == 1;
    $failed = 1 if $latency > $threshold;
}
printf "%d transitions, max: %.3f ms\n", scalar(@latencies), $max_latency * 1000
    if $cycles > 1;
die sprintf("TUI latency exceeded %.0f ms\n", $threshold * 1000) if $failed;
PERL
