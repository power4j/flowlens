# Bounded tiered IP traffic statistics

Status: accepted

IP traffic dimensions use one bounded state per direction, with a five-minute rolling window made of five 60-second buckets alongside lifetime bytes. The hard per-direction cap is 16,384 IP states; overflow is pruned in batches to a 16,128-state target to avoid repeated scans during bursts. Capacity is divided into minimum heavy-traffic, rising-traffic, and observation reservations; tier membership is re-evaluated every bucket with hysteresis, while `topN` remains a single lifetime-byte ranking. This preserves the existing display contract while preventing historical heavy peers from hiding newly rising peers, and keeps high-cardinality traffic bounded.

Tier selection and eviction use separate signals rather than one weighted score:

- Heavy tier: highest lifetime bytes, with a 70% minimum reservation.
- Rising tier: the union of relative rankings by recent-window bytes and surge bytes, with a 20% minimum reservation.
- Observation tier: new IPs for at least two buckets, with a 10% minimum reservation; eviction uses current-bucket bytes, then recent-window bytes, then `last_seen` only as a final tie-breaker.
- Tier changes require a two-bucket hold-down. Three idle windows remove heavy-tier protection, while retained lifetime bytes may remain until capacity pressure evicts the state.

## Consequences

- Global inbound and outbound byte totals remain exact.
- IP detail rankings remain lifetime-byte rankings and may omit rising peers unless a separate diagnostic view is added later.
- Recent-window state is bounded by the per-direction IP-state capacity; no per-bucket map is unbounded.
- Tier counts, promotions, demotions, and evictions are observable through `--diagnostics`.
