## Agent skills

### Issue tracker

Issues live as markdown files under `.scratch/<feature>/`. See `docs/agents/issue-tracker.md`.

## Linux release builds

Linux distribution binaries must use the glibc 2.28 baseline documented in
`README.md`. Use:

```bash
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.28
```

The release artifact is `target/x86_64-unknown-linux-gnu/release/flowlens`.
Plain `cargo build --release` is only for local development or same-host
testing, not for Linux distribution builds.

### Definition of done

Before handing off or committing any code change, run these checks after the
final source edit:

```bash
cargo fmt --all -- --check
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
```

All four commands must pass. If a check fails, fix the issue and rerun the
complete set before committing. Report the result of each command in the
handoff.

### Triage labels

Five default triage roles map to labels of the same name. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: root `CONTEXT.md` + `docs/adr/`. See `docs/agents/domain.md`.

## Subagent delegation

- Proactively use subagents when a task is clearly bounded, long-running,
  context-heavy, or benefits from an isolated fresh context.
- For a well-specified implementation ticket, prefer one isolated implementation
  subagent with a complete self-contained prompt. Do not ask the user to open a
  new chat manually.
- Use `fork_turns=none` when the purpose is to simulate a fresh session.
- The primary agent remains responsible for coordination, reviewing the final
  diff, rerunning verification, and reporting the result.
- Do not delegate trivial tasks, unresolved product decisions, or work that
  requires multiple agents to edit the same files concurrently.
- Use only one writing agent at a time. Read-only review agents may run in
  parallel after implementation is complete.
- Subagents must preserve the current branch, existing user changes, task scope,
  and repository instructions.

## Host sandbox failures

When required gh, build, test, or generator commands fail because the agent sandbox blocks credentials, network, IPC, file watching, or nested sandbox-exec, retry unchanged with the narrowest host escalation before diagnosing authentication or project failure. Require sandbox evidence; never bypass genuine test failures or the product sandbox under test.
