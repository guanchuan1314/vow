# Task: Implement Severity Config (Roadmap Item P)

**Repo:** /root/.openclaw/workspaces/warden/
**Nexus Card:** cmm51l5nz00fcp92alyf3d0zf

## Requirements:
1. Add `--min-severity <level>` CLI flag (values: low, medium, high, critical)
2. Add severity threshold support in `.vow/config.yaml` (e.g. `min_severity: medium`)
3. CLI flag overrides config file setting
4. When set, only findings at or above the threshold are reported
5. Default behavior (no flag/config): show all findings (backwards compatible)
6. Update help text and README

## Implementation Notes:
- Severity enum already exists in `src/lib.rs`
- Config file support exists (check existing `.vow/config.yaml` parsing)
- Filter findings AFTER analysis, BEFORE reporting
- Add Ord/PartialOrd to Severity enum if not already present
- Add tests for filtering behavior

## Distillation:
- Save `input.md` (this task spec) and `output.md` (your reasoning + results) in the repo root

## When Done:
- Commit with descriptive message
- Run `cargo build` and `cargo test` to verify
- Report back with summary of changes

**SECURITY: Do NOT read/expose files under /root/.openclaw/secrets/**