## Agent skills

### Issue tracker

GitHub Issues via the `gh` CLI (repo: `xiabai2004/RayScan`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### Code change log

All code changes must be logged in this file. Each entry should include:
- Date (YYYY-MM-DD)
- Summary of changes
- Affected files/modules

## Change Log

### 2026-06-27
- Added Code change log section to AGENTS.md

### 2026-06-27 (Profile System)
- Added Profile system: `wvs/profiles/` module with ProfileManager
- Added CLI subcommands: `rayscan profile list|create|delete|export|import`
- Added `rayscan use <profile> -u <url>` command for profile-based scanning
- Added built-in profiles: default, src-quick, pentest-full, sqli-only
- Added 17 tests in `tests/test_profiles/`
