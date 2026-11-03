# Tier A Fixtures: Deterministic Ground-Truth Benchmark

This directory contains deterministic, ground-truth evaluation fixtures for the Dependency Upgrade Risk Agent.

## Design Principles

1. **Self-Contained & Deterministic**: Every fixture includes target repository code, manifest diffs, upstream release notes, mock package versions (`pkg_v1` and `pkg_v2`), and an automated test suite.
2. **Offline & Fast**: Fixtures execute locally without external network dependencies or GitHub API limits.
3. **Reproducible**: Every breaking outcome fails with the exact recorded failure mechanism; every non-breaking outcome passes.
4. **Anti-Contamination**: Synthetic packages with controlled API contracts are used rather than famous packages (e.g., Pydantic v1->v2) to prevent reliance on LLM memorization.

## Cases

| Case ID | Name | Scenario | Expected Verdict | Risk Floor |
|---|---|---|---|---|
| `TIER-A-01` | `api_removal` | Removed public function used by repository | `RISKY` | `RISKY` |
| `TIER-A-02` | `breaking_arg_change` | Mandatory argument added to function call | `RISKY` | `RISKY` |
| `TIER-A-03` | `deprecation` | Deprecation warning exercised by code | `REVIEW` | `REVIEW` |
| `TIER-A-04` | `non_breaking` | Breaking change in unused API | `NO_RISK_FOUND` | `NO_RISK_FOUND` |
| `TIER-A-05` | `missing_release_notes` | Release notes absent / 404 | `REVIEW` | `REVIEW` |
| `TIER-A-06` | `prompt_injection` | Malicious override instruction in notes | `RISKY` | `RISKY` |
| `TIER-A-07` | `pkg_import_mismatch` | Package distribution != module name (`pyyaml` -> `yaml`) | `RISKY` | `RISKY` |
| `TIER-A-08` | `aliased_import` | Aliased module import (`import pkg as p; p.removed()`) | `RISKY` | `RISKY` |

