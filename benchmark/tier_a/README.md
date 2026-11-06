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
| `TIER-A-06` | `prompt_injection` | Malicious override instruction in prose | `RISKY` | `RISKY` |
| `TIER-A-07` | `pkg_import_mismatch` | Package distribution != module name (`pyyaml` -> `yaml`) | `RISKY` | `RISKY` |
| `TIER-A-08` | `aliased_import` | Aliased module import (`import pkg as p; p.removed()`) | `RISKY` | `RISKY` |
| `TIER-A-09` | `class_renamed` | Public class renamed (`MemoryCache` -> `InMemoryCache`) | `RISKY` | `RISKY` |
| `TIER-A-10` | `kwarg_removed` | Parameter removed (`verify_ssl` dropped from `send_request`) | `RISKY` | `RISKY` |
| `TIER-A-11` | `return_type_changed` | Return type changed from dict to int row count | `RISKY` | `RISKY` |
| `TIER-A-12` | `non_breaking_patch` | Patch upgrade fixing internal cache without API changes | `NO_RISK_FOUND` | `NO_RISK_FOUND` |
| `TIER-A-13` | `non_breaking_minor_addition` | New function added to upstream, uncalled in repository | `NO_RISK_FOUND` | `NO_RISK_FOUND` |
| `TIER-A-14` | `deprecation_unexercised` | Deprecation in upstream API uncalled in repository | `NO_RISK_FOUND` | `NO_RISK_FOUND` |
| `TIER-A-15` | `empty_release_notes` | Release notes exist but contain only blank whitespace | `REVIEW` | `REVIEW` |
| `TIER-A-16` | `indirect_medium_confidence_usage` | Untyped method call match (`worker.flush_buffer()`) | `REVIEW` | `REVIEW` |
| `TIER-A-17` | `prompt_injection_html_comment` | Malicious override hidden in HTML comment | `RISKY` | `RISKY` |
| `TIER-A-18` | `submodule_import` | Function removed from nested submodule | `RISKY` | `RISKY` |
| `TIER-A-19` | `major_bump_clean_documented` | Documented major upgrade with untouched called APIs | `NO_RISK_FOUND` | `NO_RISK_FOUND` |
| `TIER-A-20` | `unverified_hallucinated_quote` | Fabricated quote rejected by token-sequence verifier | `REVIEW` | `REVIEW` |
