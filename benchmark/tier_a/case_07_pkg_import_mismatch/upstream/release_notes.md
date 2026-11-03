# Release notes for synthetic-yaml 2.0.0

Released on 2026-02-25.

## Breaking Changes
- Removed `load_unsafe()` completely due to security vulnerabilities. All users must switch to `safe_load()`. Calling `load_unsafe()` raises an AttributeError.

