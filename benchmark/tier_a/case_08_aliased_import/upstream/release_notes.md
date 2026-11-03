# Release notes for logger-engine 2.0.0

Released on 2026-03-01.

## Breaking Changes
- Removed `log_fatal()`. Use `log_critical()` instead. Any calls to `log_fatal()` will fail with an AttributeError.

