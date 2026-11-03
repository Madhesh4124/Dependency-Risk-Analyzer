# Release notes for math-solver 2.0.0

Released on 2026-02-01.

## Breaking Changes
- Changed the signature of `solve()`. The function now takes `mode` ('exact' or 'approximate') as a mandatory second argument (`solve(equation, mode, precision=2)`). Existing callers that do not supply `mode` will fail with a `TypeError`.

