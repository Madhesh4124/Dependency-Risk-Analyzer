# Release notes for data-transformer 2.0.0

Released on 2026-01-15.

## Breaking Changes
- Removed the deprecated function `transform_legacy()`. Applications calling `transform_legacy()` will raise an `AttributeError`. Please migrate to `transform()` which provides identical functionality with improved performance.
- Dropped compatibility shims for Python 3.8.

