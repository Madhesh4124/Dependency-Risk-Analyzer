# Release notes for stream-processor 2.0.0

## Breaking Changes
- Removed deprecated flush_buffer() method on StreamWorker instances. Please migrate to drain().
