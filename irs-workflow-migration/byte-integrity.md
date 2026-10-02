# Byte Integrity and Line Endings

Existing Windows-authored migration audit artifacts use CRLF line endings, and evidence hashes bind exact bytes.

## Git Portability Rule

- The rule `** -text` in `irs-workflow-migration/.gitattributes` covers only files recursively under that directory.
- Placing `.gitattributes` inside `irs-workflow-migration/` ensures the configuration is scoped specifically to this directory tree without requiring global repository or user configuration.
- Specifying `-text` disables newline conversion across all operating systems, but does not itself disable textual diffs.
- Exact byte preservation prevents hash mismatches across checkouts on Linux, macOS, and Windows.

## Tooling and Ingestion Requirements

- Artifacts and files must be uploaded with raw bytes unchanged.
- File ingestion and artifact verification must read raw bytes directly (or read UTF-8 without universal newline translation, e.g., binary mode or `newline=""`).
- Historic published commits are kept unchanged; the snapshot preserves byte identity and must be verified against expected hashes.
