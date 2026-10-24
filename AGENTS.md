# Filecrypt implementation guidance

## Source of truth and scope

- Read [the reference specification](spec/filecrypt-reference-spec.md) before making implementation changes. Sections 3–12 define the required behavior; this file is implementation guidance, not a replacement for the spec.
- Build the full Go reference implementation, including raw-key and password modes. Section 13 is a separate interview rehearsal; do not substitute that smaller design or emit a version-1 header for its encoding.
- Preserve the specified format, cryptographic derivations, limits, CLI contract, and publication behavior. Surface contradictions before changing a normative requirement. Document implementation choices and any deviations in the README; required behavior cannot be left as a TODO.
- This is an educational custom format, without a cryptographic audit or age compatibility. Do not claim otherwise.

## Toolchain and layout

- Use an installed, supported Go toolchain at least as new as Go 1.24. Check `go version` before scaffolding; if Go is unavailable, report the prerequisite and do not claim checks passed.
- Declare a compatible minimum Go version in `go.mod`. Pin a compatible `golang.org/x/crypto` version and commit `go.sum`; do not select a dependency requiring a newer toolchain than the declared minimum.
- Prefer the standard library, with `golang.org/x/crypto/argon2` for Argon2id. Avoid unrelated dependencies and generated frameworks.
- Start with `cmd/filecrypt`, `internal/cli`, `internal/filecrypt`, and `internal/fileio`, plus `README.md`. Keep stream encoding independent of paths and argument parsing. Use small test seams for randomness, limits, and file failures rather than a general filesystem abstraction.
- Keep existing user changes intact. Do not include editor metadata or generated binaries in implementation changes.

## Security and correctness invariants

- Use library AES-256-GCM via `cipher.NewGCM`, full HKDF-SHA-256 via `crypto/hkdf.Key`, Argon2id, and production randomness from `crypto/rand`. Do not implement primitives or substitute derivations.
- Preserve the exact 64-byte header, labels, big-endian fields, record framing, and AAD in sections 5–6. Retain original header and record-header bytes for authentication.
- Derive the root once per operation, the file key with the file salt, and a distinct chunk key for every expected record index. The 12-byte zero nonce is valid only with this hierarchy, a fresh per-file salt, and exactly one encryption per chunk key.
- Validate header fields, credential-mode matching, and the fixed KDF profile before password derivation or record-buffer allocation. Validate record flags and lengths before reading ciphertext. Never use attacker-controlled KDF costs or allocation sizes.
- Read payloads with bounded chunk buffers; no whole-payload reads or file-sized collections. Enforce the fixed 1 TiB plaintext limit incrementally in both directions with checked counters, including final partial records.
- A full chunk is non-final. Always emit an authenticated final record, including an empty one for empty input or exact chunk multiples. Require actual EOF after the final record; missing final records, appended bytes, and non-EOF read errors fail.
- Authenticate each record before writing its plaintext to staging. Any authentication or later stream failure must prevent publication. Use `decryption failed: wrong credential or damaged file` for authentication failures.
- Validate opened input and credential files as regular files. Read raw keys with a 33-byte bound and passwords with a 1025-byte bound; enforce their specified lengths. Preserve all credential bytes, including whitespace and newlines. Never expose secrets through arguments, diagnostics, or test output.
- Generate keys and stage outputs with owner-only permissions. Use same-directory `os.CreateTemp`, check writes and explicit output close, and publish only with `os.Link(tempPath, destinationPath)`. Never replace an existing entry or fall back to overwrite-prone creation or rename.
- Treat a successful link as the commit point. Before commit, preserve the primary error and attempt cleanup. After commit, temporary-name cleanup failure produces a warning and successful status, retaining the valid destination.
- Keep exit selection at the outermost CLI boundary: help/success `0`, processing errors `1`, usage errors `2`. Processing code must return errors so cleanup runs; do not use `log.Fatal` or `os.Exit` there.

## Implementation sequence

1. Scaffold the module and small CLI boundary. Define constants, credential types, and validated header/record parsing. Add malformed-input and boundary tests alongside the parsers.
2. Implement derivation and streaming encryption/decryption. Establish a deterministic raw-key wire fixture with an independently checked construction, framing, and AAD; do not rely solely on encoder/decoder round trips.
3. Implement and fault-test the staged no-replace publication helper, then integrate keygen and transformations with credential and regular-file validation.
4. Complete the CLI contract, tampering and filesystem coverage, bounded fuzz targets, README, and end-to-end smoke tests. Track all acceptance items in spec section 10, including password mode and error paths.

## Required validation

- Cover chunk boundaries, serialized-size and final-record shape, fresh salts, literal credential bytes, derivation separation, malformed headers/framing, and all specified tampering cases.
- Exercise generated large streams with non-accumulating sinks and test the size limit through a small internal test limit; keep the production limit fixed. Do not commit large fixtures or allocate 1 TiB in tests.
- Test existing outputs and path aliases, a destination appearing before publication, injected read/write/close/link failures, cleanup attempts, post-commit cleanup warnings, permissions, and absence of the final path until commit.
- Ensure decryption failures never publish a new plaintext file. Verify diagnostics omit known test secrets and plaintext.
- Keep expensive password tests focused. Fuzz bounded parsing and raw-key decryption without repeatedly invoking Argon2 on arbitrary data.
- Format changed Go files, then run and report the actual outcomes of:

  ```sh
  gofmt -w <changed Go files>
  go build ./...
  go vet ./...
  go test ./...
  go test -race ./...
  go test ./internal/filecrypt -run='^$' -fuzz='^FuzzDecrypt$' -fuzztime=10s
  ```

  Name the raw-key decryption fuzz target `FuzzDecrypt`, or update the command to match the implemented target. Run other implemented parser fuzz targets as appropriate. Resolve missing tooling or report precisely which checks could not run.
- Run a disposable CLI smoke test covering keygen, encrypt, decrypt, byte-for-byte comparison, tampering rejection, and preservation of an existing output. Use synthetic credentials only.

## Documentation and handoff

- Fulfill README requirements in spec section 11: runnable commands, literal password-file newline semantics and a safe example, format reference, design reasoning, key-compromise boundaries, memory and size bounds, and age as an established alternative.
- Explain macOS/Linux same-directory hard-link requirements, atomic no-replace publication, possible leftover temporary links, staged plaintext after crashes, and the absence of crash durability, secure deletion, complete secret erasure, or forward secrecy guarantees.
- Finish with the implemented behavior, runnable commands, actual validation results, and material limitations. Do not mark the full implementation complete until the required acceptance behavior and documentation are delivered.
