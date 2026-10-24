# Filecrypt: Go reference implementation specification

## 1. Assignment

Implement a Go command-line application named `filecrypt` that encrypts and decrypts local files. Deliver runnable source, tests, and documentation. Explain the implementation choices in the README and final handoff.

This specification resolves the choices discussed during interview preparation: authenticated chunked encryption, bounded memory, separate file and chunk keys, optional use of a password at invocation time, and safe output publication. Implement both credential modes described below. The binary format is an educational format defined here; it is not compatible with age and has not received a cryptographic review.

Use library implementations of all cryptographic primitives. Do not implement AES, GCM, HKDF, or Argon2 yourself. Do not silently replace the specified wire format with age. Document age as an alternative when an application can use an established encrypted-file format.

The full reference implementation is broader than a 90-minute interview. Section 13 defines a smaller rehearsal checkpoint. Complete all required sections for the full reference implementation.

## 2. Goals and limits

Required:

- Encrypt arbitrary bytes and recover them exactly, including empty input.
- Process large files with memory proportional to one chunk, excluding the fixed password-KDF workspace.
- Authenticate content, header, record lengths, record positions, and the end of the stream.
- Reject modified, reordered, missing, duplicated, substituted, truncated, and appended records.
- Refuse to replace existing files or modify inputs and credential files.
- Publish a complete result only after successful processing and output close.
- Derive independent file and chunk keys from a supplied master key or password-derived secret.
- Produce useful errors without logging secrets or file content.

Out of scope:

- Directory traversal, recursive encryption, archives, stdin/stdout payload streaming, or in-place editing.
- Parallel encryption, resumable writes, random-access updates, and multiple recipients.
- KMS integration, key rotation, envelope encryption, revocation, or secure deletion.
- Preservation of filenames, timestamps, ACLs, or source permission bits.
- Hiding approximate file size, preventing rollback to a previously valid encrypted file, or proving author identity.
- Security against compromise of the running process, swap, or an attacker modifying the output directory during execution.
- Crash-durability guarantees. Atomic publication and persistence after power loss are separate properties.

Required platform: macOS and Linux on a filesystem supporting same-directory hard links. Unsupported publication operations must fail clearly; do not fall back to an overwrite-prone operation. Document this platform constraint.

## 3. CLI contract

```sh
filecrypt keygen --out master.key
filecrypt encrypt --in notes.txt --out notes.fc --key-file master.key
filecrypt decrypt --in notes.fc --out restored.txt --key-file master.key

filecrypt encrypt --in notes.txt --out notes.fc --password-file password.bin
filecrypt decrypt --in notes.fc --out restored.txt --password-file password.bin

filecrypt --help
filecrypt encrypt --help
```

Requirements:

1. Use `flag.FlagSet` or an equally small CLI solution. Prefer the standard library.
2. `encrypt` and `decrypt` require `--in`, `--out`, and exactly one of `--key-file` or `--password-file`.
3. Reject unknown commands, unknown flags, missing values, extra positional arguments, and conflicting credentials.
4. Help returns exit status 0. Usage errors return 2. Processing, credential, format, authentication, and filesystem errors return 1. Successful operations return 0.
5. Errors go to stderr. Successful transformations need not print anything. Never send payloads to stdout.
6. No flag accepts the secret itself. No secrets, derived keys, or plaintext appear in errors.
7. Input and credential paths must resolve to regular files. Input symlinks may resolve to regular files. Reject directories and device files. Validate through opened file descriptors where practical.
8. Existing output entries, including symlinks and hard links, must remain unchanged. This also protects input/output aliases and credential/output aliases.
9. Source files must remain stable while being processed; concurrent source mutation is outside the contract. Do not promise snapshot semantics.

### Credential bytes

- `keygen` generates exactly 32 bytes using `crypto/rand` and creates a new owner-only file using the same publication rules as other outputs.
- `--key-file` requires exactly 32 raw bytes. Use a bounded read of at most 33 bytes to validate it. Do not trim, decode, hash, or pad it.
- `--password-file` requires 1 through 1024 bytes. Use a bounded read of at most 1025 bytes. The bytes are the password exactly, including any newline. Do not normalize or trim them.
- Explain the password-file newline behavior in help and README. Do not introduce an interactive prompt or environment-variable secret fallback.
- Credential-file permissions are the caller's responsibility; generated files must use mode `0o600`.

## 4. Required cryptography and dependencies

- Go 1.24 or newer; use the installed supported toolchain and declare its compatible minimum version.
- Standard-library AES-256-GCM through `aes.NewCipher` and `cipher.NewGCM` with the standard 12-byte nonce and 16-byte tag.
- HKDF-SHA-256 through `crypto/hkdf.Key`, including extract and expand.
- Argon2id through `golang.org/x/crypto/argon2.IDKey` for password mode.
- `crypto/rand` for all production randomness.
- Pin an `x/crypto` version compatible with the selected Go toolchain and commit `go.sum`.

Use `NewGCM`, not `NewGCMWithRandomNonce`, for this format: nonce construction is specified below and no random nonce is serialized inside records. Do not mix the contracts of those constructors.

Do not use bcrypt for encryption-key derivation. Do not use a plain SHA-256 password hash as a substitute for Argon2id. Do not add cipher or KDF negotiation.

## 5. Binary format, version 1

All integer fields are unsigned and big-endian. The file is a 64-byte header followed by one or more records. There is always a final record, even for empty input. No trailing bytes or concatenated files are accepted.

### 5.1 Fixed header

| Byte offset | Length | Field | Required value |
|---|---:|---|---|
| 0 | 8 | Magic | ASCII `GFILEENC` |
| 8 | 1 | Format version | `1` |
| 9 | 1 | Credential mode | `1` = raw key; `2` = password |
| 10 | 4 | Plaintext chunk size | `65536` |
| 14 | 32 | File salt / generation identifier | Fresh random bytes for every encryption |
| 46 | 4 | Argon2 time cost | Raw: `0`; password: `3` |
| 50 | 4 | Argon2 memory cost in KiB | Raw: `0`; password: `65536` |
| 54 | 1 | Argon2 parallelism | Raw: `0`; password: `4` |
| 55 | 9 | Reserved | All zero |

Reject invalid magic, version, mode, chunk size, reserved fields, or KDF values before attempting password derivation or allocating record buffers. The supplied credential mode must match the header.

Password parameters are a fixed version-1 profile, not attacker-controlled tuning inputs. Reject any other profile. A future profile requires a deliberate format change. Argon2 memory is measured in KiB; the specified profile uses approximately 64 MiB of working memory.

Preserve the original header bytes and use them in record authentication. Fresh random salt is required even when encrypting identical content with identical credentials. Do not reuse a header for a retry, append, resume, or edited file.

### 5.2 Record framing

Each record contains:

```text
plaintext_length: uint32
flags:           uint8
ciphertext:      plaintext_length + 16 bytes
```

The first five bytes are the record header. The 16-byte GCM tag is included at the end of `ciphertext` by `Seal`.

- `flags == 0`: non-final record; plaintext length must equal `65536`.
- `flags == 1`: final record; plaintext length must be between `0` and `65535` inclusive.
- All other flags are invalid.
- Record indices start at zero and are inferred from the expected position; they are not stored in the file.
- A full chunk is always non-final. Exact multiples of the chunk size end with an additional empty final record.
- An empty file contains one empty final record with an authentication tag.
- Reject EOF before a final record, incomplete framing, incomplete tags, and any byte after the final record.
- Reject declared lengths before allocating or reading their ciphertext. Never allocate based on an unchecked length.

Let `C = 65536`, `N = plaintext length`, and `q = floor(N / C)`. A valid encrypted file has length:

```text
64 + N + 21 * (q + 1)
```

In particular, an encrypted empty file is 85 bytes. Use these facts in boundary tests.

## 6. Key hierarchy and authentication

The following definitions are normative. `HKDF` means full HKDF-SHA-256. `BE64(i)` means exactly eight big-endian bytes. Text labels are ASCII with no implicit terminator. Empty HKDF salt means `nil`.

### 6.1 Derivation

```text
raw-key mode:
    root = supplied 32-byte master key

password mode:
    root = Argon2id(password, file_salt,
                    time=3, memory_KiB=65536, parallelism=4,
                    output_length=32)

file_key = HKDF(secret=root,
                salt=file_salt,
                info="filecrypt/v1/file",
                output_length=32)

chunk_key_i = HKDF(secret=file_key,
                   salt=empty,
                   info=ASCII("filecrypt/v1/chunk/") || BE64(i),
                   output_length=32)
```

Run Argon2id once per operation, not once per chunk. Derive chunk keys independently by index. No derived keys are serialized or exposed by CLI commands.

### 6.2 Record encryption

For record `i`:

```text
nonce = 12 zero bytes
AAD   = original_64_byte_header || BE64(i) || original_5_byte_record_header
record_ciphertext = AES_256_GCM(chunk_key_i).Seal(nil, nonce, plaintext, AAD)
```

The fixed zero nonce is safe only because every record uses a separately derived key, with fresh per-file salt and a unique record index. There must be exactly one encryption under each derived chunk key. Never reuse a file salt with the same root secret, restart an index in the same file, or reuse this nonce rule with a shared file key. If changing the key hierarchy, reconsider nonce construction too.

On decryption, derive the key using the expected index, not an untrusted supplied index. Authenticate before writing the plaintext of that record to a temporary output. `Open` failure invalidates the entire operation; discard any returned bytes and remove staged output.

The header, record framing, and expected index are bound to every record by AAD. File-specific derivation prevents cross-file record substitution. The authenticated final flag and strict trailing-byte check detect incomplete or extended streams.

### 6.3 Security boundaries to explain

- Compromise of a derived chunk key exposes that record; it should not reveal its parent or sibling keys under HKDF's assumptions.
- Compromise of a file key exposes every record in that file.
- Compromise of the master key exposes all available files derived from it.
- Knowledge or successful guessing of a reused password exposes files protected by that password, despite distinct salts.
- This hierarchy does not provide forward secrecy or protect against a process that can access the root secret.
- A valid older file can be replayed. The format has no external freshness state.
- Ciphertext possession permits offline password guessing; the KDF increases its cost but cannot repair a weak password.

State these as properties of this design, not as claims that HKDF eliminates master-key compromise. Keep keys in byte slices where practical, minimize lifetime and copies, and make no guarantee of complete secret erasure in Go.

## 7. Streaming and limits

Use fixed-size buffers and `io.ReadFull` or equivalent correct framing. Never use `os.ReadFile`, `io.ReadAll`, a line scanner, or a file-sized `bytes.Buffer` for payloads.

Encryption loop:

1. Read up to one full plaintext chunk.
2. Full read with no error: emit a non-final record.
3. `io.ErrUnexpectedEOF`: emit the bytes read as the final record.
4. `io.EOF` with zero bytes: emit an empty final record.
5. Any other error: fail and discard staged output. Do not authenticate a partial read as complete input after an I/O failure.

Decryption loop:

1. Read a complete record header and validate it.
2. Read exactly its bounded ciphertext length.
3. Derive the expected chunk key and call `Open` with the specified AAD.
4. Write authenticated plaintext only to staged output.
5. Increment the expected index for non-final records.
6. For a final record, verify actual EOF. A non-EOF read error is a failure, not successful completion.

Maximum plaintext size is 1 TiB (`1 << 40` bytes), including any final partial record. Enforce this during processing in both directions, using checked counters. Reject larger regular files early when possible, but do not rely only on the initial stat. Check before counter overflow. The exact-limit case is valid and still includes its final record. No buffers, record collections, keys, or goroutines may accumulate with file size.

Read-only malformed format fields may produce specific errors. Authentication failures should say `decryption failed: wrong credential or damaged file`; do not claim to distinguish those causes.

## 8. Filesystem transaction

For `keygen`, encryption, and decryption:

1. Validate arguments and credential shape. Open and validate the input when applicable.
2. Create a temporary file in the destination directory with `os.CreateTemp`; retain owner-only mode `0o600`.
3. Write the result to that temporary file. The final destination must remain absent during processing.
4. Check all write errors and explicitly check the output file's close result. Do not report success while relying on an unchecked deferred close.
5. After complete success, publish with `os.Link(tempPath, destinationPath)`. Same-directory staging keeps both entries on the same filesystem. Linking must fail if any destination entry already exists.
6. Remove the temporary name after successful publication. The destination now references the completed file.

Do not use `os.Create(destination)`, `os.WriteFile(destination, ...)`, or plain `os.Rename(temp, destination)` for publication: those operations can replace existing data. An existence check may improve diagnostics, but the actual publication operation must enforce no replacement even if the destination appears after validation.

On any pre-publication failure, close resources, attempt temporary-file cleanup, and leave the destination absent or its existing contents untouched. Preserve the primary error; mention cleanup failure without masking it. Cleanup is best effort on filesystem failures or abrupt termination.

The successful link is the commit point. Failure to remove the extra temporary name after commit must produce a stderr warning and retain successful exit status; it must not delete the valid destination or claim the transformation failed. Document that a leftover temporary hard link may remain in this exceptional case.

Never publish a decrypted prefix after a later authentication failure. A staged prefix can exist privately during decryption; that is different from authenticating the entire file before any plaintext reaches disk. Plaintext may remain in a staging file after a crash; secure deletion and crash recovery are out of scope.

Keep the file-commit helper separate enough to test write, close, publication, and cleanup failures without building a general filesystem framework. Do not use `log.Fatal` or `os.Exit` inside processing functions, because they bypass deferred cleanup. Only the outermost CLI boundary chooses an exit status after processing returns.

## 9. Suggested organization

Prefer a small module, for example:

```text
cmd/filecrypt/main.go
internal/cli/...
internal/filecrypt/...       # header, framing, derivation, streaming codec
internal/fileio/...          # staged no-replace publication
README.md
go.mod
go.sum
```

This layout is advisory. Avoid interfaces for every function or unnecessary packages. Separate byte-stream encryption from paths and CLI parsing so tests can use readers/writers and inject failures. Dependency injection for randomness may be used internally for deterministic tests; never expose deterministic salts or RNG seeds as CLI options.

## 10. Required acceptance tests

Use table-driven Go tests where useful. Do not limit validation to round trips.

### Content and boundaries

- Round-trip empty bytes, ASCII, Unicode, embedded zero bytes, and arbitrary binary data.
- Test lengths `0`, `1`, `C-1`, `C`, `C+1`, `2*C-1`, `2*C`, and `2*C+1`.
- Assert record flags, final-record shape, and the serialized-size formula independently of round-trip success.
- Encrypt identical content twice with the same credential: salts and ciphertexts differ; both decrypt correctly.
- Demonstrate bounded streaming with a generated large source and a non-accumulating sink. Do not commit large fixture files. Explain the memory bound from the buffer design; a round-trip alone is not evidence of bounded memory.
- Exercise the 1 TiB counter boundary through small internal limit tests or a configurable internal test limit, not by allocating or writing 1 TiB. Production limit must remain fixed.

### Credentials and derivation

- Wrong but valid-length master key; wrong password; header/credential-mode mismatch.
- Keys of 0, 31, and 33 bytes are rejected; a 32-byte key containing whitespace is preserved exactly.
- Empty and oversized passwords are rejected. Newline-containing passwords are treated literally.
- Both credential modes work. Keep password-mode tests focused so the suite does not perform unnecessary repeated expensive derivations.
- Same derivation inputs reproduce keys; changes to salt, index, or purpose label produce distinct derived outputs.
- Include a checked deterministic wire-format fixture for a small raw-key input, with a fixed test-only salt. Document how it was constructed and verify its framing and AAD independently of the production encoder, so matching encoder/decoder mistakes cannot be the only oracle.

### Tampering and malformed streams

- Flip bytes in the salt, valid header fields, ciphertext, and tag; require rejection.
- Reject invalid magic, version, mode, reserved bytes, chunk size, flags, lengths, and KDF profiles.
- Confirm unsupported KDF profiles are rejected before invoking Argon2id.
- Truncate within the file header, record header, ciphertext, and tag.
- Remove the final record; remove a complete middle record; reorder or duplicate records.
- Substitute a same-position record from another file encrypted using the same credentials.
- Append a byte, another record, or another encrypted file after the final record.
- Change the final flag or final length; reject a full-sized final record and a short non-final record.
- Every decryption failure leaves no newly published plaintext file.

### Filesystem and failures

- Existing destination file, directory, symlink, and hard link remain untouched.
- Input/output aliases and credential/output aliases do not alter their targets.
- Destination created between validation and publication is preserved and publication fails.
- Inject input-read, output-write, output-close, and publication failures; require nonzero status and attempted cleanup.
- Test temporary-name cleanup failure after commit separately: valid destination remains, success status plus warning.
- Check generated key and output permissions on Unix. Verify the final path is absent until commit.
- Missing paths, non-regular inputs, and missing output directories produce useful errors.

### CLI and fuzzing

- Test help, required flags, conflicts, unknown commands/flags, unexpected arguments, and exit statuses.
- Verify diagnostics do not contain known test secrets or plaintext.
- Fuzz bounded header/record parsing and raw-key decryption with malformed input: no panics or unbounded allocation. Do not make the fuzz target repeatedly run Argon2 on arbitrary inputs.

## 11. Documentation deliverables

The README must include:

- Build, test, key-generation, encryption, and decryption commands.
- Password-file byte semantics and a safe example that avoids a secret CLI argument.
- A concise format description or link to a checked-in copy of this specification.
- Why AEAD, fresh per-file salt, purpose labels, per-chunk keys, and an authenticated final record are used.
- Why the fixed nonce depends on unique chunk keys; do not describe zero nonces as generally safe.
- The blast-radius boundaries in section 6.3.
- Streaming memory behavior, 1 TiB limit, platform assumptions, publication semantics, and crash limitations.
- Why a complete format/library such as age would be considered for a real application.
- Remaining limitations and any deviations. Required behavior must not be quietly downgraded to a TODO.

## 12. Verification and completion criteria

Run and report actual results for:

```sh
gofmt -w <changed Go files>
go build ./...
go vet ./...
go test ./...
go test -race ./...
```

Run a short fuzz smoke test for the implemented parser/decryption target and a CLI smoke test showing keygen, encrypt, decrypt, byte-for-byte comparison, tampering rejection, and preservation of an existing output. Use disposable fixtures and never include real credentials.

The task is complete when all required behavior is implemented, checks pass, and the README explains the trade-offs. The final handoff should list runnable commands, validation results, and any material limitations. Do not claim a cryptographic audit, age compatibility, or secure memory erasure.

## 13. Interview rehearsal and evaluation

For a 90-minute rehearsal, start with raw-key whole-file AES-GCM, a documented 10 MiB bound, no-replace output creation, a versioned header, and core failure tests. Treat this as a separate rehearsal milestone, not a version-1 chunked file: never emit the version-1 header above for a different encoding. Then discuss the streaming/key-hierarchy upgrade. The full coding-agent assignment remains the reference format specified in sections 3 through 12.

Suggested 90-minute allocation: 10 minutes clarifying requirements, 25 minutes crypto and tests, 20 minutes CLI/filesystem integration, 20 minutes negative cases, and 15 minutes demonstration and trade-offs.

Score each category 0–4: 0 missing/unsafe; 1 major gaps; 2 partial; 3 meets requirements; 4 clear implementation plus demonstrated reasoning. Weighted points are `weight * score / 4`. This is a proposed practice rubric, not the employer's disclosed rubric.

| Category | Weight | Evidence |
|---|---:|---|
| Problem framing and trade-offs | 20% | Explicit scope, key model, bounds, format and platform choices |
| Functional correctness | 20% | Runnable CLI, exact recovery, valid framing and boundary behavior |
| Security and data preservation | 20% | Correct derivation/nonces, authentication, final marker, no replacement |
| Testing and debugging | 15% | Negative cases, independent format evidence, meaningful failure tests |
| Communication and adaptation | 15% | Explains uncertainty, reasoning, feedback and remaining limits |
| Go implementation quality | 10% | Clear boundaries, error propagation, bounded buffers and cleanup |

Critical issues requiring correction regardless of total score: repeating a nonce under the same key, publishing unauthenticated or incomplete plaintext, overwriting input/existing output, accepting truncated streams, or allowing unbounded attacker-controlled allocations/KDF costs. Consulting API documentation is acceptable; correctness depends on understanding and validating the API contract.

## 14. Technical references

These support the primitive contracts and design discussion. The custom header, framing, derivation labels, and publication contract above are requirements of this assignment, not an external standard.

- [Go AES](https://pkg.go.dev/crypto/aes)
- [Go AEAD and GCM](https://pkg.go.dev/crypto/cipher)
- [Go HKDF](https://pkg.go.dev/crypto/hkdf)
- [HKDF: RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)
- [Go Argon2id](https://pkg.go.dev/golang.org/x/crypto/argon2)
- [Go filesystem APIs](https://pkg.go.dev/os)
- [Age format: established streaming-format reference](https://age-encryption.org/v1)
- [Age Go API: alternative application implementation](https://pkg.go.dev/filippo.io/age)
