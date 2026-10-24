# filecrypt

`filecrypt` encrypts and decrypts local regular files using the educational
[version-1 reference format](spec/filecrypt-reference-spec.md). Both a raw
32-byte master key and a password file are supported. Existing output entries
are always preserved. This custom format has not received a cryptographic
audit and is not compatible with age.

## Build and use

Requires Go 1.26 or newer, macOS or Linux, and a destination filesystem that
supports same-directory hard links. The module pins `golang.org/x/crypto`
v0.58.0, which requires Go 1.26; development checks were run with Go 1.27.3.

```sh
go build -o filecrypt ./cmd/filecrypt
./filecrypt --help
./filecrypt keygen --out master.key
./filecrypt encrypt --in notes.txt --out notes.fc --key-file master.key
./filecrypt decrypt --in notes.fc --out restored.txt --key-file master.key
cmp notes.txt restored.txt
```

Each output must be a new path. Inputs and credential paths must resolve to
regular files; input symlinks to regular files are supported. Generated keys
contain exactly 32 random raw bytes. Supplied keys must also contain exactly
32 bytes: no hex/base64 decoding, trimming, hashing, or padding is performed.
Keep the key: there is no recovery mechanism.

Password files contain **1 through 1024 literal bytes**, including any newline.
For example, a text file containing `example` and one containing `example`
followed by a newline specify different passwords. The CLI never prompts for
secrets, accepts a secret argument, or reads an environment-variable secret.
A synthetic example that creates a random credential without putting its
contents in a command argument or shell history:

```sh
umask 077
openssl rand -out password.bin 32
./filecrypt encrypt --in notes.txt --out password-notes.fc --password-file password.bin
./filecrypt decrypt --in password-notes.fc --out password-restored.txt --password-file password.bin
cmp notes.txt password-restored.txt
```

This example requires OpenSSL only to create the password file; filecrypt has
no runtime OpenSSL dependency. Protect supplied credential-file permissions
yourself. Every generated key and transformation output uses mode `0600`
(subject to a more restrictive process umask); source permission bits and
metadata are not copied.

Help exits with status `0`, invalid command usage with `2`, and credential,
format, authentication, I/O, or publication failures with `1`. Successful
transformations are silent. Errors and post-publication cleanup warnings go
to stderr; payloads never go to stdout. An authentication failure reports
`decryption failed: wrong credential or damaged file` without distinguishing
those causes. Structural format errors can be more specific.

## Format and design

The specification is normative. A file starts with a 64-byte header containing
`GFILEENC`, version 1, credential mode, the fixed 65536-byte chunk size, a fresh
32-byte random salt, the fixed KDF profile, and reserved zero bytes. Integers
are big-endian. Each record is a four-byte plaintext length, a one-byte flag,
and AES-256-GCM ciphertext including its 16-byte tag.

Full chunks are non-final. A final record contains 0–65535 plaintext bytes;
empty input and exact chunk multiples end in an authenticated empty final
record. For plaintext length `N` and chunk size `C = 65536`, encrypted size is
`64 + N + 21 * (floor(N/C) + 1)`. An empty encrypted file is 85 bytes.

The root secret is either the supplied raw key or the 32-byte result of
Argon2id(password, file salt), with time cost 3, memory 65536 KiB, and
parallelism 4. The password KDF runs once per operation. Its version-1 profile
is fixed: malformed headers and other KDF parameters are rejected before
password derivation and record-buffer allocation.

Full HKDF-SHA-256 derives a file key using the file salt and the purpose label
`filecrypt/v1/file`. Another HKDF derives each chunk key with empty salt and
`filecrypt/v1/chunk/` followed by the eight-byte expected record index. Purpose
labels separate the derivations, fresh file salts separate generations, and
independent chunk keys limit exposure from a compromised chunk key.

Each record uses library AES-256-GCM with a twelve-zero-byte nonce. **This nonce
rule depends on a fresh per-file salt and exactly one encryption under each
distinct chunk key.** It is not a generally safe rule for a shared encryption
key. Never reuse a generation header, append/resume an encrypted file, or
restart record indices. The CLI exposes no deterministic randomness controls.

AEAD authenticates content and binds the original header, the expected index,
and the original record header as additional authenticated data. This binds
framing and position, while file-specific derivation prevents cross-file
record substitution. The authenticated final marker plus an actual EOF check
reject truncation and extensions. Reordered, duplicated, missing, modified,
or appended records invalidate the whole operation.

## Memory, publication, and limits

The maximum plaintext size is 1 TiB (`1 << 40` bytes). Encryption rejects an
oversized regular input early, and both directions enforce checked running
counters, including the final partial record. Input files must remain stable
throughout processing; the program does not provide snapshot semantics.

Each codec retains a single 65552-byte payload buffer and a small, fixed amount
of framing/key state, reusing the payload buffer for in-place GCM operations.
Live record state does not accumulate with file size. Password mode additionally
uses approximately 64 MiB of fixed Argon2 workspace. Go's allocator, garbage
collector, and runtime add overhead; this is a design bound, not a process RSS
ceiling. Credentials are bounded reads, and untrusted lengths are validated
before reading ciphertext. The generated-stream test connects source, codecs,
and a non-accumulating sink without retaining an entire payload.

For all three operations, `os.CreateTemp` stages a private file in the output
directory. Writes and the explicit output close must succeed before
`os.Link(temp, destination)` commits the completed result. A hard link cannot
replace any existing destination, including dangling symlinks or aliases to
an input or credential. A destination appearing during processing is also
preserved. There is no rename or overwrite fallback if hard links fail.

Before commit, errors trigger close and best-effort temporary-file removal.
Cleanup errors accompany the primary error. After a successful link, failure
to remove the extra temporary name leaves a valid destination, emits a warning,
and keeps exit status `0`. An extra temporary hard link can remain in that case.

During decryption, authenticated chunks can reach the private staging file
before later records are authenticated. The final path is published only after
the complete stream passes. Crashes can leave staged plaintext behind. There
is no secure deletion, crash recovery, `fsync` persistence guarantee, or defense
against an attacker modifying the output directory during execution. Atomic
publication does not promise persistence after power loss.

## Security boundaries and alternatives

- Compromise of a chunk key exposes that record; under HKDF's assumptions it
  should not reveal its parent or sibling keys.
- Compromise of a file key exposes all records of that file.
- Compromise of the master key exposes all available files derived from it.
- Knowledge or successful guessing of a reused password exposes files protected
  with that password despite distinct salts. Possession of ciphertext permits
  offline password guessing; Argon2 increases its cost but cannot fix a weak password.
- The design provides no forward secrecy, author identity, or protection from
  a compromised process/root secret, swap, or replay of an older valid file.
- Keys are held in byte slices where practical and buffers are cleared when
  feasible, but Go cannot guarantee complete erasure of secret copies.

Approximate file size remains visible. Directory recursion, stdin/stdout payload
streams, in-place edits, parallel encryption, resumable writes, multiple
recipients, KMS integration, rotation, and metadata preservation are outside
this assignment. There are no intentional deviations from the required format
or CLI contract.

For a real application that can adopt an established encrypted-file format,
consider [age](https://age-encryption.org/) and its
[Go library](https://pkg.go.dev/filippo.io/age) rather than maintaining a custom
format. It supplies an existing format and recipient-oriented tooling. This
project keeps the specified educational format to demonstrate the explicit
streaming, derivation, and publication requirements.

## Verification

```sh
gofmt -w cmd internal
go build ./...
go vet ./...
go test ./...
go test -race ./...
go test ./internal/filecrypt -run='^$' -fuzz='^FuzzDecrypt$' -fuzztime=10s
go test ./internal/filecrypt -run='^$' -fuzz='^FuzzParse$' -fuzztime=10s
sh scripts/smoke.sh
```

Tests cover content and chunk boundaries, independently checked framing and
wire bytes, fresh salts, both credential modes, derivation separation,
malformed/tampered streams, no publication after decryption failure, credential
semantics, aliases, racing destinations, injected I/O/close/link/cleanup errors,
permissions, CLI statuses, bounded streaming, and small internal limit tests.
The raw-key fuzz target rejects password headers before Argon2 can run.
See [fixture construction notes](internal/filecrypt/testdata/README.md).

The smoke script builds a temporary binary and uses disposable synthetic
credentials to verify raw-key and password round trips, exact byte comparison,
tampering rejection, and existing-output preservation. It removes its temporary
directory on exit. Run race tests on a Go platform with race-detector support.

## GitHub CI and releases

[CI](.github/workflows/ci.yml) runs on branch pushes, pull requests, and manual
dispatches. It checks formatting, verifies modules, builds, runs vet, unit and
race tests, and exercises the CLI on Linux and macOS with Go 1.26.x and the
latest stable Go release. The Linux/stable job also runs both 10-second fuzz
smoke tests. Keep the minimum CI Go version aligned with `go.mod`.

[Release](.github/workflows/release.yml) runs when a version tag is pushed.
It first runs the same complete CI suite against the tagged commit, then
cross-compiles CGO-free Linux and macOS binaries for AMD64 and ARM64, packages
them with the README, license, and format specification, and smoke-tests the
packaged Linux/AMD64 binary. The four `.tar.gz` archives and `SHA256SUMS` are
retained as workflow artifacts for seven days and uploaded to GitHub Releases.

After committing and pushing these workflows and the desired source changes,
publish a release with a new tag:

```sh
git tag -a v1.0.0 -m 'Release v1.0.0'
git push origin v1.0.0
```

Use a tag such as `v1.1.0-rc.1` to publish a prerelease without marking it latest.
Tags must match `vMAJOR.MINOR.PATCH` with an optional prerelease suffix. No
personal access token is needed: only the publishing job receives
`contents: write` through GitHub's built-in token. Repository or organization
policy must allow that permission. The publisher verifies checksums, uploads
all assets to a draft, then publishes it. A failed draft can be resumed by
rerunning the workflow; an already-published release is never overwritten.

For local packaging and verification, use a new output directory:

```sh
bash scripts/package-release.sh v1.0.0
(cd dist && shasum -a 256 --check SHA256SUMS)
```

For example, `filecrypt_v1.0.0_darwin_arm64.tar.gz` is for Apple Silicon Macs;
`filecrypt_v1.0.0_linux_amd64.tar.gz` is for AMD64 Linux. Verify downloaded
archives against `SHA256SUMS` before extracting. Checksums detect mismatched
downloads; the release binaries are not signed or notarized.
