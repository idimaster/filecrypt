#!/bin/sh
set -eu

# Run from the repository root. All credentials and payloads are synthetic.
if [ "$#" -gt 1 ]; then
  printf 'Usage: sh scripts/smoke.sh [FILECRYPT_BINARY]\n' >&2
  exit 2
fi
smoke_dir=$(mktemp -d "${TMPDIR:-/tmp}/filecrypt-smoke.XXXXXX")
trap 'rm -rf "$smoke_dir"' EXIT HUP INT TERM

if [ "$#" -eq 1 ]; then
  cp "$1" "$smoke_dir/filecrypt"
else
  go build -o "$smoke_dir/filecrypt" ./cmd/filecrypt
fi
printf 'synthetic plaintext\000 with unicode π\n' > "$smoke_dir/input"
"$smoke_dir/filecrypt" keygen --out "$smoke_dir/key"
"$smoke_dir/filecrypt" encrypt --in "$smoke_dir/input" --out "$smoke_dir/encrypted" --key-file "$smoke_dir/key"
"$smoke_dir/filecrypt" decrypt --in "$smoke_dir/encrypted" --out "$smoke_dir/restored" --key-file "$smoke_dir/key"
cmp "$smoke_dir/input" "$smoke_dir/restored"

# Fixed bytes are only for this disposable test, never real credentials.
printf 'synthetic password\n' > "$smoke_dir/password"
"$smoke_dir/filecrypt" encrypt --in "$smoke_dir/input" --out "$smoke_dir/password.fc" --password-file "$smoke_dir/password"
"$smoke_dir/filecrypt" decrypt --in "$smoke_dir/password.fc" --out "$smoke_dir/password.out" --password-file "$smoke_dir/password"
cmp "$smoke_dir/input" "$smoke_dir/password.out"

# Append data to an otherwise valid file: a decrypted prefix must stay private.
cp "$smoke_dir/encrypted" "$smoke_dir/tampered"
printf 'x' >> "$smoke_dir/tampered"
status=0
"$smoke_dir/filecrypt" decrypt --in "$smoke_dir/tampered" --out "$smoke_dir/rejected" --key-file "$smoke_dir/key" 2> "$smoke_dir/error" || status=$?
test "$status" -eq 1
test ! -e "$smoke_dir/rejected"
test -s "$smoke_dir/error"

cp "$smoke_dir/encrypted" "$smoke_dir/existing-copy"
status=0
"$smoke_dir/filecrypt" encrypt --in "$smoke_dir/input" --out "$smoke_dir/encrypted" --key-file "$smoke_dir/key" 2> "$smoke_dir/error" || status=$?
test "$status" -eq 1
cmp "$smoke_dir/encrypted" "$smoke_dir/existing-copy"
printf 'CLI smoke test passed: keygen, both credential modes, byte comparison, tampering rejection, existing-output preservation\n'
