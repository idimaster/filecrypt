# Raw-key version-1 fixture

`raw-v1.hex` contains one 98-byte encrypted file, encoded as hexadecimal.
The master key is bytes `00` through `1f`, the salt is bytes `20` through
`3f`, and the 13 plaintext bytes are `filecrypt\x00v1\n`. Its sole record is
final, has index zero, and has record header `0000000d01`.

The standalone `generate.go` imports no production package. It constructs the
literal header and record bytes, derives keys with the library HKDF using the
specification's labels, constructs the AAD as header + eight zero index bytes +
record header, and uses library AES-256-GCM with a twelve-zero-byte nonce.
Reproduce from the repository root:

```sh
go run internal/filecrypt/testdata/generate.go
```

Compare the printed hex with the checked-in fixture. `TestWireFixture` checks
the framing, independently authenticates the ciphertext and mutations of each
AAD component, compares the production encoder to these checked bytes, and
checks the production decoder. The generator is never invoked automatically
by the tests, so changes cannot silently regenerate the oracle. These are
public synthetic test credentials; deterministic randomness is not exposed
through the CLI.
