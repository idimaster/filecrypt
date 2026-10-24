package filecrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"testing"
)

func rawCredential() Credential {
	return Credential{Mode: RawKey, Secret: bytes.Repeat([]byte{42}, 32)}
}

func encryptBytes(t *testing.T, p []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Encrypt(&out, bytes.NewReader(p), rawCredential()); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestRoundTripAndFraming(t *testing.T) {
	cases := [][]byte{nil, []byte("ASCII"), []byte("こんにちは 🌍"), {0, 1, 0, 255}}
	for _, n := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 2*ChunkSize - 1, 2 * ChunkSize, 2*ChunkSize + 1} {
		p := make([]byte, n)
		for i := range p {
			p[i] = byte(i*73 + 17)
		}
		cases = append(cases, p)
	}
	for i, p := range cases {
		t.Run(fmt.Sprintf("case%d_len%d", i, len(p)), func(t *testing.T) {
			wire := encryptBytes(t, p)
			wantSize := 64 + len(p) + 21*(len(p)/ChunkSize+1)
			if len(wire) != wantSize {
				t.Fatalf("size %d, want %d", len(wire), wantSize)
			}
			// Parse independently, without calling production header/record helpers.
			if string(wire[:8]) != "GFILEENC" || wire[8] != 1 || wire[9] != 1 || binary.BigEndian.Uint32(wire[10:14]) != 65536 {
				t.Fatal("header")
			}
			pos := 64
			for record := 0; record <= len(p)/ChunkSize; record++ {
				n := int(binary.BigEndian.Uint32(wire[pos : pos+4]))
				flag := wire[pos+4]
				if record < len(p)/ChunkSize {
					if n != ChunkSize || flag != 0 {
						t.Fatal("full record shape")
					}
				} else if n != len(p)%ChunkSize || flag != 1 {
					t.Fatal("final record shape")
				}
				pos += 5 + n + 16
			}
			if pos != len(wire) {
				t.Fatal("trailing data")
			}
			var restored bytes.Buffer
			if err := Decrypt(&restored, bytes.NewReader(wire), rawCredential()); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(restored.Bytes(), p) {
				t.Fatal("round trip mismatch")
			}
		})
	}
}

func TestFreshSalt(t *testing.T) {
	a, b := encryptBytes(t, []byte("same")), encryptBytes(t, []byte("same"))
	if bytes.Equal(a[14:46], b[14:46]) || bytes.Equal(a[69:], b[69:]) {
		t.Fatal("reused randomness/ciphertext")
	}
	for _, wire := range [][]byte{a, b} {
		var out bytes.Buffer
		if err := Decrypt(&out, bytes.NewReader(wire), rawCredential()); err != nil || out.String() != "same" {
			t.Fatalf("decrypt: %v", err)
		}
	}
}

func TestCredentialValidation(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		if err := (Credential{RawKey, make([]byte, n)}).Validate(); err == nil {
			t.Fatalf("accepted key length %d", n)
		}
	}
	for _, n := range []int{0, 1025} {
		if err := (Credential{Password, make([]byte, n)}).Validate(); err == nil {
			t.Fatalf("accepted password length %d", n)
		}
	}
	for _, c := range []Credential{{RawKey, bytes.Repeat([]byte(" \t\n\r"), 8)}, {Password, []byte("\n")}, {Password, make([]byte, 1024)}} {
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if err := (Credential{Mode: 3}).Validate(); err == nil {
		t.Fatal("invalid mode")
	}
	for _, fn := range []func(io.Writer, io.Reader, Credential) error{Encrypt, Decrypt} {
		if err := fn(io.Discard, strings.NewReader(""), Credential{RawKey, nil}); err == nil {
			t.Fatal("invalid credential reached codec")
		}
	}
}

func TestPasswordMode(t *testing.T) {
	c := Credential{Password, []byte("test-only-password\n")}
	plain := []byte("password mode\x00payload")
	var out bytes.Buffer
	if err := Encrypt(&out, bytes.NewReader(plain), c); err != nil {
		t.Fatal(err)
	}
	if out.Bytes()[9] != 2 {
		t.Fatal("password header")
	}
	var restored bytes.Buffer
	if err := Decrypt(&restored, bytes.NewReader(out.Bytes()), c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Bytes(), plain) {
		t.Fatal("password round trip")
	}
	// Omitting the newline is a different password, not a normalized equivalent.
	wrong := Credential{Password, []byte("test-only-password")}
	if err := Decrypt(io.Discard, bytes.NewReader(out.Bytes()), wrong); !errors.Is(err, errAuthentication) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := Decrypt(io.Discard, bytes.NewReader(out.Bytes()), rawCredential()); err == nil {
		t.Fatal("mode mismatch")
	}
}

func TestDerivationSeparation(t *testing.T) {
	root, salt := rawCredential().Secret, bytes.Repeat([]byte{9}, 32)
	a, err := deriveFileKey(root, salt)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := deriveFileKey(root, salt)
	if !bytes.Equal(a, b) {
		t.Fatal("nondeterministic derivation")
	}
	otherSalt := bytes.Clone(salt)
	otherSalt[0]++
	b, _ = deriveFileKey(root, otherSalt)
	if bytes.Equal(a, b) {
		t.Fatal("salt separation")
	}
	b, _ = hkdf.Key(sha256.New, root, salt, "filecrypt/v1/other", 32)
	if bytes.Equal(a, b) {
		t.Fatal("purpose separation")
	}
	zero, _ := deriveChunkKey(a, 0)
	again, _ := deriveChunkKey(a, 0)
	one, _ := deriveChunkKey(a, 1)
	if !bytes.Equal(zero, again) || bytes.Equal(zero, one) || bytes.Equal(a, zero) {
		t.Fatal("index/parent separation")
	}
}

func TestWireFixture(t *testing.T) {
	encoded, err := os.ReadFile("testdata/raw-v1.hex")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	salt := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
		salt[i] = byte(32 + i)
	}
	plain := []byte("filecrypt\x00v1\n")
	if len(wire) != 98 || string(wire[:8]) != "GFILEENC" || wire[8] != 1 || wire[9] != 1 || binary.BigEndian.Uint32(wire[10:14]) != 65536 || !bytes.Equal(wire[14:46], salt) || !bytes.Equal(wire[46:64], make([]byte, 18)) {
		t.Fatal("fixture header/size")
	}
	if !bytes.Equal(wire[64:69], []byte{0, 0, 0, 13, 1}) {
		t.Fatal("fixture framing")
	}
	// Independent construction: literal labels and AAD, no production helpers.
	fk, err := hkdf.Key(sha256.New, master, salt, "filecrypt/v1/file", 32)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := hkdf.Key(sha256.New, fk, nil, "filecrypt/v1/chunk/\x00\x00\x00\x00\x00\x00\x00\x00", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(ck)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	aad := append(bytes.Clone(wire[:64]), make([]byte, 8)...)
	aad = append(aad, wire[64:69]...)
	got, err := gcm.Open(nil, make([]byte, 12), wire[69:], aad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("independent fixture authentication: %v", err)
	}
	for _, pos := range []int{14, 64, 72} {
		bad := bytes.Clone(aad)
		bad[pos] ^= 1
		if _, err := gcm.Open(nil, make([]byte, 12), wire[69:], bad); err == nil {
			t.Fatalf("AAD byte %d not bound", pos)
		}
	}
	o := defaults()
	o.random = bytes.NewReader(salt)
	var generated bytes.Buffer
	if err := encrypt(&generated, bytes.NewReader(plain), Credential{RawKey, master}, o); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated.Bytes(), wire) {
		t.Fatal("encoder differs from checked fixture")
	}
	var restored bytes.Buffer
	if err := Decrypt(&restored, bytes.NewReader(wire), Credential{RawKey, master}); err != nil || !bytes.Equal(restored.Bytes(), plain) {
		t.Fatalf("decode fixture: %v", err)
	}
}

// malformedCases is shared by stream rejection tests; CLI tests exercise the
// same attack families through real staged files and verify no publication.
func malformedCases(t *testing.T) map[string][]byte {
	t.Helper()
	p := make([]byte, 3*ChunkSize+7)
	for i := range p {
		p[i] = byte(i/ChunkSize + 1)
	}
	wire := encryptBytes(t, p)
	other := encryptBytes(t, p)
	width := ChunkSize + 21
	first := wire[64 : 64+width]
	second := wire[64+width : 64+2*width]
	third := wire[64+2*width : 64+3*width]
	final := wire[64+3*width:]
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	cases := map[string][]byte{
		"missing-final":  bytes.Clone(wire[:64+3*width]),
		"missing-middle": join(wire[:64], first, third, final),
		"reorder":        join(wire[:64], second, first, third, final),
		"duplicate":      join(wire[:64], first, second, second, third, final),
		"substitute":     join(wire[:64], first, other[64+width:64+2*width], third, final),
		"append-byte":    join(wire, []byte{0}),
		"append-record":  join(wire, final),
		"append-file":    join(wire, other),
	}
	for name, pos := range map[string]int{"magic": 0, "version": 8, "mode": 9, "chunk-size": 10, "salt": 14, "raw-time": 46, "raw-memory": 50, "raw-parallelism": 54, "reserved": 55, "ciphertext": 69, "tag": 64 + width - 1, "flags": 68, "length": 64, "final-flag": 64 + 3*width + 4, "final-length": 64 + 3*width + 3} {
		bad := bytes.Clone(wire)
		bad[pos] ^= 128
		cases[name] = bad
	}
	bad := bytes.Clone(wire)
	bad[9] = 2
	cases["valid-mode-invalid-profile"] = bad
	bad = bytes.Clone(wire)
	binary.BigEndian.PutUint32(bad[64:68], 0)
	cases["short-nonfinal"] = bad
	bad = bytes.Clone(wire)
	binary.BigEndian.PutUint32(bad[64+3*width:64+3*width+4], ChunkSize)
	cases["full-final"] = bad
	for _, n := range []int{0, 1, 8, 63, 64, 65, 68, 69, 70, 64 + width - 1, len(wire) - 1} {
		cases[fmt.Sprintf("truncated-%d", n)] = bytes.Clone(wire[:n])
	}
	return cases
}

func TestMalformedAndTamperedStreams(t *testing.T) {
	for name, wire := range malformedCases(t) {
		t.Run(name, func(t *testing.T) {
			if err := Decrypt(io.Discard, bytes.NewReader(wire), rawCredential()); err == nil {
				t.Fatal("accepted invalid file")
			}
		})
	}
	wrong := Credential{RawKey, bytes.Repeat([]byte{99}, 32)}
	if err := Decrypt(io.Discard, bytes.NewReader(encryptBytes(t, []byte("secret"))), wrong); !errors.Is(err, errAuthentication) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestHeaderRejectedBeforeKDF(t *testing.T) {
	c := Credential{Password, []byte("test")}
	base := newHeader(Password)
	for _, pos := range []int{0, 8, 9, 10, 46, 50, 54, 55} {
		h := base
		h[pos] ^= 128
		o := defaults()
		o.passwordKey = func([]byte, []byte, uint32, uint32, uint8, uint32) []byte {
			t.Fatal("KDF invoked for invalid header")
			return nil
		}
		if err := decrypt(io.Discard, bytes.NewReader(h[:]), c, o); err == nil {
			t.Fatalf("accepted invalid field at %d", pos)
		}
	}
	// A valid mode change/profile still cannot bypass credential-mode validation.
	h := newHeader(RawKey)
	o := defaults()
	o.passwordKey = func([]byte, []byte, uint32, uint32, uint8, uint32) []byte {
		t.Fatal("KDF invoked for mode mismatch")
		return nil
	}
	if err := decrypt(io.Discard, bytes.NewReader(h[:]), c, o); err == nil {
		t.Fatal("mode mismatch")
	}
}

func TestPasswordKDFOnce(t *testing.T) {
	o := defaults()
	calls := 0
	o.passwordKey = func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
		calls++
		if time != 3 || memory != 65536 || threads != 4 || keyLen != 32 || len(salt) != 32 {
			t.Fatal("wrong KDF profile")
		}
		return bytes.Repeat([]byte{7}, 32)
	}
	c := Credential{Password, []byte("test")}
	var wire bytes.Buffer
	if err := encrypt(&wire, bytes.NewReader(make([]byte, 2*ChunkSize+1)), c, o); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("encryption KDF calls %d", calls)
	}
	if err := decrypt(io.Discard, bytes.NewReader(wire.Bytes()), c, o); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("decryption KDF calls %d", calls)
	}
}

func TestSizeLimit(t *testing.T) {
	for _, limit := range []uint64{0, ChunkSize, ChunkSize + 3} {
		for _, extra := range []int{0, 1} {
			p := make([]byte, int(limit)+extra)
			o := defaults()
			o.limit = limit
			var wire bytes.Buffer
			err := encrypt(&wire, bytes.NewReader(p), rawCredential(), o)
			if (err == nil) != (extra == 0) {
				t.Fatalf("encrypt limit %d extra %d: %v", limit, extra, err)
			}
			full := encryptBytes(t, p)
			err = decrypt(io.Discard, bytes.NewReader(full), rawCredential(), o)
			if (err == nil) != (extra == 0) {
				t.Fatalf("decrypt limit %d extra %d: %v", limit, extra, err)
			}
		}
	}
	if n, err := addSize(MaxPlaintextSize, 0, MaxPlaintextSize); err != nil || n != MaxPlaintextSize {
		t.Fatal("exact limit")
	}
	for _, tc := range [][3]uint64{{MaxPlaintextSize, 1, MaxPlaintextSize}, {math.MaxUint64, 1, math.MaxUint64}, {math.MaxUint64, 1, MaxPlaintextSize}} {
		if _, err := addSize(tc[0], tc[1], tc[2]); err == nil {
			t.Fatal("counter overflow/limit accepted")
		}
	}
}

type generatedReader struct {
	remaining int64
	maxRead   int
}

func (r *generatedReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRead {
		r.maxRead = len(p)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), r.remaining))
	clear(p[:n])
	r.remaining -= int64(n)
	return n, nil
}

type countingWriter struct {
	n        int64
	maxWrite int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	w.maxWrite = max(w.maxWrite, len(p))
	return len(p), nil
}

func TestBoundedStreaming(t *testing.T) {
	const size = 32*1024*1024 + 1
	r := &generatedReader{remaining: size}
	w := &countingWriter{}
	if err := Encrypt(w, r, rawCredential()); err != nil {
		t.Fatal(err)
	}
	if r.maxRead > ChunkSize || w.maxWrite > ChunkSize+TagSize || w.n != 64+size+21*(size/ChunkSize+1) {
		t.Fatalf("unbounded read/write or wrong size: %+v %+v", r, w)
	}
	// Connect the codecs with a pipe; neither the source nor sink stores the file.
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := Encrypt(writer, &generatedReader{remaining: size}, rawCredential())
		writer.CloseWithError(err)
		done <- err
	}()
	w = &countingWriter{}
	err := Decrypt(w, reader, rawCredential())
	reader.CloseWithError(err)
	encErr := <-done
	if err != nil || encErr != nil || w.n != size || w.maxWrite > ChunkSize {
		t.Fatalf("stream: %v %v %+v", err, encErr, w)
	}
}

var errInjected = errors.New("injected I/O failure")

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errInjected }

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errInjected }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestIOFailures(t *testing.T) {
	for _, n := range []int{0, 3, ChunkSize + 3} {
		r := io.MultiReader(bytes.NewReader(make([]byte, n)), errorReader{})
		if err := Encrypt(io.Discard, r, rawCredential()); !errors.Is(err, errInjected) {
			t.Fatalf("partial read %d: %v", n, err)
		}
	}
	wire := encryptBytes(t, []byte("a"))
	if err := Decrypt(io.Discard, io.MultiReader(bytes.NewReader(wire), errorReader{}), rawCredential()); !errors.Is(err, errInjected) {
		t.Fatalf("trailing read error: %v", err)
	}
	for _, w := range []io.Writer{errorWriter{}, shortWriter{}} {
		if err := Encrypt(w, strings.NewReader("a"), rawCredential()); err == nil {
			t.Fatal("encrypt write error")
		}
		if err := Decrypt(w, bytes.NewReader(wire), rawCredential()); err == nil {
			t.Fatal("decrypt write error")
		}
	}
	o := defaults()
	o.random = errorReader{}
	if err := encrypt(io.Discard, strings.NewReader(""), rawCredential(), o); !errors.Is(err, errInjected) {
		t.Fatalf("random failure: %v", err)
	}
}
