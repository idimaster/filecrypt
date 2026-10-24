package cli

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filecrypt/internal/filecrypt"
)

func invoke(t *testing.T, want int, args ...string) (string, string) {
	t.Helper()
	var out, err bytes.Buffer
	status := Run(args, &out, &err)
	if status != want {
		t.Fatalf("status %d want %d; stderr: %s", status, want, err.String())
	}
	if want != 0 && err.Len() == 0 {
		t.Fatal("missing error diagnostic")
	}
	return out.String(), err.String()
}

func put(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
func get(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected published output %s: %v", path, err)
	}
}
func noStage(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".filecrypt-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("staging files: %v %v", matches, err)
	}
}

func TestUsageAndHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"keygen", "--help"}, {"encrypt", "--help"}, {"decrypt", "-h"}} {
		out, err := invoke(t, 0, args...)
		if !strings.Contains(out, "including any newline") || err != "" {
			t.Fatal("help must explain literal password bytes")
		}
	}
	for i, args := range [][]string{
		nil, {"unknown"}, {"--bad"}, {"keygen"}, {"keygen", "--out"}, {"keygen", "--out", "x", "extra"}, {"keygen", "--unknown"},
		{"encrypt"}, {"decrypt", "--in", "a", "--out", "b"}, {"encrypt", "--in", "a", "--out", "b", "--key-file", "c", "--password-file", "d"},
		{"encrypt", "--in", "a", "--out", "b", "--key-file", "c", "--password-file="}, {"encrypt", "--in", "a", "--out", "b", "--key-file="},
		{"encrypt", "--in", "a", "--out", "b", "--password-file", "p", "extra"}, {"decrypt", "--key-file"}, {"keygen", "--out", "x", "--key-file", "k"},
		{"encrypt", "--unknown=known-test-secret"},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			out, err := invoke(t, 2, args...)
			if out != "" || strings.Contains(err, "known-test-secret") {
				t.Fatal("invalid diagnostic output")
			}
		})
	}
}

func TestCLIEndToEnd(t *testing.T) {
	dir := t.TempDir()
	key, in, encrypted, restored := filepath.Join(dir, "key"), filepath.Join(dir, "input"), filepath.Join(dir, "encrypted"), filepath.Join(dir, "restored")
	plain := append([]byte("synthetic Unicode π\x00\n"), bytes.Repeat([]byte{93}, filecrypt.ChunkSize+1)...)
	put(t, in, plain)
	invoke(t, 0, "keygen", "--out", key)
	if len(get(t, key)) != 32 {
		t.Fatal("key size")
	}
	invoke(t, 0, "encrypt", "--in", in, "--out", encrypted, "--key-file", key)
	out, diagnostics := invoke(t, 0, "decrypt", "--in", encrypted, "--out", restored, "--key-file", key)
	if out != "" || diagnostics != "" || !bytes.Equal(get(t, restored), plain) || !bytes.Equal(get(t, in), plain) {
		t.Fatal("round trip changed content/output")
	}
	for _, path := range []string{key, encrypted, restored} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("output permissions: %v %v", info, err)
		}
	}
	// Existing output and its original bytes survive a second attempt.
	before := get(t, encrypted)
	invoke(t, 1, "encrypt", "--in", in, "--out", encrypted, "--key-file", key)
	if !bytes.Equal(get(t, encrypted), before) {
		t.Fatal("replaced output")
	}
	invoke(t, 1, "keygen", "--out", key)
	noStage(t, dir)
}

func TestLiteralCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	key, password := filepath.Join(dir, "key"), filepath.Join(dir, "password")
	for _, n := range []int{0, 31, 33, 10000} {
		put(t, key, make([]byte, n))
		if _, err := readCredential(key, ""); err == nil {
			t.Fatalf("key length %d", n)
		}
	}
	literal := bytes.Repeat([]byte(" \t\r\n"), 8)
	put(t, key, literal)
	c, err := readCredential(key, "")
	if err != nil || !bytes.Equal(c.Secret, literal) {
		t.Fatalf("key normalized: %v", err)
	}
	for _, n := range []int{0, 1025, 10000} {
		put(t, password, make([]byte, n))
		if _, err := readCredential("", password); err == nil {
			t.Fatalf("password length %d", n)
		}
	}
	for _, b := range [][]byte{[]byte("test password\n"), {0}, make([]byte, 1024)} {
		put(t, password, b)
		c, err := readCredential("", password)
		if err != nil || !bytes.Equal(c.Secret, b) {
			t.Fatalf("password normalized: %v", err)
		}
	}
	if _, err := readCredential(dir, ""); err == nil {
		t.Fatal("directory credential")
	}
}

func TestCLIPasswordAndWhitespaceKey(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input")
	put(t, in, []byte("literal credentials payload"))
	for _, mode := range []string{"key-file", "password-file"} {
		credential, encrypted, restored := filepath.Join(dir, mode), filepath.Join(dir, mode+".fc"), filepath.Join(dir, mode+".out")
		secret := []byte("test-only password\n")
		if mode == "key-file" {
			secret = bytes.Repeat([]byte(" \t\r\n"), 8)
		}
		put(t, credential, secret)
		invoke(t, 0, "encrypt", "--in", in, "--out", encrypted, "--"+mode, credential)
		invoke(t, 0, "decrypt", "--in", encrypted, "--out", restored, "--"+mode, credential)
		if !bytes.Equal(get(t, in), get(t, restored)) || !bytes.Equal(get(t, credential), secret) {
			t.Fatal("credential round trip")
		}
	}
}

func TestProcessingErrors(t *testing.T) {
	dir := t.TempDir()
	key, in := filepath.Join(dir, "key"), filepath.Join(dir, "input")
	invoke(t, 0, "keygen", "--out", key)
	put(t, in, []byte("payload"))
	for i, args := range [][]string{
		{"encrypt", "--in", filepath.Join(dir, "missing"), "--key-file", key},
		{"encrypt", "--in", dir, "--key-file", key},
		{"encrypt", "--in", "/dev/null", "--key-file", key},
		{"encrypt", "--in", in, "--key-file", filepath.Join(dir, "missing")},
		{"decrypt", "--in", in, "--key-file", key},
		{"encrypt", "--in", in, "--password-file", dir},
	} {
		out := filepath.Join(dir, fmt.Sprintf("output-%d", i))
		args = append(args, "--out", out)
		invoke(t, 1, args...)
		absent(t, out)
		noStage(t, dir)
	}
	invoke(t, 1, "keygen", "--out", filepath.Join(dir, "missing", "output"))
	// Following regular-file input symlinks is supported.
	link := filepath.Join(dir, "input-link")
	if err := os.Symlink(in, link); err != nil {
		t.Fatal(err)
	}
	invoke(t, 0, "encrypt", "--in", link, "--out", filepath.Join(dir, "linked.fc"), "--key-file", key)
}

func TestStatusAfterOperation(t *testing.T) {
	for _, tc := range []struct {
		warning, err error
		status       int
	}{
		{nil, nil, 0}, {errors.New("temporary hard link remains"), nil, 0}, {nil, errors.New("injected read/write/close/publication failure"), 1},
	} {
		var out, diagnostics bytes.Buffer
		status := run([]string{"keygen", "--out", "unused"}, &out, &diagnostics, func(string, string, string, string, string) (error, error) { return tc.warning, tc.err })
		if status != tc.status || out.Len() != 0 {
			t.Fatalf("status/output: %d %s", status, out.String())
		}
		if tc.warning != nil && !strings.Contains(diagnostics.String(), "warning:") {
			t.Fatal("missing post-commit warning")
		}
	}
}

// Check the size of diagnostics, without accidentally logging the test secret.
func checkDiagnostic(t *testing.T, diagnostics string, secrets ...[]byte) {
	t.Helper()
	for _, secret := range secrets {
		if len(secret) != 0 && strings.Contains(diagnostics, string(secret)) {
			t.Fatal("diagnostics exposed secret/plaintext")
		}
	}
}

func TestAliasesPreserveInputsAndCredentials(t *testing.T) {
	dir := t.TempDir()
	key, in, encrypted := filepath.Join(dir, "key"), filepath.Join(dir, "input"), filepath.Join(dir, "encrypted")
	put(t, key, bytes.Repeat([]byte("k"), 32))
	put(t, in, []byte("original input"))
	invoke(t, 0, "encrypt", "--in", in, "--out", encrypted, "--key-file", key)
	for _, command := range []string{"encrypt", "decrypt"} {
		source := in
		if command == "decrypt" {
			source = encrypted
		}
		for _, target := range []string{source, key} {
			for _, kind := range []string{"direct", "symlink", "hardlink"} {
				t.Run(command+"/"+filepath.Base(target)+"/"+kind, func(t *testing.T) {
					beforeSource, beforeKey := get(t, source), get(t, key)
					out := target
					if kind != "direct" {
						out = filepath.Join(t.TempDir(), "alias")
						var err error
						if kind == "symlink" {
							err = os.Symlink(target, out)
						} else {
							err = os.Link(target, out)
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					invoke(t, 1, command, "--in", source, "--out", out, "--key-file", key)
					if !bytes.Equal(get(t, source), beforeSource) || !bytes.Equal(get(t, key), beforeKey) {
						t.Fatal("alias modified input/credential")
					}
					noStage(t, dir)
				})
			}
		}
	}
}

func TestDecryptionFailuresNeverPublish(t *testing.T) {
	dir := t.TempDir()
	key, input := filepath.Join(dir, "key"), filepath.Join(dir, "input")
	secret := []byte("0123456789abcdef0123456789abcdef")
	put(t, key, secret)
	plain := append([]byte("known plaintext test secret"), make([]byte, 3*filecrypt.ChunkSize)...)
	var encoded, other bytes.Buffer
	c := filecrypt.Credential{Mode: filecrypt.RawKey, Secret: secret}
	if err := filecrypt.Encrypt(&encoded, bytes.NewReader(plain), c); err != nil {
		t.Fatal(err)
	}
	if err := filecrypt.Encrypt(&other, bytes.NewReader(plain), c); err != nil {
		t.Fatal(err)
	}
	wire := encoded.Bytes()
	width := filecrypt.ChunkSize + 21
	finalPos := 64 + 3*width
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	cases := map[string][]byte{
		"missing-final":  bytes.Clone(wire[:finalPos]),
		"missing-middle": join(wire[:64+width], wire[64+2*width:]),
		"reorder":        join(wire[:64], wire[64+width:64+2*width], wire[64:64+width], wire[64+2*width:]),
		"duplicate":      join(wire[:64+2*width], wire[64+width:64+2*width], wire[64+2*width:]),
		"substitute":     join(wire[:64+width], other.Bytes()[64+width:64+2*width], wire[64+2*width:]),
		"append-byte":    join(wire, []byte{1}),
		"append-record":  join(wire, wire[finalPos:]),
		"append-file":    join(wire, other.Bytes()),
	}
	for name, pos := range map[string]int{"magic": 0, "version": 8, "mode": 9, "chunk-size": 10, "salt": 14, "KDF": 46, "reserved": 63, "ciphertext": 64 + width + 5, "tag": finalPos - 1, "flags": 68, "length": 64, "final-flag": finalPos + 4, "final-length": finalPos + 3} {
		b := bytes.Clone(wire)
		b[pos] ^= 128
		cases[name] = b
	}
	b := bytes.Clone(wire)
	binary.BigEndian.PutUint32(b[finalPos:finalPos+4], filecrypt.ChunkSize)
	cases["full-final"] = b
	b = bytes.Clone(wire)
	binary.BigEndian.PutUint32(b[64:68], 1)
	cases["short-nonfinal"] = b
	for _, n := range []int{0, 1, 63, 64, 66, 68, 69, 70, len(wire) - 1} {
		cases[fmt.Sprintf("truncate-%d", n)] = bytes.Clone(wire[:n])
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			put(t, input, b)
			out := filepath.Join(dir, "output")
			_, diagnostics := invoke(t, 1, "decrypt", "--in", input, "--out", out, "--key-file", key)
			checkDiagnostic(t, diagnostics, secret, []byte("known plaintext test secret"))
			absent(t, out)
			noStage(t, dir)
		})
	}
	put(t, input, wire)
	put(t, key, bytes.Repeat([]byte("w"), 32))
	out := filepath.Join(dir, "wrong-key-output")
	_, diagnostics := invoke(t, 1, "decrypt", "--in", input, "--out", out, "--key-file", key)
	if !strings.Contains(diagnostics, "decryption failed: wrong credential or damaged file") {
		t.Fatal("wrong authentication diagnostic")
	}
	checkDiagnostic(t, diagnostics, secret, []byte("known plaintext test secret"))
	absent(t, out)
	noStage(t, dir)
	// Credential shape errors are processing failures, rather than usage failures.
	put(t, key, []byte("short"))
	invoke(t, 1, "decrypt", "--in", input, "--out", out, "--key-file", key)
	absent(t, out)
	password := filepath.Join(dir, "password")
	put(t, password, []byte("test password\n"))
	invoke(t, 1, "decrypt", "--in", input, "--out", out, "--password-file", password)
	absent(t, out)
}
