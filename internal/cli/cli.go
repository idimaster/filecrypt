// Package cli provides the testable CLI boundary and operation orchestration.
package cli

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"

	"filecrypt/internal/filecrypt"
	"filecrypt/internal/fileio"
)

const help = `Usage:
  filecrypt keygen --out FILE
  filecrypt encrypt --in FILE --out FILE (--key-file FILE | --password-file FILE)
  filecrypt decrypt --in FILE --out FILE (--key-file FILE | --password-file FILE)

Outputs must not exist. Input and credential paths must resolve to regular files.
Key files contain exactly 32 raw bytes. Password files contain 1 through 1024
literal bytes, including any newline; bytes are never trimmed or normalized.
Secrets are accepted only through files, never command arguments or environment.
Use --help with any command. Requires macOS/Linux and same-directory hard links.
`

// Run returns the process exit status. Payloads never go to stdout.
func Run(args []string, stdout, stderr io.Writer) int {
	return run(args, stdout, stderr, execute)
}

func run(args []string, stdout, stderr io.Writer, operation func(string, string, string, string, string) (error, error)) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "-help") {
		fmt.Fprint(stdout, help)
		return 0
	}
	if len(args) == 0 {
		fmt.Fprint(stderr, help)
		return 2
	}
	command := args[0]
	if command != "keygen" && command != "encrypt" && command != "decrypt" {
		fmt.Fprintln(stderr, "unknown command")
		return 2
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	// Flag errors can echo untrusted arguments. Emit a bounded diagnostic instead.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	out := fs.String("out", "", "new output path")
	var in, keyPath, passwordPath string
	if command != "keygen" {
		fs.StringVar(&in, "in", "", "input path")
		fs.StringVar(&keyPath, "key-file", "", "32 raw credential bytes")
		fs.StringVar(&passwordPath, "password-file", "", "literal password bytes, including newline")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, help)
			return 0
		}
		fmt.Fprintln(stderr, "invalid command arguments; use --help")
		return 2
	}
	if fs.NArg() != 0 || *out == "" || (command != "keygen" && (in == "" || (keyPath == "") == (passwordPath == ""))) {
		fmt.Fprintln(stderr, "missing required flags, conflicting credentials, or unexpected arguments; use --help")
		return 2
	}
	// Count explicitly supplied credential flags, even if one has an empty value.
	credentials := 0
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "key-file" || f.Name == "password-file" {
			credentials++
		}
	})
	if command != "keygen" && credentials != 1 {
		fmt.Fprintln(stderr, "supply exactly one credential file")
		return 2
	}
	warning, err := operation(command, in, *out, keyPath, passwordPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if warning != nil {
		fmt.Fprintln(stderr, "warning:", warning)
	}
	return 0
}

func execute(command, in, out, keyPath, passwordPath string) (warning, err error) {
	if command == "keygen" {
		var key [32]byte
		defer clear(key[:])
		if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
			return nil, fmt.Errorf("generate master key: %w", err)
		}
		return fileio.WriteNew(out, func(w io.Writer) error {
			n, err := w.Write(key[:])
			if err != nil {
				return err
			}
			if n != len(key) {
				return io.ErrShortWrite
			}
			return nil
		})
	}
	c, err := readCredential(keyPath, passwordPath)
	if err != nil {
		return nil, err
	}
	defer clear(c.Secret)
	input, info, err := fileio.OpenRegular(in)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	if command == "encrypt" && uint64(info.Size()) > filecrypt.MaxPlaintextSize {
		return nil, errors.New("plaintext exceeds size limit (maximum 1 TiB)")
	}
	return fileio.WriteNew(out, func(w io.Writer) error {
		if command == "encrypt" {
			return filecrypt.Encrypt(w, input, c)
		}
		return filecrypt.Decrypt(w, input, c)
	})
}

func readCredential(keyPath, passwordPath string) (filecrypt.Credential, error) {
	path, mode, bound := keyPath, filecrypt.RawKey, int64(33)
	if passwordPath != "" {
		path, mode, bound = passwordPath, filecrypt.Password, 1025
	}
	f, _, err := fileio.OpenRegular(path)
	if err != nil {
		return filecrypt.Credential{}, fmt.Errorf("credential file: %w", err)
	}
	// Only credential bytes use ReadAll, bounded independently of file size.
	secret, readErr := io.ReadAll(io.LimitReader(f, bound))
	closeErr := f.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		clear(secret)
		return filecrypt.Credential{}, fmt.Errorf("read credential file: %w", err)
	}
	c := filecrypt.Credential{Mode: mode, Secret: secret}
	if err := c.Validate(); err != nil {
		clear(secret)
		return filecrypt.Credential{}, err
	}
	return c, nil
}
