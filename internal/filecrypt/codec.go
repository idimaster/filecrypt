package filecrypt

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

var errAuthentication = errors.New("decryption failed: wrong credential or damaged file")

// options is a per-operation test seam. Production entry points always use defaults.
type options struct {
	random      io.Reader
	limit       uint64
	passwordKey func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte
}

func defaults() options {
	return options{random: rand.Reader, limit: MaxPlaintextSize, passwordKey: argon2.IDKey}
}

func fileKey(c Credential, h *header, o options) ([]byte, error) {
	root := c.Secret
	if c.Mode == Password {
		// The header was validated against the fixed profile before reaching here.
		root = o.passwordKey(c.Secret, h[14:46], 3, 65536, 4, 32)
		defer clear(root)
	}
	return deriveFileKey(root, h[14:46])
}

// Encrypt streams input to output. The caller must discard output on any error.
func Encrypt(dst io.Writer, src io.Reader, c Credential) error {
	return encrypt(dst, src, c, defaults())
}

func encrypt(dst io.Writer, src io.Reader, c Credential, o options) error {
	if err := c.Validate(); err != nil {
		return err
	}
	h := newHeader(c.Mode)
	if _, err := io.ReadFull(o.random, h[14:46]); err != nil {
		return fmt.Errorf("generate file salt: %w", err)
	}
	key, err := fileKey(c, &h, o)
	if err != nil {
		return fmt.Errorf("derive file key: %w", err)
	}
	defer clear(key)
	if err := writeAll(dst, h[:]); err != nil {
		return err
	}
	buf := make([]byte, ChunkSize+TagSize)
	defer clear(buf)
	var total, index uint64
	var nonce [12]byte
	for {
		n, readErr := io.ReadFull(src, buf[:ChunkSize])
		final := false
		switch readErr {
		case nil:
		case io.EOF, io.ErrUnexpectedEOF:
			final = true
		default:
			return fmt.Errorf("read input: %w", readErr)
		}
		total, err = addSize(total, uint64(n), o.limit)
		if err != nil {
			return err
		}
		var r recordHeader
		binary.BigEndian.PutUint32(r[:4], uint32(n))
		if final {
			r[4] = 1
		}
		aead, err := recordAEAD(key, index)
		if err != nil {
			return err
		}
		aad := additionalData(&h, index, &r)
		// In-place Seal uses the unique key for this index exactly once.
		ciphertext := aead.Seal(buf[:0], nonce[:], buf[:n], aad[:])
		if err := writeAll(dst, r[:]); err != nil {
			return err
		}
		if err := writeAll(dst, ciphertext); err != nil {
			return err
		}
		if final {
			return nil
		}
		// The plaintext limit caps the number of records far below uint64 overflow.
		index++
	}
}

// Decrypt writes authenticated records, but success requires an authenticated end
// and actual EOF. The caller must keep all output private until success.
func Decrypt(dst io.Writer, src io.Reader, c Credential) error {
	return decrypt(dst, src, c, defaults())
}

func decrypt(dst io.Writer, src io.Reader, c Credential, o options) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var h header
	if _, err := io.ReadFull(src, h[:]); err != nil {
		return fmt.Errorf("read file header: %w", err)
	}
	if err := h.validate(c.Mode); err != nil {
		return err
	}
	key, err := fileKey(c, &h, o)
	if err != nil {
		return fmt.Errorf("derive file key: %w", err)
	}
	defer clear(key)
	buf := make([]byte, ChunkSize+TagSize)
	defer clear(buf)
	var total, index uint64
	var nonce [12]byte
	for {
		var r recordHeader
		if _, err := io.ReadFull(src, r[:]); err != nil {
			return fmt.Errorf("read record header (final record required): %w", err)
		}
		n, final, err := r.parse()
		if err != nil {
			return err
		}
		total, err = addSize(total, uint64(n), o.limit)
		if err != nil {
			return err
		}
		if _, err := io.ReadFull(src, buf[:n+TagSize]); err != nil {
			return fmt.Errorf("read record ciphertext: %w", err)
		}
		aead, err := recordAEAD(key, index)
		if err != nil {
			return err
		}
		aad := additionalData(&h, index, &r)
		plaintext, err := aead.Open(buf[:0], nonce[:], buf[:n+TagSize], aad[:])
		if err != nil {
			return errAuthentication
		}
		if err := writeAll(dst, plaintext); err != nil {
			return err
		}
		if final {
			var trailing [1]byte
			n, err := io.ReadFull(src, trailing[:])
			if n != 0 {
				return errors.New("unexpected data after final record")
			}
			if err != io.EOF {
				return fmt.Errorf("check end of input: %w", err)
			}
			return nil
		}
		index++
	}
}

func writeAll(dst io.Writer, p []byte) error {
	n, err := dst.Write(p)
	if err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if n != len(p) {
		return fmt.Errorf("write output: %w", io.ErrShortWrite)
	}
	return nil
}
