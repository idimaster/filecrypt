// Package filecrypt implements the educational version-1 streaming format.
// It does not publish files; callers must stage output until the entire operation succeeds.
package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ChunkSize               = 65536
	HeaderSize              = 64
	TagSize                 = 16
	MaxPlaintextSize uint64 = 1 << 40
	fileLabel               = "filecrypt/v1/file"
	chunkLabel              = "filecrypt/v1/chunk/"
)

type Mode byte

const (
	RawKey   Mode = 1
	Password Mode = 2
)

// Credential contains literal file bytes. No normalization is performed.
type Credential struct {
	Mode   Mode
	Secret []byte
}

func (c Credential) Validate() error {
	switch c.Mode {
	case RawKey:
		if len(c.Secret) != 32 {
			return errors.New("key file must contain exactly 32 raw bytes")
		}
	case Password:
		if len(c.Secret) < 1 || len(c.Secret) > 1024 {
			return errors.New("password file must contain 1 through 1024 bytes")
		}
	default:
		return errors.New("invalid credential mode")
	}
	return nil
}

type header [HeaderSize]byte
type recordHeader [5]byte

func newHeader(mode Mode) header {
	var h header
	copy(h[:8], "GFILEENC")
	h[8], h[9] = 1, byte(mode)
	binary.BigEndian.PutUint32(h[10:14], ChunkSize)
	if mode == Password {
		binary.BigEndian.PutUint32(h[46:50], 3)
		binary.BigEndian.PutUint32(h[50:54], 65536)
		h[54] = 4
	}
	return h
}

func (h *header) validate(mode Mode) error {
	if string(h[:8]) != "GFILEENC" {
		return errors.New("invalid file magic")
	}
	if h[8] != 1 {
		return errors.New("unsupported format version")
	}
	if Mode(h[9]) != RawKey && Mode(h[9]) != Password {
		return errors.New("invalid header credential mode")
	}
	if binary.BigEndian.Uint32(h[10:14]) != ChunkSize {
		return errors.New("invalid chunk size")
	}
	for _, b := range h[55:] {
		if b != 0 {
			return errors.New("nonzero reserved header field")
		}
	}
	time, memory, parallelism := binary.BigEndian.Uint32(h[46:50]), binary.BigEndian.Uint32(h[50:54]), h[54]
	if Mode(h[9]) == RawKey {
		if time != 0 || memory != 0 || parallelism != 0 {
			return errors.New("invalid raw-key KDF profile")
		}
	} else if time != 3 || memory != 65536 || parallelism != 4 {
		return errors.New("unsupported password KDF profile")
	}
	if Mode(h[9]) != mode {
		return errors.New("credential mode does not match file header")
	}
	return nil
}

func (r *recordHeader) parse() (n int, final bool, err error) {
	length := binary.BigEndian.Uint32(r[:4])
	switch r[4] {
	case 0:
		if length != ChunkSize {
			return 0, false, errors.New("non-final record must contain one full chunk")
		}
	case 1:
		if length >= ChunkSize {
			return 0, false, errors.New("invalid final record length")
		}
	default:
		return 0, false, errors.New("invalid record flags")
	}
	return int(length), r[4] == 1, nil
}

func deriveFileKey(root, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, root, salt, fileLabel, 32)
}

func deriveChunkKey(fileKey []byte, index uint64) ([]byte, error) {
	var info [len(chunkLabel) + 8]byte
	copy(info[:], chunkLabel)
	binary.BigEndian.PutUint64(info[len(chunkLabel):], index)
	return hkdf.Key(sha256.New, fileKey, nil, string(info[:]), 32)
}

func recordAEAD(fileKey []byte, index uint64) (cipher.AEAD, error) {
	key, err := deriveChunkKey(fileKey, index)
	if err != nil {
		return nil, fmt.Errorf("derive chunk key: %w", err)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize AES: %w", err)
	}
	return cipher.NewGCM(block)
}

func additionalData(h *header, index uint64, r *recordHeader) [HeaderSize + 8 + 5]byte {
	var aad [HeaderSize + 8 + 5]byte
	copy(aad[:HeaderSize], h[:])
	binary.BigEndian.PutUint64(aad[HeaderSize:HeaderSize+8], index)
	copy(aad[HeaderSize+8:], r[:])
	return aad
}

func addSize(total, n, limit uint64) (uint64, error) {
	if total > limit || n > limit-total {
		return total, errors.New("plaintext exceeds size limit (maximum 1 TiB)")
	}
	return total + n, nil
}
