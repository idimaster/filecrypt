//go:build ignore

// This standalone fixture generator deliberately imports no production code.
// Run from the repository root: go run internal/filecrypt/testdata/generate.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {
	master := decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	salt := decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	header := decode("4746494c45454e43010100010000" + hex.EncodeToString(salt) + "000000000000000000000000000000000000")
	record := decode("0000000d01")
	index := decode("0000000000000000")
	fileKey, err := hkdf.Key(sha256.New, master, salt, "filecrypt/v1/file", 32)
	check(err)
	chunkKey, err := hkdf.Key(sha256.New, fileKey, nil, "filecrypt/v1/chunk/"+string(index), 32)
	check(err)
	block, err := aes.NewCipher(chunkKey)
	check(err)
	gcm, err := cipher.NewGCM(block)
	check(err)
	aad := append(append(append([]byte{}, header...), index...), record...)
	ciphertext := gcm.Seal(nil, make([]byte, 12), []byte("filecrypt\x00v1\n"), aad)
	fmt.Printf("%x\n", append(append(header, record...), ciphertext...))
}

func decode(s string) []byte { b, err := hex.DecodeString(s); check(err); return b }
func check(err error) {
	if err != nil {
		panic(err)
	}
}
