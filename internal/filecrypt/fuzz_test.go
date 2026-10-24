package filecrypt

import (
	"bytes"
	"io"
	"testing"
)

func FuzzDecrypt(f *testing.F) {
	var wire bytes.Buffer
	if err := Encrypt(&wire, bytes.NewReader([]byte("seed")), rawCredential()); err != nil {
		f.Fatal(err)
	}
	f.Add(wire.Bytes())
	f.Add([]byte{})
	f.Add([]byte("GFILEENC"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4*ChunkSize {
			t.Skip()
		}
		// Raw credential mode rejects password headers before any Argon2 work.
		_ = Decrypt(io.Discard, bytes.NewReader(b), rawCredential())
	})
}

func FuzzParse(f *testing.F) {
	h := newHeader(RawKey)
	f.Add(h[:], []byte{0, 1, 0, 0, 0})
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, hb, rb []byte) {
		if len(hb) == HeaderSize {
			var h header
			copy(h[:], hb)
			_ = h.validate(RawKey)
		}
		if len(rb) == 5 {
			var r recordHeader
			copy(r[:], rb)
			n, _, err := r.parse()
			if err == nil && (n < 0 || n > ChunkSize) {
				t.Fatal("unbounded record")
			}
		}
	})
}
