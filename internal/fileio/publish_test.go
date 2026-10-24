package fileio

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requireNoStage(t *testing.T, dir string) {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(dir, ".filecrypt-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("leftover staging files: %v", entries)
	}
}

func TestWriteNew(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "output")
	warning, err := WriteNew(destination, func(w io.Writer) error {
		if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("published before commit")
		}
		f := w.(stagedFile)
		info, err := os.Stat(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("staging permissions %o", info.Mode().Perm())
		}
		_, err = io.WriteString(w, "complete output")
		return err
	})
	if warning != nil || err != nil {
		t.Fatalf("write: %v %v", warning, err)
	}
	b, err := os.ReadFile(destination)
	if err != nil || string(b) != "complete output" {
		t.Fatalf("contents: %q %v", b, err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions: %v %v", info, err)
	}
	requireNoStage(t, dir)
}

func TestExistingDestinations(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink", "dangling-symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			dst := filepath.Join(dir, "output")
			if err := os.WriteFile(target, []byte("preserve"), 0o640); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "file":
				err = os.WriteFile(dst, []byte("preserve"), 0o640)
			case "directory":
				err = os.Mkdir(dst, 0o700)
			case "symlink":
				err = os.Symlink(target, dst)
			case "dangling-symlink":
				err = os.Symlink(filepath.Join(dir, "absent"), dst)
			case "hardlink":
				err = os.Link(target, dst)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(dst)
			if err != nil {
				t.Fatal(err)
			}
			_, err = WriteNew(dst, func(io.Writer) error { t.Fatal("processed existing destination"); return nil })
			if err == nil {
				t.Fatal("accepted existing entry")
			}
			after, err := os.Lstat(dst)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("existing entry changed")
			}
			b, err := os.ReadFile(target)
			if err != nil || string(b) != "preserve" {
				t.Fatal("target changed")
			}
			if kind == "file" {
				b, err = os.ReadFile(dst)
				if err != nil || string(b) != "preserve" {
					t.Fatal("output changed")
				}
			}
			requireNoStage(t, dir)
		})
	}
}

var errFailure = errors.New("injected failure")
var errCleanup = errors.New("injected cleanup failure")

type faultFile struct {
	stagedFile
	writeErr, closeErr error
	closed             *bool
}

func (f faultFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.stagedFile.Write(p)
}
func (f faultFile) Close() error {
	*f.closed = true
	return errors.Join(f.stagedFile.Close(), f.closeErr)
}

func TestTransactionFailures(t *testing.T) {
	for _, stage := range []string{"create", "read", "write", "close", "publish", "cleanup-with-primary", "close-with-primary"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			dst := filepath.Join(dir, "output")
			ops := systemOperations()
			originalCreate, originalRemove := ops.createTemp, ops.remove
			closed, removed, linked := false, false, false
			ops.createTemp = func(dir, pattern string) (stagedFile, error) {
				if stage == "create" {
					return nil, errFailure
				}
				f, err := originalCreate(dir, pattern)
				if err != nil {
					return nil, err
				}
				ff := faultFile{stagedFile: f, closed: &closed}
				if stage == "write" {
					ff.writeErr = errFailure
				}
				if stage == "close" || stage == "close-with-primary" {
					ff.closeErr = errFailure
				}
				return ff, nil
			}
			ops.link = func(a, b string) error {
				linked = true
				if !closed {
					t.Fatal("link before close")
				}
				if stage == "publish" {
					return errFailure
				}
				return os.Link(a, b)
			}
			ops.remove = func(path string) error {
				removed = true
				err := originalRemove(path)
				if stage == "cleanup-with-primary" {
					return errCleanup
				}
				return err
			}
			warning, err := writeNew(dst, func(w io.Writer) error {
				if stage == "read" || stage == "cleanup-with-primary" || stage == "close-with-primary" {
					return errFailure
				}
				_, err := io.WriteString(w, "data")
				return err
			}, ops)
			if warning != nil || !errors.Is(err, errFailure) {
				t.Fatalf("lost primary error: %v %v", warning, err)
			}
			if stage == "cleanup-with-primary" && !errors.Is(err, errCleanup) {
				t.Fatal("cleanup error omitted")
			}
			if stage != "create" && (!closed || !removed) {
				t.Fatal("missing close/cleanup")
			}
			if stage != "publish" && linked {
				t.Fatal("linked after pre-publication failure")
			}
			if _, err := os.Lstat(dst); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published failed output")
			}
			requireNoStage(t, dir)
		})
	}
}

func TestDestinationAppearsAtCommit(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "output")
	ops := systemOperations()
	ops.link = func(a, b string) error {
		if err := os.WriteFile(b, []byte("racing destination"), 0o600); err != nil {
			t.Fatal(err)
		}
		return os.Link(a, b)
	}
	_, err := writeNew(dst, func(w io.Writer) error { _, err := io.WriteString(w, "new output"); return err }, ops)
	if err == nil {
		t.Fatal("replaced racing destination")
	}
	b, err := os.ReadFile(dst)
	if err != nil || string(b) != "racing destination" {
		t.Fatal("racing destination changed")
	}
	requireNoStage(t, dir)
}

func TestPostCommitCleanupFailure(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "output")
	ops := systemOperations()
	var temporary string
	ops.remove = func(path string) error { temporary = path; return errCleanup }
	warning, err := writeNew(dst, func(w io.Writer) error { _, err := io.WriteString(w, "valid"); return err }, ops)
	if err != nil || !errors.Is(warning, errCleanup) || !strings.Contains(warning.Error(), temporary) {
		t.Fatalf("commit status: %v %v", warning, err)
	}
	data, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(data, []byte("valid")) {
		t.Fatal("valid output lost")
	}
	a, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(temporary)
	if err != nil || !os.SameFile(a, b) {
		t.Fatal("temporary link missing")
	}
}

func TestMissingDirectory(t *testing.T) {
	_, err := WriteNew(filepath.Join(t.TempDir(), "missing", "output"), func(io.Writer) error { t.Fatal("unexpected write"); return nil })
	if err == nil {
		t.Fatal("accepted missing directory")
	}
}

func TestOpenRegular(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "input")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(file, []byte("input"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, link} {
		f, info, err := OpenRegular(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			t.Fatal("not regular")
		}
		f.Close()
	}
	for _, path := range []string{dir, filepath.Join(dir, "missing"), "/dev/null"} {
		if f, _, err := OpenRegular(path); err == nil {
			f.Close()
			t.Fatalf("accepted %s", path)
		}
	}
}
