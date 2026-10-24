// Package fileio stages complete outputs and atomically publishes without replacement.
package fileio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type stagedFile interface {
	io.WriteCloser
	Name() string
}

// Only the operations needed to inject transaction failures are abstracted.
type operations struct {
	createTemp func(string, string) (stagedFile, error)
	link       func(string, string) error
	remove     func(string) error
}

func systemOperations() operations {
	return operations{
		createTemp: func(dir, pattern string) (stagedFile, error) { return os.CreateTemp(dir, pattern) },
		link:       os.Link,
		remove:     os.Remove,
	}
}

// WriteNew publishes only after write and close succeed. A warning means commit
// succeeded, but the extra temporary name could not be removed; err remains nil.
func WriteNew(destination string, write func(io.Writer) error) (warning, err error) {
	return writeNew(destination, write, systemOperations())
}

func writeNew(destination string, write func(io.Writer) error, ops operations) (warning, err error) {
	if _, err := os.Lstat(destination); err == nil {
		return nil, errors.New("output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect output: %w", err)
	}
	f, err := ops.createTemp(filepath.Dir(destination), ".filecrypt-*")
	if err != nil {
		return nil, fmt.Errorf("create staged output: %w", err)
	}
	closed, committed := false, false
	defer func() {
		if !closed {
			if closeErr := f.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close staged output: %w", closeErr))
			}
		}
		if !committed {
			if cleanupErr := ops.remove(f.Name()); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("remove staged output: %w", cleanupErr))
			}
		}
	}()
	if err := write(f); err != nil {
		return nil, err
	}
	closeErr := f.Close()
	closed = true
	if closeErr != nil {
		return nil, fmt.Errorf("close staged output: %w", closeErr)
	}
	if err := ops.link(f.Name(), destination); err != nil {
		return nil, fmt.Errorf("publish output with no-replace hard link: %w", err)
	}
	committed = true
	if err := ops.remove(f.Name()); err != nil {
		return fmt.Errorf("output published; temporary hard link remains at %s: %w", f.Name(), err), nil
	}
	return nil, nil
}

// OpenRegular follows input symlinks and validates the opened descriptor.
func OpenRegular(path string) (*os.File, os.FileInfo, error) {
	// Reject ordinary FIFOs/devices before opening, since a FIFO open could block.
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect input file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("input must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open input file: %w", err)
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		closeErr := f.Close()
		if err == nil {
			err = errors.New("input must be a regular file")
		}
		return nil, nil, errors.Join(err, closeErr)
	}
	return f, info, nil
}
