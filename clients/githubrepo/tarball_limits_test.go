// Copyright 2026 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package githubrepo

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-github/v82/github"

	"github.com/ossf/scorecard/v5/clients"
	"github.com/ossf/scorecard/v5/clients/internal/archive"
	sce "github.com/ossf/scorecard/v5/errors"
)

// limitsTarEntry describes one entry of a generated test tarball.
type limitsTarEntry struct {
	name     string
	linkname string
	size     int64 // size of a regular file, filled with zeros
	typeflag byte
}

// zeroStream is an endless stream of zero bytes.
type zeroStream struct{}

func (zeroStream) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// writeLimitsTarball writes a gzipped tarball made of entries and returns its path and size.
// Zero filled files compress to almost nothing, which is what makes decompression bombs cheap.
func writeLimitsTarball(t *testing.T, entries []limitsTarEntry) (string, int64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating tarball: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: 0o644, Linkname: e.linkname}
		switch e.typeflag {
		case tar.TypeDir:
			hdr.Mode = 0o755
		case tar.TypeReg:
			hdr.Size = e.size
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("writing header for %q: %v", e.name, err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := io.CopyN(tw, zeroStream{}, e.size); err != nil {
				t.Fatalf("writing %q: %v", e.name, err)
			}
		}
	}
	for _, c := range []io.Closer{tw, gz, f} {
		if err := c.Close(); err != nil {
			t.Fatalf("closing tarball: %v", err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat tarball: %v", err)
	}
	return path, info.Size()
}

// newLimitsHandler returns a handler ready to extract entries with the given limits.
func newLimitsHandler(t *testing.T, entries []limitsTarEntry, limits archive.Limits) *tarballHandler {
	t.Helper()
	path, _ := writeLimitsTarball(t, entries)
	handler, err := setup(path)
	if err != nil {
		t.Fatalf("test setup failed: %v", err)
	}
	handler.limits = limits
	t.Cleanup(func() { cleanupHandler(t, &handler) })
	return &handler
}

// cleanupHandler removes whatever the handler left on disk.
func cleanupHandler(t *testing.T, handler *tarballHandler) {
	t.Helper()
	if err := handler.cleanup(); err != nil {
		t.Errorf("cleanup: %v", err)
	}
}

func dirEntry(name string) limitsTarEntry {
	return limitsTarEntry{name: name, typeflag: tar.TypeDir}
}

func fileEntry(name string, size int64) limitsTarEntry {
	return limitsTarEntry{name: name, typeflag: tar.TypeReg, size: size}
}

// manyFiles returns n regular files of the given size, directly under the top-level directory.
func manyFiles(n int, size int64) []limitsTarEntry {
	entries := make([]limitsTarEntry, 0, n)
	for i := range n {
		entries = append(entries, fileEntry(fmt.Sprintf("top/file%03d", i), size))
	}
	return entries
}

func withTopDir(entries ...[]limitsTarEntry) []limitsTarEntry {
	all := []limitsTarEntry{dirEntry("top/")}
	for _, e := range entries {
		all = append(all, e...)
	}
	return all
}

func TestExtractTarballLimits(t *testing.T) {
	t.Parallel()
	const (
		kiB = 1 << 10
		miB = 1 << 20
	)
	tests := []struct {
		name      string
		entries   []limitsTarEntry
		wantFiles []string
		limits    archive.Limits
		wantErr   bool
	}{
		{
			name: "archive within the limits",
			entries: withTopDir([]limitsTarEntry{
				fileEntry("top/a", 10), dirEntry("top/dir/"), fileEntry("top/dir/b", 20),
			}),
			limits:    archive.Limits{MaxEntryBytes: 100, MaxTotalBytes: 1000, MaxEntries: 100},
			wantFiles: []string{"a", "dir/b"},
		},
		{
			name:      "zero limits select the defaults",
			entries:   withTopDir([]limitsTarEntry{fileEntry("top/a", 10)}),
			wantFiles: []string{"a"},
		},
		{
			name:      "file exactly at the per-file limit",
			entries:   withTopDir([]limitsTarEntry{fileEntry("top/big", 100)}),
			limits:    archive.Limits{MaxEntryBytes: 100, MaxTotalBytes: 1000},
			wantFiles: []string{"big"},
		},
		{
			name:    "file one byte over the per-file limit",
			entries: withTopDir([]limitsTarEntry{fileEntry("top/big", 101)}),
			limits:  archive.Limits{MaxEntryBytes: 100, MaxTotalBytes: 1000},
			wantErr: true,
		},
		{
			name:    "several small files exceed the total",
			entries: withTopDir(manyFiles(11, 100)),
			limits:  archive.Limits{MaxEntryBytes: 100, MaxTotalBytes: 1000},
			wantErr: true,
		},
		{
			name:      "several small files exactly at the total",
			entries:   withTopDir(manyFiles(10, 100)),
			limits:    archive.Limits{MaxEntryBytes: 100, MaxTotalBytes: 1000},
			wantFiles: fileNames(10),
		},
		{
			name:    "compressible file bigger than the per-file limit",
			entries: withTopDir([]limitsTarEntry{fileEntry("top/bomb", 4*miB)}),
			limits:  archive.Limits{MaxEntryBytes: 64 * kiB, MaxTotalBytes: 1 * miB},
			wantErr: true,
		},
		{
			name:    "compressible files within the per-file limit but over the total",
			entries: withTopDir(manyFiles(8, 256*kiB)),
			limits:  archive.Limits{MaxEntryBytes: 256 * kiB, MaxTotalBytes: 1 * miB},
			wantErr: true,
		},
		{
			name:      "entry count exactly at the limit",
			entries:   withTopDir(manyFiles(4, 1)),
			limits:    archive.Limits{MaxEntries: 5},
			wantFiles: fileNames(4),
		},
		{
			name:    "entry count one over the limit",
			entries: withTopDir(manyFiles(5, 1)),
			limits:  archive.Limits{MaxEntries: 5},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler := newLimitsHandler(t, tt.entries, tt.limits)
			err := handler.extractTarball()
			if tt.wantErr {
				assertLimitExceeded(t, handler, err)
			} else {
				assertExtracted(t, handler, err, tt.wantFiles)
			}
		})
	}
}

func assertExtracted(t *testing.T, handler *tarballHandler, err error, wantFiles []string) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := handler.listFiles(func(string) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("listFiles: %v", err)
	}
	slices.Sort(got)
	if !slices.Equal(got, wantFiles) {
		t.Errorf("files = %q, want %q", got, wantFiles)
	}
}

func assertLimitExceeded(t *testing.T, handler *tarballHandler, err error) {
	t.Helper()
	if !errors.Is(err, archive.ErrLimitExceeded) {
		t.Fatalf("err = %v, want archive.ErrLimitExceeded", err)
	}
	// A corrupted archive is skipped by setup() and the checks would score what was
	// extracted so far; a limit error must not be treated that way.
	if errors.Is(err, errTarballCorrupted) {
		t.Errorf("limit error must not be reported as a corrupted tarball: %v", err)
	}
	if !strings.Contains(err.Error(), "--local") {
		t.Errorf("error should tell the user how to scan the repository anyway: %v", err)
	}
	// Everything extracted before the limit was hit is removed.
	if _, statErr := os.Stat(handler.tempDir); !os.IsNotExist(statErr) {
		t.Errorf("temp dir was not removed after the limit was exceeded: %v", statErr)
	}
	if len(handler.files) != 0 {
		t.Errorf("files not cleared after the limit was exceeded: %q", handler.files)
	}
}

func fileNames(n int) []string {
	names := make([]string, 0, n)
	for i := range n {
		names = append(names, fmt.Sprintf("file%03d", i))
	}
	return names
}

// The archive must be a real bomb for the test above to mean anything.
func TestLimitsTarballIsACompressionBomb(t *testing.T) {
	t.Parallel()
	const size = 4 << 20
	_, compressed := writeLimitsTarball(t, withTopDir([]limitsTarEntry{fileEntry("top/bomb", size)}))
	if compressed*100 > size {
		t.Errorf("tarball is %d bytes for %d bytes of content, want at least 100:1", compressed, size)
	}
}

// Files written before the limit is hit must be deleted as well, not only the offending one.
func TestExtractTarballLimitRemovesPartialExtraction(t *testing.T) {
	t.Parallel()
	// Three files are extracted successfully before the fourth goes over the per-file limit.
	entries := withTopDir(manyFiles(3, 100), []limitsTarEntry{fileEntry("top/toobig", 1000)})
	handler := newLimitsHandler(t, entries, archive.Limits{MaxEntryBytes: 500, MaxTotalBytes: 10000})
	tempDir, tempTarFile := handler.tempDir, handler.tempTarFile

	if err := handler.extractTarball(); !errors.Is(err, archive.ErrLimitExceeded) {
		t.Fatalf("err = %v, want archive.ErrLimitExceeded", err)
	}
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Errorf("partially extracted files remain in %s: %v", tempDir, err)
	}
	if _, err := os.Stat(tempTarFile); !os.IsNotExist(err) {
		t.Errorf("downloaded archive remains: %v", err)
	}
}

// A limit error must reach the caller through setup() instead of being skipped.
func TestSetupFailsWhenArchiveExceedsLimits(t *testing.T) {
	t.Parallel()
	path, _ := writeLimitsTarball(t, withTopDir(manyFiles(5, 100)))
	tarball, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading tarball: %v", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(tarball); err != nil {
			t.Errorf("serving tarball: %v", err)
		}
	}))
	t.Cleanup(ts.Close)

	name := "repo"
	archiveURL := ts.URL + "/{archive_format}"
	h := tarballHandler{
		httpClient: http.DefaultClient,
		limits:     archive.Limits{MaxEntryBytes: 100, MaxTotalBytes: 300},
	}
	h.init(t.Context(), &github.Repository{Name: &name, ArchiveURL: &archiveURL}, clients.HeadSHA)
	t.Cleanup(func() { cleanupHandler(t, &h) })

	err = h.setup()
	if !errors.Is(err, sce.ErrScorecardInternal) {
		t.Fatalf("setup() = %v, want an internal error", err)
	}
	if !strings.Contains(err.Error(), "total limit of 300 bytes") {
		t.Errorf("setup() error should name the limit that was hit: %v", err)
	}
	// Nothing partial may be served to the checks.
	if files, err := h.listFiles(func(string) (bool, error) { return true, nil }); err == nil || len(files) != 0 {
		t.Errorf("listFiles() = %q, %v; want no files and an error", files, err)
	}
	if _, err := os.Stat(h.tempDir); !os.IsNotExist(err) {
		t.Errorf("temp dir should be removed: %v", err)
	}
}

// The limits must not weaken the existing path traversal and symlink protections.
func TestExtractTarballLimitsKeepPathProtections(t *testing.T) {
	t.Parallel()
	limits := archive.Limits{MaxEntryBytes: 1 << 20, MaxTotalBytes: 1 << 24, MaxEntries: 100}

	t.Run("zip slip is still rejected", func(t *testing.T) {
		t.Parallel()
		handler := newLimitsHandler(t, withTopDir([]limitsTarEntry{fileEntry("top/../../escaped", 10)}), limits)
		escaped := filepath.Join(filepath.Dir(handler.tempDir), "escaped")
		t.Cleanup(func() { _ = os.Remove(escaped) })

		err := handler.extractTarball()
		if !errors.Is(err, errZipSlip) {
			t.Fatalf("err = %v, want errZipSlip", err)
		}
		if errors.Is(err, archive.ErrLimitExceeded) {
			t.Errorf("a path traversal error must not be reported as a limit error: %v", err)
		}
		if _, statErr := os.Lstat(escaped); !os.IsNotExist(statErr) {
			t.Errorf("file was written outside the extraction directory: %v", statErr)
		}
	})

	t.Run("symlinks are skipped and not followed", func(t *testing.T) {
		t.Parallel()
		outside := t.TempDir()
		entries := withTopDir([]limitsTarEntry{
			{name: "top/link", typeflag: tar.TypeSymlink, linkname: outside},
			fileEntry("top/link/pwned", 10),
			fileEntry("top/ok", 10),
		})
		handler := newLimitsHandler(t, entries, limits)

		if err := handler.extractTarball(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if leaked, err := os.ReadDir(outside); err != nil || len(leaked) != 0 {
			t.Errorf("symlink target was written to: %v, err = %v", leaked, err)
		}
		info, err := os.Lstat(filepath.Join(handler.tempDir, "link"))
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			t.Error("a symlink was created in the extraction directory")
		}
	})
}
