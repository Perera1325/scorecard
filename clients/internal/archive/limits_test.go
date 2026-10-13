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

package archive

import (
	"bytes"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

// zeros is an endless stream of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// countingWriter counts the bytes written to it and discards them.
type countingWriter struct{ n int64 }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

type failingWriter struct{}

var errDisk = errors.New("disk failure")

func (failingWriter) Write([]byte) (int, error) { return 0, errDisk }

func TestDefaultLimits(t *testing.T) {
	t.Parallel()
	got := DefaultLimits()
	want := Limits{
		MaxEntryBytes: DefaultMaxEntryBytes,
		MaxTotalBytes: DefaultMaxTotalBytes,
		MaxEntries:    DefaultMaxEntries,
	}
	if got != want {
		t.Errorf("DefaultLimits() = %+v, want %+v", got, want)
	}
	// The per-file limit must not exceed the total, or it would never apply.
	if got.MaxEntryBytes > got.MaxTotalBytes {
		t.Errorf("per-file limit %d is larger than total limit %d", got.MaxEntryBytes, got.MaxTotalBytes)
	}
}

func TestNewBudgetFillsDefaults(t *testing.T) {
	t.Parallel()
	for _, limits := range []Limits{{}, {MaxEntryBytes: -1, MaxTotalBytes: -5, MaxEntries: -2}} {
		if got := NewBudget(limits).limits; got != DefaultLimits() {
			t.Errorf("NewBudget(%+v).limits = %+v, want the defaults", limits, got)
		}
	}
	partial := NewBudget(Limits{MaxEntryBytes: 7}).limits
	if partial.MaxEntryBytes != 7 || partial.MaxTotalBytes != DefaultMaxTotalBytes ||
		partial.MaxEntries != DefaultMaxEntries {
		t.Errorf("partial limits not merged with defaults: %+v", partial)
	}
}

func TestCopyEntry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		wantMsg string  // substring of the error message
		sizes   []int64 // entries copied in order, each a stream of zeros of this size
		limits  Limits
		// wantErrAt is the index of the entry expected to fail, or -1.
		wantErrAt int
	}{
		{
			name:      "within limits",
			limits:    Limits{MaxEntryBytes: 100, MaxTotalBytes: 1000},
			sizes:     []int64{10, 20, 30},
			wantErrAt: -1,
		},
		{
			name:      "empty entry",
			limits:    Limits{MaxEntryBytes: 100, MaxTotalBytes: 1000},
			sizes:     []int64{0},
			wantErrAt: -1,
		},
		{
			name:      "entry exactly at the per-file limit",
			limits:    Limits{MaxEntryBytes: 100, MaxTotalBytes: 1000},
			sizes:     []int64{100},
			wantErrAt: -1,
		},
		{
			name:      "entry one byte over the per-file limit",
			limits:    Limits{MaxEntryBytes: 100, MaxTotalBytes: 1000},
			sizes:     []int64{101},
			wantErrAt: 0,
			wantMsg:   "per-file limit of 100 bytes",
		},
		{
			name:      "total exactly at the limit",
			limits:    Limits{MaxEntryBytes: 100, MaxTotalBytes: 300},
			sizes:     []int64{100, 100, 100},
			wantErrAt: -1,
		},
		{
			name:      "total one byte over the limit",
			limits:    Limits{MaxEntryBytes: 100, MaxTotalBytes: 300},
			sizes:     []int64{100, 100, 100, 1},
			wantErrAt: 3,
			wantMsg:   "total limit of 300 bytes",
		},
		{
			name:      "many small entries exceed the total",
			limits:    Limits{MaxEntryBytes: 100, MaxTotalBytes: 1000},
			sizes:     slice(11, 100),
			wantErrAt: 10,
			wantMsg:   "total limit of 1000 bytes",
		},
		{
			name:      "last entry is cut by the remaining total, not by the per-file limit",
			limits:    Limits{MaxEntryBytes: 100, MaxTotalBytes: 150},
			sizes:     []int64{100, 60},
			wantErrAt: 1,
			wantMsg:   "total limit of 150 bytes",
		},
		{
			name:      "limits at the maximum int64 do not overflow",
			limits:    Limits{MaxEntryBytes: math.MaxInt64, MaxTotalBytes: math.MaxInt64},
			sizes:     []int64{10},
			wantErrAt: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			budget := NewBudget(tt.limits)
			for i, size := range tt.sizes {
				var dst countingWriter
				n, err := budget.CopyEntry(&dst, io.LimitReader(zeros{}, size), "entry", size)
				if i != tt.wantErrAt {
					if err != nil {
						t.Fatalf("entry %d: unexpected error: %v", i, err)
					}
					if n != size || dst.n != size {
						t.Fatalf("entry %d: copied %d (wrote %d), want %d", i, n, dst.n, size)
					}
					continue
				}
				if !errors.Is(err, ErrLimitExceeded) {
					t.Fatalf("entry %d: err = %v, want ErrLimitExceeded", i, err)
				}
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("entry %d: error %q does not mention %q", i, err, tt.wantMsg)
				}
				return
			}
			if tt.wantErrAt >= 0 {
				t.Fatalf("entry %d did not fail", tt.wantErrAt)
			}
		})
	}
}

func slice(n int, v int64) []int64 {
	s := make([]int64, n)
	for i := range s {
		s[i] = v
	}
	return s
}

// A header that claims a small size but whose stream keeps going must stop at the limit.
func TestCopyEntryStopsLyingHeader(t *testing.T) {
	t.Parallel()
	budget := NewBudget(Limits{MaxEntryBytes: 1 << 20, MaxTotalBytes: 1 << 30})
	var dst countingWriter
	_, err := budget.CopyEntry(&dst, zeros{}, "liar", 10)
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
	// At most the limit plus the one detection byte may be written, however endless the stream.
	if dst.n > 1<<20+1 {
		t.Errorf("wrote %d bytes, want at most %d", dst.n, 1<<20+1)
	}
}

// A huge declared size must be refused before reading or writing anything.
func TestCopyEntryRejectsDeclaredSizeUpFront(t *testing.T) {
	t.Parallel()
	budget := NewBudget(Limits{MaxEntryBytes: 1 << 20, MaxTotalBytes: 1 << 30})
	for _, declared := range []int64{1<<20 + 1, math.MaxInt64} {
		var dst countingWriter
		src := &bytes.Buffer{}
		src.WriteString("payload")
		_, err := budget.CopyEntry(&dst, src, "bomb", declared)
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("declared %d: err = %v, want ErrLimitExceeded", declared, err)
		}
		if dst.n != 0 || src.Len() != len("payload") {
			t.Errorf("declared %d: data was moved (wrote %d, left %d)", declared, dst.n, src.Len())
		}
	}
}

func TestCopyEntryRejectsNegativeSize(t *testing.T) {
	t.Parallel()
	budget := NewBudget(Limits{})
	if _, err := budget.CopyEntry(io.Discard, strings.NewReader("x"), "neg", -1); !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("err = %v, want ErrLimitExceeded", err)
	}
}

// Real write failures are not limit errors, so callers can tell them apart.
func TestCopyEntryPropagatesWriteErrors(t *testing.T) {
	t.Parallel()
	budget := NewBudget(Limits{})
	_, err := budget.CopyEntry(failingWriter{}, strings.NewReader("data"), "file", 4)
	if !errors.Is(err, errDisk) {
		t.Errorf("err = %v, want it to wrap the write error", err)
	}
	if errors.Is(err, ErrLimitExceeded) {
		t.Errorf("a write failure must not be reported as a limit error: %v", err)
	}
}

func TestCopyEntryQuotesNames(t *testing.T) {
	t.Parallel()
	budget := NewBudget(Limits{MaxEntryBytes: 1, MaxTotalBytes: 1})
	_, err := budget.CopyEntry(io.Discard, strings.NewReader("ab"), "evil\nname\x1b[31m", 2)
	if err == nil || strings.ContainsAny(err.Error(), "\n\x1b") {
		t.Errorf("error must quote hostile names, got %q", err)
	}
}

func TestCountEntry(t *testing.T) {
	t.Parallel()
	budget := NewBudget(Limits{MaxEntries: 3})
	for i := range 3 {
		if err := budget.CountEntry("entry"); err != nil {
			t.Fatalf("entry %d: unexpected error: %v", i, err)
		}
	}
	err := budget.CountEntry("one-too-many")
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
	if !strings.Contains(err.Error(), "3 entries") {
		t.Errorf("error %q does not state the limit", err)
	}
}
