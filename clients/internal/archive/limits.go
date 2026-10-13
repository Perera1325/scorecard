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

// Package archive holds helpers shared by the repository clients that extract
// repository archives onto local disk.
//
// The archives come from the repository being scored, so their contents are
// attacker controlled. A few kilobytes of gzip can expand to gigabytes, and a
// single archive can contain millions of tiny files, so extraction must be
// bounded.
package archive

import (
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	// DefaultMaxEntryBytes is the default cap on the extracted size of one file.
	// It equals GitHub's documented hard limit on pushed files ("GitHub blocks
	// files larger than 100 MiB"), so a GitHub-hosted file cannot exceed it.
	// The largest file in the largest repositories sampled (llvm-project,
	// linux, kubernetes) is about 25 MiB.
	DefaultMaxEntryBytes int64 = 100 << 20

	// DefaultMaxTotalBytes is the default cap on the total extracted size.
	// The largest archive sampled (llvm-project) extracts to about 2.4 GiB.
	DefaultMaxTotalBytes int64 = 4 << 30

	// DefaultMaxEntries is the default cap on the number of archive entries.
	// The largest archive sampled (llvm-project) has about 190k files. Many
	// tiny files exhaust inodes and disk blocks long before they reach the byte
	// cap, so entries are limited separately.
	DefaultMaxEntries int64 = 1_000_000
)

// ErrLimitExceeded is returned, wrapped with details, when an archive goes over
// one of the configured limits.
var ErrLimitExceeded = errors.New("archive extraction limit exceeded")

// Limits bounds how much a single archive may expand. A field that is zero or
// negative selects its default.
type Limits struct {
	// MaxEntryBytes caps the extracted size of any single file.
	MaxEntryBytes int64
	// MaxTotalBytes caps the extracted size of all files together.
	MaxTotalBytes int64
	// MaxEntries caps the number of entries (files, directories and others).
	MaxEntries int64
}

// DefaultLimits returns the default limits.
func DefaultLimits() Limits {
	return Limits{
		MaxEntryBytes: DefaultMaxEntryBytes,
		MaxTotalBytes: DefaultMaxTotalBytes,
		MaxEntries:    DefaultMaxEntries,
	}
}

func (l Limits) withDefaults() Limits {
	def := DefaultLimits()
	if l.MaxEntryBytes <= 0 {
		l.MaxEntryBytes = def.MaxEntryBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = def.MaxTotalBytes
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = def.MaxEntries
	}
	return l
}

// Budget tracks how much of the Limits one archive has used so far.
// Create one per archive; it is not safe for concurrent use.
type Budget struct {
	limits  Limits
	total   int64
	entries int64
}

// NewBudget returns a Budget enforcing limits.
func NewBudget(limits Limits) *Budget {
	return &Budget{limits: limits.withDefaults()}
}

// CountEntry records one archive entry and fails if that goes over MaxEntries.
// Call it for every entry in the archive, whatever its type.
func (b *Budget) CountEntry(name string) error {
	if b.entries >= b.limits.MaxEntries {
		return fmt.Errorf("%w: archive has more than %d entries (stopped at %q)",
			ErrLimitExceeded, b.limits.MaxEntries, name)
	}
	b.entries++
	return nil
}

// CopyEntry copies one file's content from src to dst and returns the number of
// bytes written. declaredSize is the size claimed by the archive header.
//
// It fails with ErrLimitExceeded, before writing anything, if declaredSize alone
// is over a limit. It also never reads more than the limits allow, so an entry
// that outgrows its header still stops at the limit.
// Other errors from the copy are returned wrapped, without ErrLimitExceeded.
func (b *Budget) CopyEntry(dst io.Writer, src io.Reader, name string, declaredSize int64) (int64, error) {
	if declaredSize < 0 {
		return 0, fmt.Errorf("%w: entry %q has invalid size %d", ErrLimitExceeded, name, declaredSize)
	}

	// b.total never exceeds MaxTotalBytes, so remaining is never negative.
	remaining := b.limits.MaxTotalBytes - b.total
	limit := min(b.limits.MaxEntryBytes, remaining)
	if declaredSize > limit {
		return 0, b.limitError(name, declaredSize)
	}

	// Read one byte past the limit so that going over is detected instead of
	// silently truncated. Skip the +1 where it would overflow.
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	written, err := io.Copy(dst, io.LimitReader(src, readLimit))
	b.total += min(written, limit)
	if err != nil {
		return written, fmt.Errorf("copying %q: %w", name, err)
	}
	if written > limit {
		return written, b.limitError(name, written)
	}
	return written, nil
}

// limitError describes which limit a file of the given size went over.
func (b *Budget) limitError(name string, size int64) error {
	if size > b.limits.MaxEntryBytes {
		return fmt.Errorf("%w: file %q is larger than the per-file limit of %d bytes",
			ErrLimitExceeded, name, b.limits.MaxEntryBytes)
	}
	return fmt.Errorf("%w: extracting %q would exceed the total limit of %d bytes",
		ErrLimitExceeded, name, b.limits.MaxTotalBytes)
}
