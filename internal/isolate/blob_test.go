// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package isolate

import (
	"strings"
	"testing"
)

// The expected values come from `git hash-object` (SHA-1) and from
// `git hash-object` in a SHA-256 repository.
func TestGitBlobSHA(t *testing.T) {
	sha1Head, sha256Head := strings.Repeat("a", 40), strings.Repeat("a", 64)
	tests := []struct{ head, content, want string }{
		{sha1Head, "", "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"},
		{sha1Head, "hello\n", "ce013625030ba8dba906f756967f9e9ca394464a"},
		{sha256Head, "", "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"},
		{sha256Head, "hello\n", "2cf8d83d9ee29543b34a87727421fdecb7e3f3a183d337639025de576db9ebb4"},
	}
	for _, tc := range tests {
		if got := gitBlobSHA(tc.head, tc.content); got != tc.want {
			t.Errorf("gitBlobSHA(%d, %q) = %s, want %s", len(tc.head), tc.content, got, tc.want)
		}
	}
}
