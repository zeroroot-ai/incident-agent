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

// The cases of filesProblem that the flow tests do not reach. Each case breaks
// one rule, and a change that drops the rule makes its case pass the check.
func TestFilesProblem(t *testing.T) {
	head := strings.Repeat("a", 40)
	blob := gitBlobSHA(head, "kind: X\n")
	want := Change{Files: []File{{Path: "d/p.yaml", Content: "kind: X\n"}, {Path: "d/l.yaml", Delete: true}}}
	good := func() MR {
		return MR{HeadSHA: head, FilesKnown: true, Files: []ChangedFile{
			{Path: "d/p.yaml", Change: "added", BlobSHA: blob},
			{Path: "d/l.yaml", Change: "deleted"},
		}}
	}
	if p := filesProblem(good(), want); p != "" {
		t.Fatalf("the exact change is refused: %s", p)
	}
	for _, mode := range []string{"", "100644"} {
		mr := good()
		mr.Files[0].Mode = mode
		if p := filesProblem(mr, want); p != "" {
			t.Fatalf("mode %q is refused: %s", mode, p)
		}
	}
	tests := map[string]struct {
		edit func(*MR)
		want string
		with Change
	}{
		"mode 100755":          {func(m *MR) { m.Files[0].Mode = "100755" }, "mode", want},
		"mode 120000":          {func(m *MR) { m.Files[0].Mode = "120000" }, "mode", want},
		"a mode_changed entry": {func(m *MR) { m.Files[0].Change = "mode_changed" }, "mode or the type", want},
		"a modified entry with a previous": {func(m *MR) {
			m.Files[0].Change, m.Files[0].PreviousPath = "modified", "d/old.yaml"
		}, "renames", want},
		"a renamed entry":                {func(m *MR) { m.Files[0].Change = "renamed" }, "renames", want},
		"a delete with the wrong change": {func(m *MR) { m.Files[1].Change = "modified" }, "than a delete", want},
		"a delete with a blob":           {func(m *MR) { m.Files[1].BlobSHA = blob }, "than a delete", want},
		"an entry with no change":        {func(m *MR) { m.Files[0].Change = "" }, "did not write", want},
		"a wrong blob": {func(m *MR) {
			m.Files[0].BlobSHA = gitBlobSHA(head, "other")
		}, "content", want},
		"a cut list":                  {func(m *MR) { m.Truncated = true }, "cut", want},
		"a host error":                {func(m *MR) { m.FilesKnown, m.FilesError = false, "boom" }, "boom", want},
		"no list for an empty change": {func(m *MR) { m.FilesKnown, m.Files = false, nil }, "does not return", Change{}},
		"a head of 41 characters":     {func(m *MR) { m.HeadSHA = head + "a" }, "head commit", want},
		"an extra file": {func(m *MR) {
			m.Files = append(m.Files, ChangedFile{Path: "x", Change: "added"})
		}, "changes 3", want},
		"a missing file": {func(m *MR) { m.Files[0].Path = "d/other.yaml" }, "does not change the expected", want},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mr := good()
			tc.edit(&mr)
			if p := filesProblem(mr, tc.with); p == "" || !strings.Contains(p, tc.want) {
				t.Fatalf("problem = %q, want one that holds %q", p, tc.want)
			}
		})
	}
}

// A list entry with no path or no change is malformed. It never reads as a
// valid entry.
func TestChangedFilesRefusesAMalformedEntry(t *testing.T) {
	for name, v := range map[string]any{
		"no list":      nil,
		"not a map":    []any{"x"},
		"no change":    []any{map[string]any{"path": "a"}},
		"no path":      []any{map[string]any{"change": "added"}},
		"a bare value": "x",
	} {
		if _, ok := changedFiles(v); ok {
			t.Errorf("%s: the list is accepted", name)
		}
	}
	got, ok := changedFiles([]any{map[string]any{"path": "a", "change": "added", "mode": "100644", "blob_sha": "b"}})
	if !ok || len(got) != 1 || got[0].Mode != "100644" {
		t.Errorf("got %+v, ok = %v", got, ok)
	}
}
