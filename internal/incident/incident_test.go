// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incident_test

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/incident-agent/internal/incident"
)

func TestValidKey(t *testing.T) {
	if got, err := incident.ValidKey("  inc-1 "); err != nil || got != "inc-1" {
		t.Errorf("got %q err %v", got, err)
	}
	for name, raw := range map[string]string{
		"empty":     " ",
		"too long":  strings.Repeat("k", incident.MaxKeyBytes+1),
		"a newline": "inc\n1",
	} {
		if _, err := incident.ValidKey(raw); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestCause(t *testing.T) {
	inc := incident.Incident{Causes: []incident.Cause{
		{FindingID: "a", Status: "verified"}, {FindingID: "b", Status: "fixed"},
	}}
	if c, ok := inc.Cause("b"); !ok || c.Verified() {
		t.Errorf("b: %+v %v, want found and not verified", c, ok)
	}
	if c, ok := inc.Cause("a"); !ok || !c.Verified() {
		t.Errorf("a: %+v %v, want found and verified", c, ok)
	}
	if _, ok := inc.Cause("c"); ok {
		t.Error("c: want not found")
	}
}
