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

func TestAllVerified(t *testing.T) {
	if _, ok := (incident.Incident{}).AllVerified(); ok {
		t.Error("no cause: want false")
	}
	inc := incident.Incident{Causes: []incident.Cause{
		{FindingID: "a", Status: "verified"}, {FindingID: "b", Status: "fixed"},
	}}
	if c, ok := inc.AllVerified(); ok || c.FindingID != "b" {
		t.Errorf("got %+v %v, want b and false", c, ok)
	}
	inc.Causes[1].Status = "verified"
	if _, ok := inc.AllVerified(); !ok {
		t.Error("two verified causes: want true")
	}
}
