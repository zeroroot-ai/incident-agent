// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package read_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/incident-agent/internal/read"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
	"github.com/zeroroot-ai/sdk/agent"
)

// An unavailable read is never an empty incident. The error must match both
// the sentinel of this package and the sentinel of the SDK.
func TestDaemon_ReportsTheMissingReadAndNeverAnEmptyIncident(t *testing.T) {
	inc, err := read.Daemon{}.Incident(context.Background(), "inc-1")
	if !errors.Is(err, read.ErrNoIncidentRead) || !errors.Is(err, agent.ErrKnowledgeUnavailable) {
		t.Fatalf("err = %v, want both sentinels", err)
	}
	if inc.Key != "" || len(inc.Alerts) != 0 {
		t.Errorf("incident = %+v, want the zero value", inc)
	}
}

// No read of the tool calls of an agent exists, so the check never confirms a
// call. A record that any writer can put on the Incident node must not
// release a containment.
func TestDaemon_NeverConfirmsAToolCall(t *testing.T) {
	err := read.Daemon{}.CheckCall(context.Background(), "0b5e2c1a-0000-4000-8000-000000000001", respond.Action{})
	if !errors.Is(err, read.ErrNoToolCallRead) || !errors.Is(err, agent.ErrKnowledgeUnavailable) {
		t.Fatalf("err = %v, want both sentinels", err)
	}
}
