// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package read is the read of one incident from the graph.
//
// # The daemon offers no incident read to an agent yet
//
// The daemon holds the read: the incident report reader
// (gibson internal/platform/incidentreport) runs the four queries of an
// incident, its alerts, the places that they reach, its causes with their
// status and their fixes. Only the tenant API serves it
// (IncidentReportService.GetIncidentReport), and an agent calls only the
// harness callback service.
//
// The harness callback has no call that answers it:
//
//   - QueryNodes is a search. The daemon drops from_node_id and
//     relationship_type of the query (protoQueryToStoreQuery), so it cannot
//     follow PART_OF, AFFECTS or CAUSED_BY.
//   - ApplicationFindings walks the findings of one Application, not an
//     incident.
//   - WorldView has no Alert and no Incident kind.
//
// So Daemon returns an error that wraps agent.ErrKnowledgeUnavailable for
// each read, and a run fails with a reason that says so. gibson#1573 adds the
// read. It never returns an
// empty incident: an empty read would let the contain step report a clean
// pass over an incident that nobody looked at. When the daemon serves the
// read, Daemon calls it and maps the answer to incident.Incident. The README
// states the call that is missing.
package read

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
	"github.com/zeroroot-ai/sdk/agent"
)

// ErrNoIncidentRead means that the harness callback service has no call that
// reads an incident.
var ErrNoIncidentRead = errors.New("read: the harness callback service has no incident read")

// ErrNoToolCallRead means that the harness callback service has no call that
// reads back a tool call of the calling agent.
//
// The flight recorder of the daemon holds each tool call (ToolCallRecord in
// gibson internal/engine/harness), but an agent cannot read it. The record
// also holds no name of the component that made the call. The one use of a
// tool_call_id by an agent is a citation in SubmitFinding, which checks the
// mission and not the agent. The README states the call that is missing.
var ErrNoToolCallRead = errors.New("read: the harness callback service has no read of the tool calls of an agent")

// Daemon reads an incident and the tool calls of this agent through the
// harness. It satisfies incident.Reader and contain.CallChecker.
type Daemon struct{}

// Incident reads one incident.
func (Daemon) Incident(_ context.Context, key string) (incident.Incident, error) {
	return incident.Incident{}, fmt.Errorf("read incident %s: %w: %w",
		key, ErrNoIncidentRead, agent.ErrKnowledgeUnavailable)
}

// CheckCall asks the daemon whether this agent made the tool call. The
// harness has no such read, so it fails with a reason and never confirms a
// call. A release then fails, and it releases nothing that it cannot prove
// this agent contained.
func (Daemon) CheckCall(_ context.Context, toolCallID string, a respond.Action) error {
	return fmt.Errorf("check tool call %s of %s: %w: %w",
		respond.Clean(toolCallID), a.ToolID(), ErrNoToolCallRead, agent.ErrKnowledgeUnavailable)
}
