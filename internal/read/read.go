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
// each read, and a run fails with a reason that says so. It never returns an
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
	"github.com/zeroroot-ai/sdk/agent"
)

// ErrNoIncidentRead means that the harness callback service has no call that
// reads an incident.
var ErrNoIncidentRead = errors.New("read: the harness callback service has no incident read")

// Daemon reads an incident through the harness. It satisfies
// incident.Reader.
type Daemon struct{}

// Incident reads one incident.
func (Daemon) Incident(_ context.Context, key string) (incident.Incident, error) {
	return incident.Incident{}, fmt.Errorf("read incident %s: %w: %w",
		key, ErrNoIncidentRead, agent.ErrKnowledgeUnavailable)
}
