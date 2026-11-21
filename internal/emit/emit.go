// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package emit writes what the agent did on the Incident node, and links the
// Incident to the finding of its cause.
//
// Each write is a sighting (ADR-0107). The agent reports what it did, and the
// brain resolves the identity and the projector writes the node. The Incident
// is named by its key, so each write enriches the one Incident node.
//
// The agent never writes the status of a finding and never writes that an
// incident is resolved. The daemon sets the status of the finding, and the
// incident report states what happened.
package emit

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
	"github.com/zeroroot-ai/sdk/agent"
)

// IDPropIncident is the identity property of an Incident node.
const IDPropIncident = "key"

// IDPropFinding is the identity property of a Finding node.
const IDPropFinding = "brain_id"

// IDPropPlace names the identity of a place in an edge. The daemon reads only
// the value of a single identity property, and it takes the property name of
// the label from its own table (brain_id for Account and Host).
const IDPropPlace = "key"

// MaxRecordNameBytes is the limit of the daemon for the name of a property
// (emitbounds.MaxPropertyKeyBytes in gibson).
const MaxRecordNameBytes = 128

// RecordHeld is the record that says why the release step released nothing.
const RecordHeld = "release.held"

// The state words of a record name.
const (
	stateContained = "contained"
	stateReleased  = "released"
)

// Observer is the one platform capability that this package needs.
type Observer interface {
	Observe(ctx context.Context, obs agent.Observation) error
}

// Emitter writes the records. It satisfies the recorder of the contain
// package and the linker of the cause package.
type Emitter struct {
	obs Observer
}

// New builds an Emitter over obs.
func New(obs Observer) (*Emitter, error) {
	if obs == nil {
		return nil, errors.New("emit: no observer")
	}
	return &Emitter{obs: obs}, nil
}

// RecordName is the name of the record of one action with one outcome: the
// state, the tool id and the vendor id, joined with ".". Each part comes from
// the closed table of connectors or from a vendor id that matched the form of
// its connector, so the name holds no free text.
func RecordName(r respond.Result) string {
	state := string(r.Outcome)
	if r.Outcome == respond.OutcomeDone {
		state = stateContained
		if r.Action.Kind == respond.KindRelease {
			state = stateReleased
		}
	}
	return state + "." + r.Action.ToolID() + "." + r.Action.Target.VendorID
}

// ContainedName is the name of the record that says the agent made the
// containment of one step on one target.
func ContainedName(t respond.Target, s respond.Step) string {
	return stateContained + "." + t.Connector.ToolID(s.Tool) + "." + t.VendorID
}

// ReleasedName is the name of the record that says the agent released the
// containment of one step on one target.
func ReleasedName(t respond.Target, s respond.Step) string {
	return stateReleased + "." + t.Connector.ToolID(s.Undo) + "." + t.VendorID
}

// Record writes the outcome of one action on the Incident node.
func (e *Emitter) Record(ctx context.Context, incidentKey string, r respond.Result) error {
	name := RecordName(r)
	if len(name) > MaxRecordNameBytes {
		return fmt.Errorf("emit: the record name %q is longer than %d bytes", name, MaxRecordNameBytes)
	}
	value := string(r.Outcome)
	if r.Detail != "" {
		value = r.Detail
	}
	return e.observe(ctx, incidentObservation(incidentKey, map[string]string{name: value}, nil))
}

// Held writes why the release step released nothing.
func (e *Emitter) Held(ctx context.Context, incidentKey, reason string) error {
	return e.observe(ctx, incidentObservation(incidentKey, map[string]string{RecordHeld: respond.Clean(reason)}, nil))
}

// LinkCause links the Incident to the finding of its cause with CAUSED_BY,
// and the finding to the place of the flaw with AFFECTS.
func (e *Emitter) LinkCause(ctx context.Context, incidentKey, findingID string, place incident.Place) error {
	if findingID == "" {
		return errors.New("emit: no finding to link")
	}
	err := e.observe(ctx, incidentObservation(incidentKey, nil, []agent.LifecycleEntityEdge{{
		Type:               incident.RelCausedBy,
		TargetLabel:        incident.LabelFinding,
		TargetIDProperties: map[string]string{IDPropFinding: findingID},
	}}))
	if err != nil {
		return err
	}
	return e.observe(ctx, agent.LifecycleEntityObservation{
		Label:        incident.LabelFinding,
		IDProperties: map[string]string{IDPropFinding: findingID},
		Edges: []agent.LifecycleEntityEdge{{
			Type:               incident.RelAffects,
			TargetLabel:        place.Label,
			TargetIDProperties: map[string]string{IDPropPlace: place.Key},
		}},
	})
}

func (e *Emitter) observe(ctx context.Context, obs agent.LifecycleEntityObservation) error {
	if err := e.obs.Observe(ctx, obs); err != nil {
		return fmt.Errorf("emit: observe %s: %w", obs.Label, err)
	}
	return nil
}

func incidentObservation(
	key string, props map[string]string, edges []agent.LifecycleEntityEdge,
) agent.LifecycleEntityObservation {
	return agent.LifecycleEntityObservation{
		Label:        incident.LabelIncident,
		IDProperties: map[string]string{IDPropIncident: key},
		Properties:   props,
		Edges:        edges,
	}
}
