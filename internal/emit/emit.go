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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"

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

// RecordNamePattern is the form of a property name that the graph projector
// of the daemon keeps. The projector drops each other property name and
// returns no error (safeTaxonomyLabel in entityUpsertParams,
// internal/server/daemon/graph_projector_neo4j.go in gibson, branch
// integration/blue-team). So each record name of this package has this form.
const RecordNamePattern = `^[A-Za-z][A-Za-z0-9_]*$`

// recordName is the compiled RecordNamePattern.
var recordName = regexp.MustCompile(RecordNamePattern)

// checkName refuses a record name that the projector would drop or that is
// longer than the limit of the daemon. A dropped record is a silent loss, so
// the agent stops before the write.
func checkName(n string) error {
	if len(n) > MaxRecordNameBytes {
		return fmt.Errorf("emit: the record name %q is longer than %d bytes", n, MaxRecordNameBytes)
	}
	if !recordName.MatchString(n) {
		return fmt.Errorf("emit: the record name %q does not match %s, and the projector drops it", n, RecordNamePattern)
	}
	return nil
}

// RecordHeld is the record that says why the release step released nothing.
const RecordHeld = "ir_release_held"

// recordPrefix starts each record name of the agent.
const recordPrefix = "ir_"

// The state words of a record name.
const (
	stateContained = "contained"
	stateReleased  = "released"
)

// MaxGeneration bounds the scan for the generation of a containment. A
// target is contained and released a few times in one incident.
const MaxGeneration = 1000

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

// ActionKey is a short, stable name of one tool on one target: the first 16
// hexadecimal characters of the SHA-256 of the connector id, the tool and the
// vendor id. A record name holds this key and not the ids, because a tool id
// holds ":" and "-", and the projector drops a name with such a character.
func ActionKey(t respond.Target, tool string) string {
	sum := sha256.Sum256([]byte(t.Connector.ID + "\x00" + tool + "\x00" + t.VendorID))
	return hex.EncodeToString(sum[:])[:16]
}

// name builds a record name: ir_<state>_<key>_<generation>. The state is a
// word of this package or an outcome, so the name holds only letters, digits
// and "_".
func name(state, key string, gen int) string {
	return recordPrefix + state + "_" + key + "_" + strconv.Itoa(gen)
}

// RecordName is the name of the record of one action with one outcome in
// one generation. A generation is one containment of a target and its
// release. A containment after a release starts the next generation, so its
// records do not hide behind the records of the last one.
func RecordName(r respond.Result, gen int) string {
	state := string(r.Outcome)
	if r.Outcome == respond.OutcomeDone {
		state = stateContained
		if r.Action.Kind == respond.KindRelease {
			state = stateReleased
		}
	}
	return name(state, ActionKey(r.Action.Target, r.Action.Tool), gen)
}

// ContainedName is the name of the record that says the agent made the
// containment of one step on one target in the generation.
func ContainedName(t respond.Target, s respond.Step, gen int) string {
	return name(stateContained, ActionKey(t, s.Tool), gen)
}

// ReleasedName is the name of the record that says the agent released the
// containment of one step on one target in the generation.
func ReleasedName(t respond.Target, s respond.Step, gen int) string {
	return name(stateReleased, ActionKey(t, s.Undo), gen)
}

// LastGeneration returns the highest generation that holds a contained record
// of the step on the target, or 0 when none does. The agent writes the
// generations in order, so the scan stops at the first one that is missing.
func LastGeneration(records map[string]string, t respond.Target, s respond.Step) int {
	gen := 0
	for n := 1; n <= MaxGeneration; n++ {
		if _, ok := records[ContainedName(t, s, n)]; !ok {
			break
		}
		gen = n
	}
	return gen
}

// Record writes the outcome of one action in one generation on the Incident
// node. The value is the id that the daemon recorded for the call, so the
// release can ask the daemon about the call. A call with no id has the
// outcome as its value.
func (e *Emitter) Record(ctx context.Context, incidentKey string, r respond.Result, gen int) error {
	n := RecordName(r, gen)
	if err := checkName(n); err != nil {
		return err
	}
	value := r.CallID
	if value == "" {
		value = string(r.Outcome)
	}
	return e.observe(ctx, incidentObservation(incidentKey, map[string]string{n: value}, nil))
}

// Held writes why the release step released nothing.
func (e *Emitter) Held(ctx context.Context, incidentKey, reason string) error {
	if err := checkName(RecordHeld); err != nil {
		return err
	}
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
