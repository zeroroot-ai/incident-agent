// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package incident holds the shape of one incident as the agent reads it from
// the graph: the Incident node, its alerts, the places that the alerts reach
// and the findings that the Incident names as its cause.
//
// The shape follows the incident report reader of the daemon
// (gibson internal/platform/incidentreport, queries.go on the branch
// integration/blue-team). An alert joins its incident with PART_OF and names
// what it is about with AFFECTS. The Incident node names its cause with
// CAUSED_BY (taxonomy version 6).
//
// Every value in this package comes from the graph. A tool of the buyer wrote
// most of them, so each one is untrusted data. No value here builds a tool
// id, a command or a URL. The respond package validates a place before it
// names a target.
package incident

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// The taxonomy labels that the agent reads and writes.
const (
	// LabelIncident is the label of the Incident node. Its identity property
	// is "key".
	LabelIncident = "Incident"
	// LabelAccount is the label of an identity that an alert reaches.
	LabelAccount = "Account"
	// LabelHost is the label of a host that an alert reaches.
	LabelHost = "Host"
	// LabelFinding is the label of a finding. Its identity property is
	// "brain_id".
	LabelFinding = "Finding"
)

// The relationship types of the incident (taxonomy version 6).
const (
	// RelCausedBy joins an Incident to the finding of its cause.
	RelCausedBy = "CAUSED_BY"
	// RelAffects joins an alert or a finding to the place that it is about.
	RelAffects = "AFFECTS"
)

// StatusVerified is the status of a finding whose fix the check that raised
// it passed (ADR-0178). The daemon sets it. The agent only reads it.
const StatusVerified = "verified"

// MaxKeyBytes bounds the key of an Incident. A longer key is not a key that a
// writer of the graph made, so the agent refuses it.
const MaxKeyBytes = 200

// Alert is one alert of the incident.
type Alert struct {
	Key      string
	Title    string
	Source   string
	Severity string
}

// Place is one node that an alert of the incident reaches with AFFECTS.
type Place struct {
	// Label is the taxonomy label of the place, for example Account or Host.
	Label string
	// Key is the identity of the place: its key, or its brain_id for a label
	// that the World identifies.
	Key string
}

// Cause is one finding that the Incident names with CAUSED_BY.
type Cause struct {
	FindingID string
	Title     string
	// Status is the status that the daemon set on the finding: open, fixing,
	// fixed or verified.
	Status string
}

// Incident is one incident as the graph holds it.
type Incident struct {
	Key     string
	Alerts  []Alert
	Reached []Place
	Causes  []Cause
	// Records are the properties of the Incident node. The agent writes a
	// record for each response action (package emit) and reads back only the
	// names, to know which containment it made. A value is never read as an
	// instruction.
	Records map[string]string
}

// Reader returns one incident from the graph.
//
// An unavailable read is never an empty incident. An incident that reads as
// empty would let the contain step report "nothing to contain" for an
// incident that nobody looked at.
type Reader interface {
	Incident(ctx context.Context, key string) (Incident, error)
}

// ValidKey checks the key of an Incident and returns it trimmed.
func ValidKey(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if key == "" {
		return "", errors.New("incident: no incident key")
	}
	if len(key) > MaxKeyBytes {
		return "", fmt.Errorf("incident: the key has %d bytes, and the limit is %d", len(key), MaxKeyBytes)
	}
	if strings.IndexFunc(key, unicode.IsControl) >= 0 {
		return "", errors.New("incident: the key holds a control character")
	}
	return key, nil
}

// AllVerified reports whether the incident names at least one cause and each
// cause is verified. It returns the first cause that is not verified when the
// answer is no.
func (i Incident) AllVerified() (Cause, bool) {
	if len(i.Causes) == 0 {
		return Cause{}, false
	}
	for _, c := range i.Causes {
		if strings.TrimSpace(c.Status) != StatusVerified {
			return c, false
		}
	}
	return Cause{}, true
}

// HasRecord reports whether the Incident node holds a record with the name.
func (i Incident) HasRecord(name string) bool {
	_, ok := i.Records[name]
	return ok
}
