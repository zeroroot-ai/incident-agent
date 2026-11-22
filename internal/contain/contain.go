// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package contain runs the two response passes over one incident: the
// containment and the release.
//
// # Records
//
// The agent writes one record on the Incident node for each call (package
// emit). The value of a record of a done call is the tool_call_id that the
// daemon recorded for the call. Any writer of the graph can write a property
// on the Incident node, so the agent trusts a record only after the daemon
// confirms that this agent made the call with that id, that tool and that
// target (CallChecker). A record that the daemon does not confirm is not a
// containment of this agent.
//
// A containment and its release are one generation. A containment after a
// release starts the next generation, with new record names, so a second
// release can run.
//
// # Containment
//
// The pass reads the incident and its records. It skips each target that the
// agent contained already in the current generation. It makes each other
// containment action one time. The grant decides. A call that the daemon
// refuses is recorded and never made again in the pass. A call that waits in
// the approval queue is recorded and stays in the queue. The next dispatch is
// its retry. A call that timed out or lost its transport has the outcome
// unknown: the agent writes no contained record for it, and the next dispatch
// calls it again.
//
// # Release
//
// A containment stops its target on purpose, so the agent does not read the
// health signal of a contained target (ADR-0180). The release pass acts only
// when the cause finding that this agent raised for the incident is verified.
// The daemon sets that status. A cause that another writer linked is not
// accepted. Then the pass undoes each containment of the current generation
// that the daemon confirms the agent made, and no other one.
package contain

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"unicode"

	"github.com/zeroroot-ai/incident-agent/internal/emit"
	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
)

// MaxActions bounds the tool calls of one pass. An incident has a few
// targets. The bound keeps a graph that grew by mistake from turning one
// dispatch into hundreds of calls.
const MaxActions = 40

// MaxCallIDBytes bounds the value of a record that the pass reads as a tool
// call id. The daemon mints a UUID.
const MaxCallIDBytes = 128

// ErrNotOwnCall means that the daemon holds no tool call of this agent with
// the id, the tool and the target of a record.
var ErrNotOwnCall = errors.New("contain: the daemon holds no call of this agent with the id, the tool and the target")

// Invoker makes one response action.
type Invoker interface {
	Invoke(ctx context.Context, a respond.Action) (respond.Result, error)
}

// Recorder writes the records of the pass on the Incident node.
type Recorder interface {
	Record(ctx context.Context, incidentKey string, r respond.Result, gen int) error
	Held(ctx context.Context, incidentKey, reason string) error
}

// CallChecker asks the daemon about one tool call. CheckCall returns nil only
// when the daemon recorded a call with the id that this agent made, with the
// tool and the arguments of the action, and the call took the action. It
// returns an error that wraps ErrNotOwnCall when the daemon holds no such
// call. Each other error means that the daemon could not answer.
type CallChecker interface {
	CheckCall(ctx context.Context, toolCallID string, a respond.Action) error
}

// CauseFinder finds the cause finding that this agent raised for an incident.
type CauseFinder interface {
	OwnCause(ctx context.Context, incidentKey string) (string, error)
}

// Skip is a place or a record that the pass did not act on, and why.
type Skip struct {
	Place incident.Place
	// Record is the name of the record that the pass did not trust. It is
	// empty for a place that no response connector can act on.
	Record string
	Reason string
}

// Summary is what one pass did.
type Summary struct {
	Incident string
	// Results holds the outcome of each action, in the order of the calls.
	Results []respond.Result
	// Already lists the containment actions that the agent made already in
	// the current generation. The pass did not call them again.
	Already []respond.Action
	// Skipped lists the places that no response connector can act on, and
	// the records that the daemon did not confirm.
	Skipped []Skip
	// Held is why the release pass released nothing. It is empty for a
	// containment pass and for a release that went ahead.
	Held string
	// Calls is the number of tool calls.
	Calls int
	// Capped is true when the pass stopped at MaxActions.
	Capped bool
}

// Count returns the number of results with the outcome.
func (s Summary) Count(o respond.Outcome) int {
	n := 0
	for _, r := range s.Results {
		if r.Outcome == o {
			n++
		}
	}
	return n
}

// Pass holds the parts of a response pass.
type Pass struct {
	Reader   incident.Reader
	Invoker  Invoker
	Recorder Recorder
	Calls    CallChecker
	// Causes is needed by the release pass only.
	Causes CauseFinder
}

func (p Pass) check(release bool) error {
	if p.Reader == nil || p.Invoker == nil || p.Recorder == nil || p.Calls == nil {
		return errors.New("contain: a pass needs a reader, an invoker, a recorder and a call checker")
	}
	if release && p.Causes == nil {
		return errors.New("contain: a release pass needs a cause finder")
	}
	return nil
}

// planned is one action of a pass with the generation of its record.
type planned struct {
	action respond.Action
	gen    int
}

// Contain contains each target of the incident that the agent did not
// contain already in the current generation.
func (p Pass) Contain(ctx context.Context, key string) (Summary, error) {
	if err := p.check(false); err != nil {
		return Summary{}, err
	}
	inc, err := p.Reader.Incident(ctx, key)
	if err != nil {
		return Summary{Incident: key}, fmt.Errorf("contain: read incident %s: %w", key, err)
	}
	sum := Summary{Incident: key}
	targets, skipped := Targets(inc)
	sum.Skipped = skipped
	var actions []planned
	for _, t := range targets {
		gen, active, err := p.generation(ctx, inc, t, &sum)
		if err != nil {
			return sum, err
		}
		for _, s := range t.Connector.Steps {
			a := respond.Action{Kind: respond.KindContain, Target: t, Tool: s.Tool}
			if active {
				owned, err := p.owned(ctx, inc, emit.ContainedName(t, s, gen), a, &sum)
				if err != nil {
					return sum, err
				}
				if owned {
					sum.Already = append(sum.Already, a)
					continue
				}
			}
			actions = append(actions, planned{action: a, gen: gen})
		}
	}
	return p.run(ctx, key, actions, sum)
}

// Release releases each containment of the current generation that the agent
// made, after the cause of this agent is verified.
func (p Pass) Release(ctx context.Context, key string) (Summary, error) {
	if err := p.check(true); err != nil {
		return Summary{}, err
	}
	inc, err := p.Reader.Incident(ctx, key)
	if err != nil {
		return Summary{Incident: key}, fmt.Errorf("release: read incident %s: %w", key, err)
	}
	held, err := HeldReason(ctx, p.Causes, inc)
	if err != nil {
		return Summary{Incident: key}, err
	}
	if held != "" {
		if err := p.Recorder.Held(ctx, key, held); err != nil {
			return Summary{Incident: key, Held: held}, fmt.Errorf("release: %w", err)
		}
		slog.Info("release held", "incident", key, "reason", held)
		return Summary{Incident: key, Held: held}, nil
	}
	sum := Summary{Incident: key}
	targets, skipped := Targets(inc)
	sum.Skipped = skipped
	var actions []planned
	for _, t := range targets {
		gen, active, err := p.generation(ctx, inc, t, &sum)
		if err != nil {
			return sum, err
		}
		if !active {
			continue
		}
		for _, s := range t.Connector.Steps {
			// A step with no undo has nothing to release. A release that the
			// agent recorded is not made again.
			if s.Undo == "" || inc.HasRecord(emit.ReleasedName(t, s, gen)) {
				continue
			}
			contained := respond.Action{Kind: respond.KindContain, Target: t, Tool: s.Tool}
			owned, err := p.owned(ctx, inc, emit.ContainedName(t, s, gen), contained, &sum)
			if err != nil {
				return sum, err
			}
			if !owned {
				continue
			}
			actions = append(actions, planned{
				action: respond.Action{Kind: respond.KindRelease, Target: t, Tool: s.Undo},
				gen:    gen,
			})
		}
	}
	return p.run(ctx, key, actions, sum)
}

// generation returns the generation of the target and whether the agent holds
// a containment of the target in it.
//
// The first step with an undo marks the generation: its contained record
// opens a generation and its released record closes it. A target with an
// open generation is active. A target with a closed generation, or with none,
// gets the next generation. A contained record that the daemon does not
// confirm opens nothing, and the next write of the agent takes its name.
func (p Pass) generation(
	ctx context.Context, inc incident.Incident, t respond.Target, sum *Summary,
) (gen int, active bool, err error) {
	mark, ok := markStep(t)
	if !ok {
		return 1, false, nil
	}
	gen = emit.LastGeneration(inc.Records, t, mark)
	if gen == 0 {
		return 1, false, nil
	}
	if inc.HasRecord(emit.ReleasedName(t, mark, gen)) {
		return gen + 1, false, nil
	}
	a := respond.Action{Kind: respond.KindContain, Target: t, Tool: mark.Tool}
	active, err = p.owned(ctx, inc, emit.ContainedName(t, mark, gen), a, sum)
	if err != nil {
		return 0, false, err
	}
	return gen, active, nil
}

// markStep returns the first step of the connector with an undo.
func markStep(t respond.Target) (respond.Step, bool) {
	for _, s := range t.Connector.Steps {
		if s.Undo != "" {
			return s, true
		}
	}
	return respond.Step{}, false
}

// owned reports whether the record exists and names a call that this agent
// made with the action. A record that fails is added to the skips, one time.
func (p Pass) owned(
	ctx context.Context, inc incident.Incident, name string, a respond.Action, sum *Summary,
) (bool, error) {
	value, ok := inc.Records[name]
	if !ok {
		return false, nil
	}
	if reason := callIDProblem(value); reason != "" {
		addSkip(sum, name, reason)
		return false, nil
	}
	err := p.Calls.CheckCall(ctx, value, a)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotOwnCall):
		addSkip(sum, name, "the daemon holds no call of this agent with the id of the record")
		return false, nil
	default:
		return false, fmt.Errorf("contain: check the call of the record %s: %w", name, err)
	}
}

// callIDProblem says why a record value is not a tool call id, or returns "".
func callIDProblem(v string) string {
	switch {
	case strings.TrimSpace(v) == "":
		return "the record holds no tool call id"
	case len(v) > MaxCallIDBytes:
		return "the record holds a value that is too long for a tool call id"
	case strings.IndexFunc(v, unicode.IsSpace) >= 0 || strings.IndexFunc(v, unicode.IsControl) >= 0:
		return "the record holds a value that is not a tool call id"
	case respond.Outcome(v) == respond.OutcomeDone:
		return "the daemon recorded no tool call id for the call"
	default:
		return ""
	}
}

func addSkip(sum *Summary, record, reason string) {
	for _, sk := range sum.Skipped {
		if sk.Record == record {
			return
		}
	}
	sum.Skipped = append(sum.Skipped, Skip{Record: record, Reason: reason})
}

// HeldReason says why a release must wait, or returns "" when it can go.
// Only the cause finding that this agent raised counts, and the daemon sets
// its status.
func HeldReason(ctx context.Context, causes CauseFinder, inc incident.Incident) (string, error) {
	own, err := causes.OwnCause(ctx, inc.Key)
	if err != nil {
		return "", fmt.Errorf("release: find the cause of this agent: %w", err)
	}
	if own == "" {
		return "this agent raised no cause finding for the incident in this mission, so each containment stays", nil
	}
	c, ok := inc.Cause(own)
	if !ok {
		return fmt.Sprintf("the incident does not name the cause %s that this agent raised, so each containment stays",
			respond.Clean(own)), nil
	}
	if c.Verified() {
		return "", nil
	}
	status := respond.Clean(c.Status)
	if status == "" {
		status = "no status"
	}
	return fmt.Sprintf("the cause %s has the status %q and not %q, so each containment stays",
		respond.Clean(c.FindingID), status, incident.StatusVerified), nil
}

// run makes the actions one time each and records each outcome. A call that
// waits for a person is not made again in the pass: the daemon keys the
// approval by the agent and the arguments, and the next dispatch is the
// retry.
func (p Pass) run(ctx context.Context, key string, actions []planned, sum Summary) (Summary, error) {
	for _, pl := range actions {
		if sum.Calls >= MaxActions {
			sum.Capped = true
			break
		}
		sum.Calls++
		r, err := p.Invoker.Invoke(ctx, pl.action)
		if err != nil {
			return sum, fmt.Errorf("contain: %w", err)
		}
		slog.Info("response action", "incident", key, "kind", pl.action.Kind, "tool", pl.action.ToolID(),
			"outcome", r.Outcome, "call", r.CallID, "generation", pl.gen)
		if err := p.Recorder.Record(ctx, key, r, pl.gen); err != nil {
			return sum, fmt.Errorf("contain: record %s: %w", pl.action.ToolID(), err)
		}
		sum.Results = append(sum.Results, r)
	}
	return sum, nil
}

// Targets returns the places of the incident that a response connector can
// act on, one time each, in a fixed order. It returns each other place with
// the reason.
func Targets(inc incident.Incident) ([]respond.Target, []Skip) {
	seen := map[string]bool{}
	places := append([]incident.Place(nil), inc.Reached...)
	targets := make([]respond.Target, 0, len(places))
	skipped := make([]Skip, 0, len(places))
	sort.SliceStable(places, func(i, j int) bool {
		if places[i].Label != places[j].Label {
			return places[i].Label < places[j].Label
		}
		return places[i].Key < places[j].Key
	})
	for _, pl := range places {
		id := pl.Label + "\x00" + pl.Key
		if seen[id] {
			continue
		}
		seen[id] = true
		t, err := respond.ParseTarget(pl)
		if err != nil {
			skipped = append(skipped, Skip{Place: pl, Reason: err.Error()})
			continue
		}
		targets = append(targets, t)
	}
	return targets, skipped
}
