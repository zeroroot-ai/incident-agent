// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package contain runs the two response passes over one incident: the
// containment and the release.
//
// # Containment
//
// The pass reads the incident, finds each place that a response connector can
// act on, and makes each containment action of that connector one time. The
// grant decides. A call that the daemon refuses is recorded and never made
// again in the pass. A call that waits in the approval queue is recorded, the
// pass goes on with the other actions, and at the end it makes the call one
// more time. A call that still waits stays in the queue for the next
// dispatch.
//
// # Release
//
// A containment stops its target on purpose, so the agent does not read the
// health signal of a contained target (ADR-0180). The release pass acts only
// when each finding that the Incident names as its cause is verified. The
// daemon sets that status. Then the pass undoes each containment that the
// agent recorded, and no other one.
package contain

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"github.com/zeroroot-ai/incident-agent/internal/emit"
	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
)

// MaxActions bounds the tool calls of one pass, with the second try of a
// pending call. An incident has a few targets. The bound keeps a graph that
// grew by mistake from turning one dispatch into hundreds of calls.
const MaxActions = 40

// Invoker makes one response action.
type Invoker interface {
	Invoke(ctx context.Context, a respond.Action) (respond.Result, error)
}

// Recorder writes the records of the pass on the Incident node.
type Recorder interface {
	Record(ctx context.Context, incidentKey string, r respond.Result) error
	Held(ctx context.Context, incidentKey, reason string) error
}

// Skip is a place that the pass did not act on, and why.
type Skip struct {
	Place  incident.Place
	Reason string
}

// Summary is what one pass did.
type Summary struct {
	Incident string
	// Results holds the last outcome of each action, in the order of the
	// calls.
	Results []respond.Result
	// Skipped lists the places that no response connector can act on.
	Skipped []Skip
	// Held is why the release pass released nothing. It is empty for a
	// containment pass and for a release that went ahead.
	Held string
	// Calls is the number of tool calls, with the second tries.
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
}

func (p Pass) check() error {
	if p.Reader == nil || p.Invoker == nil || p.Recorder == nil {
		return errors.New("contain: a pass needs a reader, an invoker and a recorder")
	}
	return nil
}

// Contain contains each target of the incident.
func (p Pass) Contain(ctx context.Context, key string) (Summary, error) {
	if err := p.check(); err != nil {
		return Summary{}, err
	}
	inc, err := p.Reader.Incident(ctx, key)
	if err != nil {
		return Summary{Incident: key}, fmt.Errorf("contain: read incident %s: %w", key, err)
	}
	targets, skipped := Targets(inc)
	actions := make([]respond.Action, 0, len(targets))
	for _, t := range targets {
		for _, s := range t.Connector.Steps {
			actions = append(actions, respond.Action{Kind: respond.KindContain, Target: t, Tool: s.Tool})
		}
	}
	sum, err := p.run(ctx, key, actions)
	sum.Skipped = skipped
	return sum, err
}

// Release releases each containment that the agent made, after each cause of
// the incident is verified.
func (p Pass) Release(ctx context.Context, key string) (Summary, error) {
	if err := p.check(); err != nil {
		return Summary{}, err
	}
	inc, err := p.Reader.Incident(ctx, key)
	if err != nil {
		return Summary{Incident: key}, fmt.Errorf("release: read incident %s: %w", key, err)
	}
	if held := heldReason(inc); held != "" {
		if err := p.Recorder.Held(ctx, key, held); err != nil {
			return Summary{Incident: key, Held: held}, fmt.Errorf("release: %w", err)
		}
		slog.Info("release held", "incident", key, "reason", held)
		return Summary{Incident: key, Held: held}, nil
	}
	targets, skipped := Targets(inc)
	actions := make([]respond.Action, 0, len(targets))
	for _, t := range targets {
		for _, s := range t.Connector.Steps {
			// A step with no undo has nothing to release. A step that the agent
			// did not record is a containment of someone else, and the agent
			// leaves it.
			if s.Undo == "" || !inc.HasRecord(emit.ContainedName(t, s)) || inc.HasRecord(emit.ReleasedName(t, s)) {
				continue
			}
			actions = append(actions, respond.Action{Kind: respond.KindRelease, Target: t, Tool: s.Undo})
		}
	}
	sum, err := p.run(ctx, key, actions)
	sum.Skipped = skipped
	return sum, err
}

// heldReason says why the release must wait, or returns "" when it can go.
func heldReason(inc incident.Incident) string {
	if len(inc.Causes) == 0 {
		return "the incident names no cause, so each containment stays"
	}
	c, ok := inc.AllVerified()
	if ok {
		return ""
	}
	status := respond.Clean(c.Status)
	if status == "" {
		status = "no status"
	}
	return fmt.Sprintf("the cause %s has the status %q and not %q, so each containment stays",
		respond.Clean(c.FindingID), status, incident.StatusVerified)
}

// run makes the actions, records each outcome, and makes each pending call
// one more time at the end.
func (p Pass) run(ctx context.Context, key string, actions []respond.Action) (Summary, error) {
	sum := Summary{Incident: key}
	pending := make([]int, 0, len(actions))
	for _, a := range actions {
		if sum.Calls >= MaxActions {
			sum.Capped = true
			break
		}
		r, err := p.call(ctx, key, a, &sum)
		if err != nil {
			return sum, err
		}
		sum.Results = append(sum.Results, r)
		if r.Outcome == respond.OutcomePending {
			pending = append(pending, len(sum.Results)-1)
		}
	}
	// The later try of a call that waits for a person. It is one more call,
	// with the same arguments, after the other work of the pass. The daemon
	// keys the approval by the agent and the arguments, so the call names the
	// same request and does not make a second one.
	for _, i := range pending {
		if sum.Calls >= MaxActions {
			sum.Capped = true
			break
		}
		r, err := p.call(ctx, key, sum.Results[i].Action, &sum)
		if err != nil {
			return sum, err
		}
		sum.Results[i] = r
	}
	return sum, nil
}

func (p Pass) call(ctx context.Context, key string, a respond.Action, sum *Summary) (respond.Result, error) {
	sum.Calls++
	r, err := p.Invoker.Invoke(ctx, a)
	if err != nil {
		return respond.Result{}, fmt.Errorf("contain: %w", err)
	}
	slog.Info("response action", "incident", key, "kind", a.Kind, "tool", a.ToolID(),
		"outcome", r.Outcome, "call", r.CallID)
	if err := p.Recorder.Record(ctx, key, r); err != nil {
		return respond.Result{}, fmt.Errorf("contain: record %s: %w", a.ToolID(), err)
	}
	return r, nil
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
