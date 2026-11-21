// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package emit_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/zeroroot-ai/incident-agent/internal/emit"
	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
	"github.com/zeroroot-ai/sdk/agent"
)

type fakeObserver struct {
	got []agent.LifecycleEntityObservation
}

func (f *fakeObserver) Observe(_ context.Context, obs agent.Observation) error {
	f.got = append(f.got, obs.(agent.LifecycleEntityObservation))
	return nil
}

const mdeID = "0123456789abcdef0123456789abcdef01234567"

func result(t *testing.T, kind respond.Kind, out respond.Outcome) respond.Result {
	t.Helper()
	tg, err := respond.ParseTarget(incident.Place{
		Label: incident.LabelHost, Key: placeKey("defender-endpoint-response", mdeID),
	})
	if err != nil {
		t.Fatal(err)
	}
	tool := tg.Connector.Steps[0].Tool
	if kind == respond.KindRelease {
		tool = tg.Connector.Steps[0].Undo
	}
	return respond.Result{Action: respond.Action{Kind: kind, Target: tg, Tool: tool}, Outcome: out, Detail: "why"}
}

// projectorKeyPattern is copied from gibson, branch integration/blue-team,
// internal/server/daemon/graph_projector_neo4j.go: safeTaxonomyLabel. The
// projector keeps a property only when its name matches it
// (entityUpsertParams), and it drops each other name with no error. The copy
// is a literal on purpose: a change of emit.RecordNamePattern must not pass
// this test.
var projectorKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// Each record name that the agent can write must reach the Incident node. The
// test builds the name of each outcome of each tool of each connector in the
// table, in a low and a high generation, and the held record.
func TestRecordName_EachNameIsKeptByTheProjector(t *testing.T) {
	outcomes := []respond.Outcome{
		respond.OutcomeDone, respond.OutcomePending, respond.OutcomeRefused,
		respond.OutcomeFailed, respond.OutcomeUnknown,
	}
	names := []string{emit.RecordHeld}
	for _, tg := range allTargets(t) {
		for _, s := range tg.Connector.Steps {
			for _, gen := range []int{1, emit.MaxGeneration} {
				names = append(names, emit.ContainedName(tg, s, gen))
				for _, out := range outcomes {
					names = append(names, emit.RecordName(respond.Result{
						Action:  respond.Action{Kind: respond.KindContain, Target: tg, Tool: s.Tool},
						Outcome: out,
					}, gen))
				}
				if s.Undo == "" {
					continue
				}
				names = append(names, emit.ReleasedName(tg, s, gen))
				for _, out := range outcomes {
					names = append(names, emit.RecordName(respond.Result{
						Action:  respond.Action{Kind: respond.KindRelease, Target: tg, Tool: s.Undo},
						Outcome: out,
					}, gen))
				}
			}
		}
	}
	for _, n := range names {
		if !projectorKeyPattern.MatchString(n) {
			t.Errorf("the projector drops the record name %q", n)
		}
		if len(n) > emit.MaxRecordNameBytes {
			t.Errorf("the record name %q is longer than %d bytes", n, emit.MaxRecordNameBytes)
		}
	}
}

func TestRecordName_PairsWithContainedAndReleased(t *testing.T) {
	tg := result(t, respond.KindContain, respond.OutcomeDone).Action.Target
	step := tg.Connector.Steps[0]
	if emit.ContainedName(tg, step, 3) != emit.RecordName(result(t, respond.KindContain, respond.OutcomeDone), 3) {
		t.Error("ContainedName and RecordName of a done containment differ")
	}
	if emit.ReleasedName(tg, step, 3) != emit.RecordName(result(t, respond.KindRelease, respond.OutcomeDone), 3) {
		t.Error("ReleasedName and RecordName of a done release differ")
	}
	if emit.ContainedName(tg, step, 1) == emit.ContainedName(tg, step, 2) {
		t.Error("two generations have one name")
	}
	if emit.RecordName(result(t, respond.KindContain, respond.OutcomePending), 1) ==
		emit.RecordName(result(t, respond.KindContain, respond.OutcomeRefused), 1) {
		t.Error("two outcomes have one name")
	}
	other := tg
	other.VendorID = strings.Repeat("f", len(tg.VendorID))
	if emit.ContainedName(tg, step, 1) == emit.ContainedName(other, step, 1) {
		t.Error("two targets have one name")
	}
}

func TestLastGeneration(t *testing.T) {
	tg := result(t, respond.KindContain, respond.OutcomeDone).Action.Target
	step := tg.Connector.Steps[0]
	recs := map[string]string{}
	if got := emit.LastGeneration(recs, tg, step); got != 0 {
		t.Errorf("no record: %d", got)
	}
	recs[emit.ContainedName(tg, step, 1)] = "call-1"
	recs[emit.ReleasedName(tg, step, 1)] = "call-2"
	recs[emit.ContainedName(tg, step, 2)] = "call-3"
	if got := emit.LastGeneration(recs, tg, step); got != 2 {
		t.Errorf("two generations: %d", got)
	}
}

func TestRecord_WritesTheCallIDOnTheIncident(t *testing.T) {
	obs := &fakeObserver{}
	e, err := emit.New(obs)
	if err != nil {
		t.Fatal(err)
	}
	r := result(t, respond.KindContain, respond.OutcomeDone)
	r.CallID = "0b5e2c1a-0000-4000-8000-000000000001"
	if err := e.Record(context.Background(), "inc-1", r, 1); err != nil {
		t.Fatal(err)
	}
	if len(obs.got) != 1 {
		t.Fatalf("observations = %d", len(obs.got))
	}
	o := obs.got[0]
	if o.Label != "Incident" || o.IDProperties["key"] != "inc-1" || len(o.Properties) != 1 || len(o.Edges) != 0 {
		t.Errorf("observation = %+v", o)
	}
	if o.Properties[emit.ContainedName(r.Action.Target, r.Action.Target.Connector.Steps[0], 1)] != r.CallID {
		t.Errorf("properties = %v, want the call id", o.Properties)
	}
	refused := result(t, respond.KindContain, respond.OutcomeRefused)
	if err := e.Record(context.Background(), "inc-1", refused, 1); err != nil {
		t.Fatal(err)
	}
	for k, v := range obs.got[1].Properties {
		if v != string(respond.OutcomeRefused) {
			t.Errorf("%s = %q, want the outcome for a call with no id", k, v)
		}
	}
}

// allTargets returns one target of each connector of the table.
func allTargets(t *testing.T) []respond.Target {
	t.Helper()
	places := []incident.Place{
		{Label: incident.LabelAccount, Key: placeKey("okta-response", "00ub0oNGTSWTBKOLGLNR")},
		{Label: incident.LabelAccount, Key: placeKey("entra-id-response", "87d349ed-44d7-43e1-9a83-5f2406dee5bd")},
		{Label: incident.LabelHost, Key: placeKey("crowdstrike-response", "0123456789abcdef0123456789abcdef")},
		{Label: incident.LabelHost, Key: placeKey("defender-endpoint-response", mdeID)},
		{Label: incident.LabelHost, Key: placeKey("sentinelone-response", "225494730938493804")},
	}
	out := make([]respond.Target, 0, len(places))
	for _, p := range places {
		tg, err := respond.ParseTarget(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, tg)
	}
	return out
}

func TestLinkCause_WritesCausedByAndAffects(t *testing.T) {
	obs := &fakeObserver{}
	e, err := emit.New(obs)
	if err != nil {
		t.Fatal(err)
	}
	place := incident.Place{Label: incident.LabelAccount, Key: "acct-a"}
	if err := e.LinkCause(context.Background(), "inc-1", "f-1", place); err != nil {
		t.Fatal(err)
	}
	if len(obs.got) != 2 {
		t.Fatalf("observations = %d", len(obs.got))
	}
	in, fd := obs.got[0], obs.got[1]
	if in.Label != "Incident" || len(in.Edges) != 1 || in.Edges[0].Type != "CAUSED_BY" ||
		in.Edges[0].TargetLabel != "Finding" || in.Edges[0].TargetIDProperties["brain_id"] != "f-1" {
		t.Errorf("incident = %+v", in)
	}
	if fd.Label != "Finding" || fd.IDProperties["brain_id"] != "f-1" || len(fd.Properties) != 0 ||
		fd.Edges[0].Type != "AFFECTS" || fd.Edges[0].TargetLabel != "Account" ||
		fd.Edges[0].TargetIDProperties["key"] != "acct-a" {
		t.Errorf("finding = %+v", fd)
	}
	if err := e.LinkCause(context.Background(), "inc-1", "", place); err == nil {
		t.Error("a link with no finding: want an error")
	}
}

func TestHeld(t *testing.T) {
	obs := &fakeObserver{}
	e, err := emit.New(obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Held(context.Background(), "inc-1", "wait\nfor the fix"); err != nil {
		t.Fatal(err)
	}
	if got := obs.got[0].Properties[emit.RecordHeld]; got != "wait for the fix" {
		t.Errorf("held = %q", got)
	}
	if _, err := emit.New(nil); err == nil {
		t.Error("New(nil): want an error")
	}
}

// placeKey is the key of a place that names a vendor id of a connector: the
// composite key of the identity properties connector and vendor_id.
func placeKey(connectorID, vendorID string) string {
	return "connector=" + connectorID + "|vendor_id=" + vendorID
}
