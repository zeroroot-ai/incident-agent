// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package emit_test

import (
	"context"
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

func TestRecordName(t *testing.T) {
	for _, tc := range []struct {
		kind respond.Kind
		out  respond.Outcome
		want string
	}{
		{respond.KindContain, respond.OutcomeDone, "contained.mcp:defender-endpoint-response:isolate_device." + mdeID},
		{respond.KindRelease, respond.OutcomeDone, "released.mcp:defender-endpoint-response:release_device." + mdeID},
		{
			respond.KindContain, respond.OutcomePending,
			"pending_authorization.mcp:defender-endpoint-response:isolate_device." + mdeID,
		},
		{respond.KindContain, respond.OutcomeRefused, "refused.mcp:defender-endpoint-response:isolate_device." + mdeID},
	} {
		r := result(t, tc.kind, tc.out)
		if got := emit.RecordName(r); got != tc.want {
			t.Errorf("RecordName = %s, want %s", got, tc.want)
		}
		if len(emit.RecordName(r)) > emit.MaxRecordNameBytes {
			t.Errorf("%s is longer than the limit of the daemon", emit.RecordName(r))
		}
	}
	tg := result(t, respond.KindContain, respond.OutcomeDone).Action.Target
	step := tg.Connector.Steps[0]
	if emit.ContainedName(tg, step) != emit.RecordName(result(t, respond.KindContain, respond.OutcomeDone)) {
		t.Error("ContainedName and RecordName of a done containment differ")
	}
	if emit.ReleasedName(tg, step) != emit.RecordName(result(t, respond.KindRelease, respond.OutcomeDone)) {
		t.Error("ReleasedName and RecordName of a done release differ")
	}
}

func TestRecord_WritesOnePropertyOnTheIncident(t *testing.T) {
	obs := &fakeObserver{}
	e, err := emit.New(obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Record(context.Background(), "inc-1", result(t, respond.KindContain, respond.OutcomeRefused)); err != nil {
		t.Fatal(err)
	}
	if len(obs.got) != 1 {
		t.Fatalf("observations = %d", len(obs.got))
	}
	o := obs.got[0]
	if o.Label != "Incident" || o.IDProperties["key"] != "inc-1" || len(o.Properties) != 1 || len(o.Edges) != 0 {
		t.Errorf("observation = %+v", o)
	}
	if o.Properties["refused.mcp:defender-endpoint-response:isolate_device."+mdeID] != "why" {
		t.Errorf("properties = %v", o.Properties)
	}
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
