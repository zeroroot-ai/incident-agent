// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package contain_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroroot-ai/incident-agent/internal/contain"
	"github.com/zeroroot-ai/incident-agent/internal/emit"
	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
)

const (
	oktaID   = "00ub0oNGTSWTBKOLGLNR"
	falconID = "0123456789abcdef0123456789abcdef"
)

type fakeReader struct {
	inc incident.Incident
	err error
}

func (f fakeReader) Incident(context.Context, string) (incident.Incident, error) { return f.inc, f.err }

// fakeInvoker answers by tool id. A list of outcomes is used in order, so a
// test can make a call wait the first time and pass the second time.
type fakeInvoker struct {
	answers map[string][]respond.Outcome
	calls   []string
}

func (f *fakeInvoker) Invoke(_ context.Context, a respond.Action) (respond.Result, error) {
	id := a.ToolID()
	f.calls = append(f.calls, id)
	out := respond.OutcomeDone
	if list := f.answers[id]; len(list) > 0 {
		out = list[0]
		f.answers[id] = list[1:]
	}
	r := respond.Result{Action: a, Outcome: out}
	if out != respond.OutcomeDone {
		r.Detail = "the daemon said " + string(out)
	}
	return r, nil
}

type fakeRecorder struct {
	records []string
	held    string
}

func (f *fakeRecorder) Record(_ context.Context, _ string, r respond.Result) error {
	f.records = append(f.records, emit.RecordName(r))
	return nil
}

func (f *fakeRecorder) Held(_ context.Context, _, reason string) error {
	f.held = reason
	return nil
}

func twoTargets() incident.Incident {
	return incident.Incident{
		Key:    "inc-1",
		Alerts: []incident.Alert{{Key: "a-1", Title: "impossible travel"}},
		Reached: []incident.Place{
			{Label: incident.LabelAccount, Key: placeKey("okta-response", oktaID)},
			{Label: incident.LabelHost, Key: placeKey("crowdstrike-response", falconID)},
			// The same host from a second alert is one target.
			{Label: incident.LabelHost, Key: placeKey("crowdstrike-response", falconID)},
			// A host that a scan found has a brain id and no connector.
			{Label: incident.LabelHost, Key: "5f0c3f0e-0000-4000-8000-000000000001"},
		},
	}
}

func TestContain_ActsOnEachTargetOnceAndSkipsTheRest(t *testing.T) {
	inv := &fakeInvoker{answers: map[string][]respond.Outcome{}}
	rec := &fakeRecorder{}
	p := contain.Pass{Reader: fakeReader{inc: twoTargets()}, Invoker: inv, Recorder: rec}
	sum, err := p.Contain(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mcp:okta-response:suspend_user",
		"mcp:okta-response:revoke_user_sessions",
		"mcp:crowdstrike-response:contain_host",
	}
	if strings.Join(inv.calls, ",") != strings.Join(want, ",") {
		t.Errorf("calls = %v, want %v", inv.calls, want)
	}
	if sum.Count(respond.OutcomeDone) != 3 || len(rec.records) != 3 {
		t.Errorf("done %d records %v", sum.Count(respond.OutcomeDone), rec.records)
	}
	if len(sum.Skipped) != 1 || !strings.Contains(sum.Skipped[0].Reason, "no connector") {
		t.Errorf("skipped = %+v, want the host with no connector", sum.Skipped)
	}
}

// A refused call is never made again. A pending call is made one more time
// at the end of the pass, after the other work.
func TestContain_RetriesAPendingCallOnceAndNeverARefusedOne(t *testing.T) {
	inv := &fakeInvoker{answers: map[string][]respond.Outcome{
		"mcp:okta-response:suspend_user":         {respond.OutcomePending, respond.OutcomeDone},
		"mcp:okta-response:revoke_user_sessions": {respond.OutcomeRefused},
		"mcp:crowdstrike-response:contain_host":  {respond.OutcomePending, respond.OutcomePending},
	}}
	rec := &fakeRecorder{}
	p := contain.Pass{Reader: fakeReader{inc: twoTargets()}, Invoker: inv, Recorder: rec}
	sum, err := p.Contain(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mcp:okta-response:suspend_user",
		"mcp:okta-response:revoke_user_sessions",
		"mcp:crowdstrike-response:contain_host",
		"mcp:okta-response:suspend_user",
		"mcp:crowdstrike-response:contain_host",
	}
	if strings.Join(inv.calls, ",") != strings.Join(want, ",") {
		t.Errorf("calls =\n%v\nwant\n%v", inv.calls, want)
	}
	if sum.Count(respond.OutcomeDone) != 1 || sum.Count(respond.OutcomeRefused) != 1 ||
		sum.Count(respond.OutcomePending) != 1 {
		t.Errorf("results = %+v", sum.Results)
	}
	if sum.Calls != 5 {
		t.Errorf("calls = %d, want 5", sum.Calls)
	}
	wantRec := "contained.mcp:okta-response:suspend_user." + oktaID
	if !strings.Contains(strings.Join(rec.records, " "), wantRec) {
		t.Errorf("records %v lack %s", rec.records, wantRec)
	}
}

func TestContain_StopsAtMaxActions(t *testing.T) {
	inc := incident.Incident{Key: "inc-1"}
	for i := range contain.MaxActions + 5 {
		id := fmt.Sprintf("%032x", i)
		inc.Reached = append(inc.Reached,
			incident.Place{Label: incident.LabelHost, Key: placeKey("crowdstrike-response", id)})
	}
	inv := &fakeInvoker{answers: map[string][]respond.Outcome{}}
	p := contain.Pass{Reader: fakeReader{inc: inc}, Invoker: inv, Recorder: &fakeRecorder{}}
	sum, err := p.Contain(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.calls) != contain.MaxActions || !sum.Capped {
		t.Errorf("calls %d capped %v, want %d and capped", len(inv.calls), sum.Capped, contain.MaxActions)
	}
}

func TestContain_AFailedReadFailsAndCallsNothing(t *testing.T) {
	boom := errors.New("graph down")
	inv := &fakeInvoker{}
	p := contain.Pass{Reader: fakeReader{err: boom}, Invoker: inv, Recorder: &fakeRecorder{}}
	_, err := p.Contain(context.Background(), "inc-1")
	if !errors.Is(err, boom) || len(inv.calls) != 0 {
		t.Fatalf("err %v calls %v", err, inv.calls)
	}
}

func contained(inc incident.Incident) incident.Incident {
	inc.Records = map[string]string{
		"contained.mcp:okta-response:suspend_user." + oktaID:         "done",
		"contained.mcp:okta-response:revoke_user_sessions." + oktaID: "done",
	}
	return inc
}

func TestRelease_HoldsUntilEachCauseIsVerified(t *testing.T) {
	for name, causes := range map[string][]incident.Cause{
		"no cause": nil,
		"fixing":   {{FindingID: "f-1", Status: "fixing"}},
		"fixed":    {{FindingID: "f-1", Status: "fixed"}},
		"one of two verified": {
			{FindingID: "f-1", Status: incident.StatusVerified},
			{FindingID: "f-2", Status: "open"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			inc := contained(twoTargets())
			inc.Causes = causes
			inv := &fakeInvoker{}
			rec := &fakeRecorder{}
			p := contain.Pass{Reader: fakeReader{inc: inc}, Invoker: inv, Recorder: rec}
			sum, err := p.Release(context.Background(), "inc-1")
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.calls) != 0 || sum.Held == "" || rec.held == "" {
				t.Errorf("calls %v held %q recorded %q, want no call and a held reason", inv.calls, sum.Held, rec.held)
			}
		})
	}
}

// The release undoes only what the agent recorded. The host has no record,
// so its containment is someone else's and stays. A revoked session has no
// undo.
func TestRelease_UndoesOnlyTheRecordedContainment(t *testing.T) {
	inc := contained(twoTargets())
	inc.Causes = []incident.Cause{{FindingID: "f-1", Status: incident.StatusVerified}}
	inv := &fakeInvoker{answers: map[string][]respond.Outcome{}}
	rec := &fakeRecorder{}
	p := contain.Pass{Reader: fakeReader{inc: inc}, Invoker: inv, Recorder: rec}
	sum, err := p.Release(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(inv.calls, ",") != "mcp:okta-response:unsuspend_user" {
		t.Errorf("calls = %v, want only unsuspend_user", inv.calls)
	}
	if sum.Held != "" || len(rec.records) != 1 || rec.records[0] != "released.mcp:okta-response:unsuspend_user."+oktaID {
		t.Errorf("held %q records %v", sum.Held, rec.records)
	}
}

func TestRelease_ARecordedReleaseIsNotMadeAgain(t *testing.T) {
	inc := contained(twoTargets())
	inc.Causes = []incident.Cause{{FindingID: "f-1", Status: incident.StatusVerified}}
	inc.Records["released.mcp:okta-response:unsuspend_user."+oktaID] = "done"
	inv := &fakeInvoker{}
	p := contain.Pass{Reader: fakeReader{inc: inc}, Invoker: inv, Recorder: &fakeRecorder{}}
	if _, err := p.Release(context.Background(), "inc-1"); err != nil {
		t.Fatal(err)
	}
	if len(inv.calls) != 0 {
		t.Errorf("calls = %v, want none", inv.calls)
	}
}

func TestPass_NeedsEachPart(t *testing.T) {
	if _, err := (contain.Pass{}).Contain(context.Background(), "inc-1"); err == nil {
		t.Fatal("want an error")
	}
	if _, err := (contain.Pass{}).Release(context.Background(), "inc-1"); err == nil {
		t.Fatal("want an error")
	}
}

// placeKey is the key of a place that names a vendor id of a connector: the
// composite key of the identity properties connector and vendor_id.
func placeKey(connectorID, vendorID string) string {
	return "connector=" + connectorID + "|vendor_id=" + vendorID
}
