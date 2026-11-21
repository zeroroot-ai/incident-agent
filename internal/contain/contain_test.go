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
	// rec, when set, adds the records that the pass wrote, as the graph
	// holds them after the projector ran.
	rec *fakeRecorder
}

func (f fakeReader) Incident(context.Context, string) (incident.Incident, error) {
	inc := f.inc
	if f.rec != nil {
		inc.Records = map[string]string{}
		for k, v := range f.inc.Records {
			inc.Records[k] = v
		}
		for k, v := range f.rec.props {
			inc.Records[k] = v
		}
	}
	return inc, f.err
}

// call is one call that the fake daemon recorded, as the flight recorder
// holds it: the id that the daemon minted, the tool and the arguments.
type call struct {
	tool string
	args map[string]any
	done bool
}

// fakeDaemon answers by tool id, mints a tool call id for each call, and
// records each call that this agent made. A list of outcomes is used in
// order.
type fakeDaemon struct {
	answers map[string][]respond.Outcome
	calls   []string
	record  map[string]call
	// down makes CheckCall fail as a daemon that cannot answer.
	down bool
}

func newDaemon(answers map[string][]respond.Outcome) *fakeDaemon {
	if answers == nil {
		answers = map[string][]respond.Outcome{}
	}
	return &fakeDaemon{answers: answers, record: map[string]call{}}
}

func (f *fakeDaemon) Invoke(_ context.Context, a respond.Action) (respond.Result, error) {
	id := a.ToolID()
	f.calls = append(f.calls, id)
	out := respond.OutcomeDone
	if list := f.answers[id]; len(list) > 0 {
		out = list[0]
		f.answers[id] = list[1:]
	}
	callID := fmt.Sprintf("0b5e2c1a-0000-4000-8000-%012d", len(f.calls))
	f.record[callID] = call{tool: id, args: a.Args(), done: out == respond.OutcomeDone}
	r := respond.Result{Action: a, Outcome: out, CallID: callID}
	if out != respond.OutcomeDone {
		r.Detail = "the daemon said " + string(out)
	}
	return r, nil
}

// CheckCall confirms a call only when the daemon recorded it for this agent
// with the same tool and arguments, and the call took the action.
func (f *fakeDaemon) CheckCall(_ context.Context, id string, a respond.Action) error {
	if f.down {
		return errors.New("the daemon cannot answer")
	}
	c, ok := f.record[id]
	if !ok || !c.done || c.tool != a.ToolID() || fmt.Sprint(c.args) != fmt.Sprint(a.Args()) {
		return fmt.Errorf("call %s: %w", id, contain.ErrNotOwnCall)
	}
	return nil
}

type fakeRecorder struct {
	props map[string]string
	names []string
	held  string
}

func (f *fakeRecorder) Record(_ context.Context, _ string, r respond.Result, gen int) error {
	if f.props == nil {
		f.props = map[string]string{}
	}
	n := emit.RecordName(r, gen)
	f.names = append(f.names, n)
	v := r.CallID
	if v == "" {
		v = string(r.Outcome)
	}
	f.props[n] = v
	return nil
}

func (f *fakeRecorder) Held(_ context.Context, _, reason string) error {
	f.held = reason
	return nil
}

// fakeCauses returns the cause finding of this agent.
type fakeCauses struct{ id string }

func (f fakeCauses) OwnCause(context.Context, string) (string, error) { return f.id, nil }

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

func target(t *testing.T, connectorID, vendorID string) respond.Target {
	t.Helper()
	label := incident.LabelHost
	if connectorID == "okta-response" {
		label = incident.LabelAccount
	}
	tg, err := respond.ParseTarget(incident.Place{Label: label, Key: placeKey(connectorID, vendorID)})
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func pass(d *fakeDaemon, rec *fakeRecorder, inc incident.Incident, causeID string) contain.Pass {
	return contain.Pass{
		Reader: fakeReader{inc: inc, rec: rec}, Invoker: d, Recorder: rec, Calls: d,
		Causes: fakeCauses{id: causeID},
	}
}

func TestContain_ActsOnEachTargetOnceAndSkipsTheRest(t *testing.T) {
	d := newDaemon(nil)
	rec := &fakeRecorder{}
	sum, err := pass(d, rec, twoTargets(), "").Contain(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mcp:okta-response:suspend_user",
		"mcp:okta-response:revoke_user_sessions",
		"mcp:crowdstrike-response:contain_host",
	}
	if strings.Join(d.calls, ",") != strings.Join(want, ",") {
		t.Errorf("calls = %v, want %v", d.calls, want)
	}
	if sum.Count(respond.OutcomeDone) != 3 || len(rec.names) != 3 {
		t.Errorf("done %d records %v", sum.Count(respond.OutcomeDone), rec.names)
	}
	if len(sum.Skipped) != 1 || !strings.Contains(sum.Skipped[0].Reason, "no connector") {
		t.Errorf("skipped = %+v, want the host with no connector", sum.Skipped)
	}
	okta := target(t, "okta-response", oktaID)
	if v := rec.props[emit.ContainedName(okta, okta.Connector.Steps[0], 1)]; d.record[v].tool != want[0] {
		t.Errorf("the contained record holds %q, want the tool call id of suspend_user", v)
	}
}

// A pending call is not made again in the pass: the next dispatch is the
// retry. A refused call is never made again.
func TestContain_MakesEachCallOneTime(t *testing.T) {
	d := newDaemon(map[string][]respond.Outcome{
		"mcp:okta-response:suspend_user":         {respond.OutcomePending, respond.OutcomeDone},
		"mcp:okta-response:revoke_user_sessions": {respond.OutcomeRefused},
		"mcp:crowdstrike-response:contain_host":  {respond.OutcomePending},
	})
	rec := &fakeRecorder{}
	sum, err := pass(d, rec, twoTargets(), "").Contain(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mcp:okta-response:suspend_user",
		"mcp:okta-response:revoke_user_sessions",
		"mcp:crowdstrike-response:contain_host",
	}
	if strings.Join(d.calls, ",") != strings.Join(want, ",") || sum.Calls != 3 {
		t.Errorf("calls =\n%v\nwant\n%v", d.calls, want)
	}
	if sum.Count(respond.OutcomePending) != 2 || sum.Count(respond.OutcomeRefused) != 1 {
		t.Errorf("results = %+v", sum.Results)
	}
}

// A call that timed out is unknown. The pass writes no contained record for
// it, and the next pass calls it again.
func TestContain_AnUnknownCallWritesNoContainedRecord(t *testing.T) {
	d := newDaemon(map[string][]respond.Outcome{
		"mcp:crowdstrike-response:contain_host": {respond.OutcomeUnknown},
	})
	rec := &fakeRecorder{}
	p := pass(d, rec, twoTargets(), "")
	if _, err := p.Contain(context.Background(), "inc-1"); err != nil {
		t.Fatal(err)
	}
	host := target(t, "crowdstrike-response", falconID)
	if _, ok := rec.props[emit.ContainedName(host, host.Connector.Steps[0], 1)]; ok {
		t.Fatalf("an unknown call wrote a contained record: %v", rec.props)
	}
	d.calls = nil
	if _, err := p.Contain(context.Background(), "inc-1"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.calls, ",") != "mcp:crowdstrike-response:contain_host" {
		t.Errorf("second pass calls = %v, want only the unknown call again", d.calls)
	}
}

// A second contain pass reads the records and skips each target that the
// agent contained already.
func TestContain_SkipsATargetThatIsContainedAlready(t *testing.T) {
	d := newDaemon(nil)
	rec := &fakeRecorder{}
	p := pass(d, rec, twoTargets(), "")
	if _, err := p.Contain(context.Background(), "inc-1"); err != nil {
		t.Fatal(err)
	}
	d.calls = nil
	sum, err := p.Contain(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 0 || len(sum.Already) != 3 {
		t.Errorf("calls %v already %d, want no call and three actions done already", d.calls, len(sum.Already))
	}
}

// Another writer of the Incident node puts a contained record there. The
// daemon does not confirm it, so the pass contains the target.
func TestContain_AForgedRecordDoesNotStopTheContainment(t *testing.T) {
	inc := twoTargets()
	host := target(t, "crowdstrike-response", falconID)
	inc.Records = map[string]string{emit.ContainedName(host, host.Connector.Steps[0], 1): "forged-call"}
	d := newDaemon(nil)
	rec := &fakeRecorder{}
	sum, err := pass(d, rec, inc, "").Contain(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(d.calls, ","), "mcp:crowdstrike-response:contain_host") {
		t.Errorf("calls = %v, want the host contained", d.calls)
	}
	if len(sum.Skipped) != 2 {
		t.Errorf("skipped = %+v, want the place with no connector and the forged record", sum.Skipped)
	}
}

func TestContain_ADaemonThatCannotAnswerFailsThePass(t *testing.T) {
	d := newDaemon(nil)
	rec := &fakeRecorder{}
	p := pass(d, rec, twoTargets(), "")
	if _, err := p.Contain(context.Background(), "inc-1"); err != nil {
		t.Fatal(err)
	}
	d.down = true
	if _, err := p.Contain(context.Background(), "inc-1"); err == nil {
		t.Fatal("want an error when the daemon cannot confirm a record")
	}
}

func TestContain_StopsAtMaxActions(t *testing.T) {
	inc := incident.Incident{Key: "inc-1"}
	for i := range contain.MaxActions + 5 {
		id := fmt.Sprintf("%032x", i)
		inc.Reached = append(inc.Reached,
			incident.Place{Label: incident.LabelHost, Key: placeKey("crowdstrike-response", id)})
	}
	d := newDaemon(nil)
	sum, err := pass(d, &fakeRecorder{}, inc, "").Contain(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != contain.MaxActions || !sum.Capped {
		t.Errorf("calls %d capped %v, want %d and capped", len(d.calls), sum.Capped, contain.MaxActions)
	}
}

func TestContain_AFailedReadFailsAndCallsNothing(t *testing.T) {
	boom := errors.New("graph down")
	d := newDaemon(nil)
	p := pass(d, &fakeRecorder{}, incident.Incident{}, "")
	p.Reader = fakeReader{err: boom}
	_, err := p.Contain(context.Background(), "inc-1")
	if !errors.Is(err, boom) || len(d.calls) != 0 {
		t.Fatalf("err %v calls %v", err, d.calls)
	}
}

// containedOkta runs a contain pass on the Okta account only and returns the
// parts, so a release test starts from records that the agent made.
func containedOkta(t *testing.T) (*fakeDaemon, *fakeRecorder, incident.Incident) {
	t.Helper()
	inc := twoTargets()
	inc.Reached = inc.Reached[:1]
	d := newDaemon(nil)
	rec := &fakeRecorder{}
	if _, err := pass(d, rec, inc, "").Contain(context.Background(), "inc-1"); err != nil {
		t.Fatal(err)
	}
	d.calls = nil
	return d, rec, inc
}

func TestRelease_HoldsUntilTheCauseOfThisAgentIsVerified(t *testing.T) {
	for name, tc := range map[string]struct {
		own    string
		causes []incident.Cause
	}{
		"no cause of this agent": {own: "", causes: []incident.Cause{{FindingID: "f-9", Status: "verified"}}},
		"not linked":             {own: "f-1", causes: []incident.Cause{{FindingID: "f-9", Status: "verified"}}},
		"fixing":                 {own: "f-1", causes: []incident.Cause{{FindingID: "f-1", Status: "fixing"}}},
		"fixed":                  {own: "f-1", causes: []incident.Cause{{FindingID: "f-1", Status: "fixed"}}},
	} {
		t.Run(name, func(t *testing.T) {
			d, rec, inc := containedOkta(t)
			inc.Causes = tc.causes
			sum, err := pass(d, rec, inc, tc.own).Release(context.Background(), "inc-1")
			if err != nil {
				t.Fatal(err)
			}
			if len(d.calls) != 0 || sum.Held == "" || rec.held == "" {
				t.Errorf("calls %v held %q recorded %q, want no call and a held reason", d.calls, sum.Held, rec.held)
			}
		})
	}
}

// The release undoes only what the daemon confirms the agent made. A revoked
// session has no undo.
func TestRelease_UndoesOnlyTheContainmentOfThisAgent(t *testing.T) {
	d, rec, inc := containedOkta(t)
	inc.Reached = twoTargets().Reached
	inc.Causes = []incident.Cause{{FindingID: "f-1", Status: incident.StatusVerified}}
	sum, err := pass(d, rec, inc, "f-1").Release(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.calls, ",") != "mcp:okta-response:unsuspend_user" {
		t.Errorf("calls = %v, want only unsuspend_user", d.calls)
	}
	okta := target(t, "okta-response", oktaID)
	if _, ok := rec.props[emit.ReleasedName(okta, okta.Connector.Steps[0], 1)]; sum.Held != "" || !ok {
		t.Errorf("held %q records %v", sum.Held, rec.props)
	}
}

// Another writer of the Incident node puts a contained record on it. Its
// value is no call of this agent, so the release leaves that target.
func TestRelease_RefusesARecordThatTheDaemonDoesNotConfirm(t *testing.T) {
	inc := twoTargets()
	inc.Causes = []incident.Cause{{FindingID: "f-1", Status: incident.StatusVerified}}
	host := target(t, "crowdstrike-response", falconID)
	okta := target(t, "okta-response", oktaID)
	d := newDaemon(nil)
	// A real call of this agent, but on another tool: the id does not match
	// the record.
	other, err := d.Invoke(context.Background(), respond.Action{
		Kind: respond.KindContain, Target: okta, Tool: okta.Connector.Steps[1].Tool,
	})
	if err != nil {
		t.Fatal(err)
	}
	d.calls = nil
	inc.Records = map[string]string{
		emit.ContainedName(host, host.Connector.Steps[0], 1): "0b5e2c1a-0000-4000-8000-999999999999",
		emit.ContainedName(okta, okta.Connector.Steps[0], 1): other.CallID,
	}
	rec := &fakeRecorder{}
	sum, err := pass(d, rec, inc, "f-1").Release(context.Background(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 0 {
		t.Errorf("calls = %v, want none", d.calls)
	}
	if len(sum.Skipped) != 3 {
		t.Errorf("skipped = %+v, want the place with no connector and two records", sum.Skipped)
	}
}

func TestRelease_ARecordedReleaseIsNotMadeAgain(t *testing.T) {
	d, rec, inc := containedOkta(t)
	inc.Causes = []incident.Cause{{FindingID: "f-1", Status: incident.StatusVerified}}
	p := pass(d, rec, inc, "f-1")
	if _, err := p.Release(context.Background(), "inc-1"); err != nil {
		t.Fatal(err)
	}
	d.calls = nil
	if _, err := p.Release(context.Background(), "inc-1"); err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 0 {
		t.Errorf("calls = %v, want none", d.calls)
	}
}

// A containment after a release is a new generation with new record names, so
// the second release runs too.
func TestContainAfterRelease_StartsANewGenerationAndReleasesAgain(t *testing.T) {
	d, rec, inc := containedOkta(t)
	inc.Causes = []incident.Cause{{FindingID: "f-1", Status: incident.StatusVerified}}
	p := pass(d, rec, inc, "f-1")
	if _, err := p.Release(context.Background(), "inc-1"); err != nil {
		t.Fatal(err)
	}
	d.calls = nil
	if _, err := p.Contain(context.Background(), "inc-1"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.calls, ",") != "mcp:okta-response:suspend_user,mcp:okta-response:revoke_user_sessions" {
		t.Errorf("contain after release calls = %v, want both steps again", d.calls)
	}
	okta := target(t, "okta-response", oktaID)
	if _, ok := rec.props[emit.ContainedName(okta, okta.Connector.Steps[0], 2)]; !ok {
		t.Fatalf("records %v lack generation 2", rec.props)
	}
	d.calls = nil
	if _, err := p.Release(context.Background(), "inc-1"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.calls, ",") != "mcp:okta-response:unsuspend_user" {
		t.Errorf("second release calls = %v, want unsuspend_user", d.calls)
	}
	if _, ok := rec.props[emit.ReleasedName(okta, okta.Connector.Steps[0], 2)]; !ok {
		t.Errorf("records %v lack the release of generation 2", rec.props)
	}
}

func TestPass_NeedsEachPart(t *testing.T) {
	if _, err := (contain.Pass{}).Contain(context.Background(), "inc-1"); err == nil {
		t.Fatal("want an error")
	}
	if _, err := (contain.Pass{}).Release(context.Background(), "inc-1"); err == nil {
		t.Fatal("want an error")
	}
	d := newDaemon(nil)
	p := pass(d, &fakeRecorder{}, twoTargets(), "")
	p.Causes = nil
	if _, err := p.Release(context.Background(), "inc-1"); err == nil {
		t.Fatal("a release with no cause finder: want an error")
	}
}

// placeKey is the key of a place that names a vendor id of a connector: the
// composite key of the identity properties connector and vendor_id.
func placeKey(connectorID, vendorID string) string {
	return "connector=" + connectorID + "|vendor_id=" + vendorID
}
