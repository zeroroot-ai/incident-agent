// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pass_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/zeroroot-ai/incident-agent/internal/contain"
	"github.com/zeroroot-ai/incident-agent/internal/emit"
	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/pass"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
	"github.com/zeroroot-ai/sdk/agent"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/openresponses"
	"github.com/zeroroot-ai/sdk/serve"
	"github.com/zeroroot-ai/sdk/types"
	"google.golang.org/grpc"
)

const (
	oktaID   = "00ub0oNGTSWTBKOLGLNR"
	falconID = "0123456789abcdef0123456789abcdef"
)

// daemon is a fake HarnessCallbackService on a real gRPC listener. The agent
// reaches it through the SDK callback client, so each call goes through the
// same conversion as in production.
//
// Each answer copies the shape of the daemon on the gibson branch
// integration/blue-team:
//
//   - invoke_tool: callback_metatool.go metaInvoke. A result is
//     {"result": <structured content of the MCP tool>} with tool_call_id. A
//     refusal is a HarnessError with the code and the words of the daemon.
//   - SubmitFinding: callback_service.go. The daemon names the finding and
//     returns no id.
//   - GetFindings: callback_service_knowledge.go agentFindingToProto. Id,
//     title, description, category, confidence and severity only.
//   - Observe: the request is stored as it came.
//   - The flight recorder: each invoke_tool call is recorded under the
//     tool_call_id of its reply, with the tool id, the arguments and whether
//     the connector took the action (ToolCallRecord in callback_service.go).
//     The harness has no read of it. checker reads it, as the read of
//     gibson would.
type daemon struct {
	harnesspb.UnimplementedHarnessCallbackServiceServer

	mu       sync.Mutex
	answers  map[string][]string // tool id -> "ok", "pending", "unauthorized"
	calls    []string
	recorded map[string]recordedCall
	findings []*typespb.Finding
	// bind makes the daemon keep the author and the tags of a finding. The
	// daemon of gibson drops both today (protoFindingToFinding and
	// agentFindingToProto). A test that needs a bound cause sets it.
	bind     bool
	observed []*harnesspb.LifecycleEntityObservation
}

// recordedCall is one call in the flight recorder of the fake daemon.
type recordedCall struct {
	tool string
	args string
	ok   bool
}

// checker confirms a call from the flight recorder of the fake daemon: the id
// must name a recorded call with the same tool and arguments that took the
// action.
type checker struct{ d *daemon }

func (c checker) CheckCall(_ context.Context, id string, a respond.Action) error {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	args, err := json.Marshal(a.Args())
	if err != nil {
		return fmt.Errorf("encode the arguments: %w", err)
	}
	r, ok := c.d.recorded[id]
	if !ok || !r.ok || r.tool != a.ToolID() || r.args != string(args) {
		return fmt.Errorf("call %s: %w", id, contain.ErrNotOwnCall)
	}
	return nil
}

func (d *daemon) GetTaxonomySchema(
	context.Context, *harnesspb.GetTaxonomySchemaRequest,
) (*harnesspb.GetTaxonomySchemaResponse, error) {
	return &harnesspb.GetTaxonomySchemaResponse{}, nil
}

// results are the structured contents of the MCP servers of
// zeroroot-ai/connectors v0.1.0 (actionOutput in each server.go).
var results = map[string]string{
	"mcp:okta-response:suspend_user":         `{"user_id":"` + oktaID + `","action":"suspend","done":true}`,
	"mcp:okta-response:unsuspend_user":       `{"user_id":"` + oktaID + `","action":"unsuspend","done":true}`,
	"mcp:okta-response:revoke_user_sessions": `{"user_id":"` + oktaID + `","action":"revoke_sessions","done":true}`,
	"mcp:crowdstrike-response:contain_host":  `{"host_id":"` + falconID + `","action":"contain","accepted":true}`,
	"mcp:crowdstrike-response:lift_containment": `{"host_id":"` + falconID +
		`","action":"lift_containment","accepted":true}`,
}

func (d *daemon) CallToolProto(
	_ context.Context, req *harnesspb.CallToolProtoRequest,
) (*harnesspb.CallToolProtoResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if req.GetName() != "invoke_tool" {
		return metaErr(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "unknown tool: "+req.GetName(), ""), nil
	}
	var in struct {
		ID   string         `json:"id"`
		Args map[string]any `json:"args"`
	}
	if err := json.Unmarshal(req.GetInputJson(), &in); err != nil {
		return metaErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
			"invoke_tool input is not valid JSON: "+err.Error(), ""), nil
	}
	d.calls = append(d.calls, in.ID)
	callID := fmt.Sprintf("0b5e2c1a-0000-4000-8000-%012d", len(d.calls))
	if d.recorded == nil {
		d.recorded = map[string]recordedCall{}
	}
	args, err := json.Marshal(in.Args)
	if err != nil {
		return nil, fmt.Errorf("encode the arguments: %w", err)
	}
	answer := "ok"
	if list := d.answers[in.ID]; len(list) > 0 {
		answer, d.answers[in.ID] = list[0], list[1:]
	}
	switch answer {
	case "pending":
		return metaErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
			"metatool: pending authorization: a person must approve this call before it runs: request r-1. "+
				"Do not retry now. Call again with the same arguments after the approval.", callID), nil
	case "unauthorized":
		return metaErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
			"metatool: not authorized to invoke tool: "+in.ID, callID), nil
	}
	body, ok := results[in.ID]
	if !ok {
		return metaErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "no such tool "+in.ID, callID), nil
	}
	d.recorded[callID] = recordedCall{tool: in.ID, args: string(args), ok: true}
	return &harnesspb.CallToolProtoResponse{OutputJson: []byte(`{"result":` + body + `}`), ToolCallId: callID}, nil
}

func metaErr(code commonpb.ErrorCode, msg, callID string) *harnesspb.CallToolProtoResponse {
	return &harnesspb.CallToolProtoResponse{Error: &harnesspb.HarnessError{Code: code, Message: msg}, ToolCallId: callID}
}

func (d *daemon) SubmitFinding(
	_ context.Context, req *harnesspb.SubmitFindingRequest,
) (*harnesspb.SubmitFindingResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f := req.GetFinding()
	pf := &typespb.Finding{
		// The daemon never reads the id of the payload.
		Id:          fmt.Sprintf("0f1d3c2a-0000-4000-8000-%012d", len(d.findings)+1),
		Title:       f.GetTitle(),
		Description: f.GetDescription(),
		Category:    f.GetCategory(),
		Confidence:  f.GetConfidence(),
		Severity:    f.GetSeverity(),
	}
	if d.bind {
		pf.AgentName, pf.Tags = f.GetAgentName(), f.GetTags()
	}
	d.findings = append(d.findings, pf)
	return &harnesspb.SubmitFindingResponse{}, nil
}

func (d *daemon) GetFindings(context.Context, *harnesspb.GetFindingsRequest) (*harnesspb.GetFindingsResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return &harnesspb.GetFindingsResponse{Findings: append([]*typespb.Finding(nil), d.findings...)}, nil
}

func (d *daemon) Observe(_ context.Context, req *harnesspb.ObserveRequest) (*harnesspb.ObserveResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if le := req.GetLifecycleEntity(); le != nil {
		d.observed = append(d.observed, le)
	}
	return &harnesspb.ObserveResponse{}, nil
}

// properties returns the properties that the agent wrote on the Incident.
func (d *daemon) properties() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]string{}
	for _, o := range d.observed {
		if o.GetLabel() == "Incident" {
			for k, v := range o.GetProperties() {
				out[k] = v
			}
		}
	}
	return out
}

// platform is the SDK callback harness with a model gateway of the test.
type platform struct {
	*serve.CallbackHarness
	answer string
	t      *testing.T
}

func (p *platform) Model(context.Context, string) (*openresponses.Client, error) {
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "resp_1", "status": "completed",
			"output": []any{map[string]any{
				"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
				"content": []any{map[string]any{"type": "output_text", "text": p.answer}},
			}},
		})
	}))
	p.t.Cleanup(gw.Close)
	return &openresponses.Client{BaseURL: gw.URL, Model: "test-model"}, nil
}

func start(t *testing.T, d *daemon) *platform {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	harnesspb.RegisterHarnessCallbackServiceServer(srv, d)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := serve.NewCallbackClient(lis.Addr().String(), serve.WithCallbackToken("grant"))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	mission := types.MissionContext{ID: "m-1", CurrentAgent: "incident-agent"}
	h := serve.NewCallbackHarness(client, serve.WithCallbackMission(mission))
	return &platform{CallbackHarness: h, t: t}
}

// reader holds the incident in the shape of the incident report reader of the
// daemon. It reads the records back from what the agent wrote, as the graph
// would after the projector ran.
type reader struct {
	inc incident.Incident
	d   *daemon
}

func (r reader) Incident(context.Context, string) (incident.Incident, error) {
	inc := r.inc
	inc.Records = r.d.properties()
	return inc, nil
}

// alertKey is the key of an Alert that the intake agent wrote: its identity
// properties connector and result_id, folded by the daemon.
const alertKey = "connector=okta-siem|result_id=9"

func theIncident() incident.Incident {
	return incident.Incident{
		Key: "inc-1",
		Alerts: []incident.Alert{
			{Key: alertKey, Title: "Sign-in from a new country", Source: "okta", Severity: "high"},
		},
		Reached: []incident.Place{
			{Label: "Account", Key: placeKey("okta-response", oktaID)},
			{Label: "Host", Key: placeKey("crowdstrike-response", falconID)},
		},
	}
}

func task(kind string) agent.Task {
	return agent.Task{ID: "t-1", Context: map[string]any{"incident": "inc-1", "ir.task": kind}}
}

func noResolvedClaim(t *testing.T, res agent.Result) {
	t.Helper()
	out, _ := res.Output.(string)
	if strings.Contains(strings.ToLower(out), "resolved") {
		t.Errorf("the report says the incident is resolved, and the agent does not know that:\n%s", out)
	}
}

func TestRun_ContainWaitsForAPersonAndNeverRetriesARefusal(t *testing.T) {
	d := &daemon{answers: map[string][]string{
		"mcp:okta-response:revoke_user_sessions": {"unauthorized"},
		"mcp:crowdstrike-response:contain_host":  {"pending"},
	}}
	p := start(t, d)
	res, err := pass.Run(context.Background(), p, reader{inc: theIncident(), d: d}, checker{d}, task("contain"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != a2a.TaskStateCompleted {
		t.Errorf("status = %v", res.Status)
	}
	want := []string{
		"mcp:okta-response:suspend_user",
		"mcp:okta-response:revoke_user_sessions",
		"mcp:crowdstrike-response:contain_host",
	}
	if strings.Join(d.calls, ",") != strings.Join(want, ",") {
		t.Errorf("calls =\n%v\nwant\n%v", d.calls, want)
	}
	props := d.properties()
	okta := target(t, "Account", "okta-response", oktaID)
	host := target(t, "Host", "crowdstrike-response", falconID)
	for _, r := range []respond.Result{
		{Action: respond.Action{Kind: respond.KindContain, Target: okta, Tool: "suspend_user"}, Outcome: respond.OutcomeDone},
		{
			Action:  respond.Action{Kind: respond.KindContain, Target: okta, Tool: "revoke_user_sessions"},
			Outcome: respond.OutcomeRefused,
		},
		{
			Action:  respond.Action{Kind: respond.KindContain, Target: host, Tool: "contain_host"},
			Outcome: respond.OutcomePending,
		},
	} {
		name := emit.RecordName(r, 1)
		if _, ok := props[name]; !ok {
			t.Errorf("the Incident lacks the record %s: %v", name, props)
		}
	}
	for name := range props {
		if !projectorKeyPattern.MatchString(name) {
			t.Errorf("the projector of the daemon drops the record %q", name)
		}
	}
	if res.Metadata["done"] != 1 || res.Metadata["refused"] != 1 || res.Metadata["pending"] != 1 {
		t.Errorf("metadata = %v", res.Metadata)
	}
	noResolvedClaim(t, res)
}

const answer = `{"title":"MFA is not required for the admin group",` +
	`"description":"The account signed in with a password only.","fix":"Require MFA for the admin group.","place":0}`

func TestRun_CauseRaisesOneFindingAndLinksItWithCausedBy(t *testing.T) {
	d := &daemon{}
	p := start(t, d)
	p.answer = answer
	res, err := pass.Run(context.Background(), p, reader{inc: theIncident(), d: d}, checker{d}, task("cause"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(d.findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(d.findings))
	}
	f := d.findings[0]
	if f.GetCategory() != "incident-cause" || f.GetSeverity() != typespb.FindingSeverity_FINDING_SEVERITY_HIGH ||
		!strings.Contains(f.GetDescription(), "Fix: Require MFA") {
		t.Errorf("finding = %v", f)
	}
	if res.Metadata["cause"] != f.GetId() {
		t.Errorf("metadata cause = %v, want the id that the daemon gave, %s", res.Metadata["cause"], f.GetId())
	}
	var linked bool
	for _, o := range d.observed {
		for _, e := range o.GetEdges() {
			if o.GetLabel() == "Incident" && o.GetIdProperties()["key"] == "inc-1" && e.GetType() == "CAUSED_BY" &&
				e.GetTargetLabel() == "Finding" && e.GetTargetIdProperties()["brain_id"] == f.GetId() {
				linked = true
			}
		}
	}
	if !linked {
		t.Errorf("no CAUSED_BY from inc-1 to %s in %v", f.GetId(), d.observed)
	}
	noResolvedClaim(t, res)
}

func TestRun_ReleaseWaitsForVerifiedAndThenUndoesWhatItMade(t *testing.T) {
	d := &daemon{bind: true}
	p := start(t, d)
	p.answer = answer
	inc := theIncident()
	r := reader{inc: inc, d: d}
	if _, err := pass.Run(context.Background(), p, r, checker{d}, task("contain")); err != nil {
		t.Fatal(err)
	}
	res, err := pass.Run(context.Background(), p, r, checker{d}, task("cause"))
	if err != nil {
		t.Fatal(err)
	}
	causeID, _ := res.Metadata["cause"].(string)

	r.inc.Causes = []incident.Cause{{FindingID: causeID, Status: "fixed"}}
	d.calls = nil
	res, err = pass.Run(context.Background(), p, r, checker{d}, task("release"))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 0 || !strings.Contains(res.Output.(string), "released nothing") {
		t.Fatalf("calls %v output %q, want no call before verified", d.calls, res.Output)
	}

	r.inc.Causes[0].Status = "verified"
	res, err = pass.Run(context.Background(), p, r, checker{d}, task("release"))
	if err != nil {
		t.Fatal(err)
	}
	want := "mcp:okta-response:unsuspend_user,mcp:crowdstrike-response:lift_containment"
	if strings.Join(d.calls, ",") != want {
		t.Errorf("calls = %v, want %s", d.calls, want)
	}
	noResolvedClaim(t, res)
}

// Another writer links its own verified finding as a cause and writes
// contained records with ids of its choice. The release accepts neither.
func TestRun_ReleaseIgnoresTheCausesAndRecordsOfAnotherWriter(t *testing.T) {
	d := &daemon{bind: true}
	p := start(t, d)
	okta := target(t, "Account", "okta-response", oktaID)
	host := target(t, "Host", "crowdstrike-response", falconID)
	inc := theIncident()
	inc.Causes = []incident.Cause{{FindingID: "f-planted", Status: "verified"}}
	inc.Records = map[string]string{
		emit.ContainedName(okta, okta.Connector.Steps[0], 1): "0b5e2c1a-0000-4000-8000-000000000001",
		emit.ContainedName(host, host.Connector.Steps[0], 1): "0b5e2c1a-0000-4000-8000-000000000002",
	}
	res, err := pass.Run(context.Background(), p, plantedReader{inc: inc, d: d}, checker{d}, task("release"))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 0 || !strings.Contains(res.Output.(string), "no cause finding") {
		t.Fatalf("calls %v output %q, want no call: the cause is not of this agent", d.calls, res.Output)
	}

	// The cause of this agent is verified, and the records still name no
	// call of this agent.
	p.answer = answer
	if _, err := pass.Run(context.Background(), p, plantedReader{inc: inc, d: d}, checker{d}, task("cause")); err != nil {
		t.Fatal(err)
	}
	inc.Causes = append(inc.Causes, incident.Cause{FindingID: d.findings[0].GetId(), Status: "verified"})
	res, err = pass.Run(context.Background(), p, plantedReader{inc: inc, d: d}, checker{d}, task("release"))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 0 || strings.Count(res.Output.(string), "is not trusted") != 2 {
		t.Fatalf("calls %v output %q, want no call and two records not trusted", d.calls, res.Output)
	}
}

// plantedReader holds the records of another writer and the records that the
// agent wrote.
type plantedReader struct {
	inc incident.Incident
	d   *daemon
}

func (r plantedReader) Incident(context.Context, string) (incident.Incident, error) {
	inc := r.inc
	inc.Records = map[string]string{}
	for k, v := range r.inc.Records {
		inc.Records[k] = v
	}
	for k, v := range r.d.properties() {
		inc.Records[k] = v
	}
	return inc, nil
}

func TestRun_ABadTaskContextFailsBeforeAnyCall(t *testing.T) {
	for name, c := range map[string]map[string]any{
		"no incident":  {"ir.task": "contain"},
		"no task":      {"incident": "inc-1"},
		"unknown task": {"incident": "inc-1", "ir.task": "attack"},
		"triage":       {"incident": "inc-1", "ir.task": "triage"},
	} {
		t.Run(name, func(t *testing.T) {
			d := &daemon{}
			p := start(t, d)
			res, err := pass.Run(context.Background(), p, reader{inc: theIncident(), d: d}, checker{d},
				agent.Task{ID: "t", Context: c})
			if err == nil || res.Status != a2a.TaskStateFailed {
				t.Fatalf("res %v err %v, want a failed run", res.Status, err)
			}
			if len(d.calls) != 0 || len(d.observed) != 0 {
				t.Errorf("calls %v observed %d, want nothing", d.calls, len(d.observed))
			}
		})
	}
}

func TestRun_NoPlatformFails(t *testing.T) {
	if _, err := pass.Run(context.Background(), nil, nil, nil, task("contain")); err == nil {
		t.Fatal("want an error")
	}
}

// projectorKeyPattern is copied from gibson, branch integration/blue-team,
// internal/server/daemon/graph_projector_neo4j.go: safeTaxonomyLabel. The
// projector drops a property whose name does not match it.
var projectorKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

func target(t *testing.T, label, connectorID, vendorID string) respond.Target {
	t.Helper()
	tg, err := respond.ParseTarget(incident.Place{Label: label, Key: placeKey(connectorID, vendorID)})
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// placeKey is the key of a place that names a vendor id of a connector: the
// composite key of the identity properties connector and vendor_id.
func placeKey(connectorID, vendorID string) string {
	return "connector=" + connectorID + "|vendor_id=" + vendorID
}

// The daemon drops the author and the tags of a finding. A title prefix and a
// category are text that any writer of the mission can copy, so the release
// does not trust them alone: it holds each containment.
func TestRun_ReleaseHoldsWhenTheDaemonDoesNotBindTheCauseToThisAgent(t *testing.T) {
	d := &daemon{}
	p := start(t, d)
	p.answer = answer
	r := reader{inc: theIncident(), d: d}
	if _, err := pass.Run(context.Background(), p, r, checker{d}, task("contain")); err != nil {
		t.Fatal(err)
	}
	res, err := pass.Run(context.Background(), p, r, checker{d}, task("cause"))
	if err != nil {
		t.Fatal(err)
	}
	causeID, _ := res.Metadata["cause"].(string)
	r.inc.Causes = []incident.Cause{{FindingID: causeID, Status: "verified"}}
	d.calls = nil
	res, err = pass.Run(context.Background(), p, r, checker{d}, task("release"))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 0 || !strings.Contains(res.Output.(string), "no cause finding is proven to be of this agent") {
		t.Fatalf("calls %v, output %q: a verified finding with no author released a containment", d.calls, res.Output)
	}
}
