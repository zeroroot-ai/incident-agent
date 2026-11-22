// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package isolate_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/isolate"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
	"github.com/zeroroot-ai/sdk/agent"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const incidentKey = "incident-7"

// gitHost is a mock of the Git host behind the connector github-fixloop. It
// answers the tools through the invoke_tool shape of the daemon:
// {"result": <structured content of the tool>}. It follows the rules of the
// real server (zeroroot-ai/connectors github-fixloop README):
//
//   - merge_merge_request merges only when the pipeline is green. Otherwise
//     the result has merged false and the state open.
//   - merge_request_state reads the state from the host on each call.
//   - open_merge_request does not exist in v0.2.0 of the server. The mock
//     answers it only when openTool is true. Otherwise the daemon refuses it
//     as an unknown tool.
//
// The mock fails the test when the agent calls a tool that a containment
// must not call: the health signal of a deploy, or the revert.
type gitHost struct {
	t        *testing.T
	openTool bool
	green    bool
	// denied lists the tool ids that the daemon refuses for the grant.
	denied map[string]bool

	opened []map[string]any
	prs    map[string]string // reference -> state
	calls  []string
}

func newHost(t *testing.T) *gitHost {
	t.Helper()
	return &gitHost{t: t, openTool: true, green: true, prs: map[string]string{}, denied: map[string]bool{}}
}

func (g *gitHost) CallToolProto(
	_ context.Context, name string, request, response proto.Message, _ ...agent.ToolCallOption,
) error {
	g.t.Helper()
	if name != respond.InvokeTool {
		g.t.Fatalf("the agent called %q, and it may call only invoke_tool", name)
	}
	req, ok := request.(*structpb.Struct)
	if !ok {
		g.t.Fatalf("the request is %T, want a struct", request)
	}
	in := req.AsMap()
	id, _ := in["id"].(string)
	args, _ := in["args"].(map[string]any)
	g.calls = append(g.calls, id)
	if g.denied[id] {
		return errors.New("metatool: not authorized to invoke tool " + id)
	}
	var result map[string]any
	switch id {
	case "mcp:github-fixloop:open_merge_request":
		if !g.openTool {
			return errors.New("tool not found: " + id)
		}
		g.opened = append(g.opened, args)
		ref := fmt.Sprintf("acme/manifests#%d", len(g.opened))
		g.prs[ref] = "open"
		result = map[string]any{"merge_request": ref}
	case "mcp:github-fixloop:merge_merge_request":
		ref, _ := args["merge_request"].(string)
		if _, known := g.prs[ref]; !known {
			return errors.New("connector mcp: merge_merge_request on \"x\" reported an error: not found")
		}
		if g.green {
			g.prs[ref] = "merged"
		}
		result = map[string]any{"state": g.prs[ref], "merged": g.prs[ref] == "merged"}
	case "mcp:github-fixloop:merge_request_state":
		ref, _ := args["merge_request"].(string)
		result = map[string]any{"state": g.prs[ref], "pipeline_green": g.green}
	default:
		g.t.Fatalf("the agent called %s: an isolation never reads a health signal or reverts", id)
	}
	out, err := structpb.NewStruct(map[string]any{"result": result})
	if err != nil {
		g.t.Fatalf("encode: %v", err)
	}
	proto.Merge(response, out)
	return nil
}

// store is the Incident node of a test. It is the recorder and the reader.
type store struct {
	records map[string]string
	causes  []incident.Cause
	held    string
	readErr error
}

func (s *store) RecordValue(_ context.Context, _, name, value string) error {
	s.records[name] = value
	return nil
}

func (s *store) Held(_ context.Context, _, reason string) error { s.held = reason; return nil }

func (s *store) Incident(_ context.Context, key string) (incident.Incident, error) {
	if s.readErr != nil {
		return incident.Incident{}, s.readErr
	}
	return incident.Incident{Key: key, Causes: s.causes, Records: maps(s.records)}, nil
}

func maps(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

type causes struct{ id string }

func (c causes) OwnCause(context.Context, string) (string, error) { return c.id, nil }

var repo = isolate.Repo{Connector: "github-fixloop", Project: "acme/manifests", BaseBranch: "main", Dir: "contain"}

func workload(t *testing.T) isolate.Workload {
	t.Helper()
	w, err := isolate.ParseWorkload("payments", "app=ledger,tier=api")
	if err != nil {
		t.Fatalf("ParseWorkload: %v", err)
	}
	return w
}

func setup(t *testing.T) (*gitHost, *store, isolate.Pass) {
	t.Helper()
	g := newHost(t)
	st := &store{records: map[string]string{}}
	host, err := isolate.NewToolHost(g, repo)
	if err != nil {
		t.Fatalf("NewToolHost: %v", err)
	}
	return g, st, isolate.Pass{Reader: st, Host: host, Recorder: st, Causes: causes{id: "f-9"}, Repo: repo}
}

func TestParseWorkload(t *testing.T) {
	long := strings.Repeat("a", 64)
	many := make([]string, 0, 11)
	for i := range 11 {
		many = append(many, fmt.Sprintf("k%d=v", i))
	}
	tests := []struct {
		name, ns, labels string
		ok               bool
	}{
		{"one label", "payments", "app=ledger", true},
		{"prefixed key", "payments", "app.kubernetes.io/name=ledger", true},
		{"no label is the whole namespace", "payments", "", false},
		{"system namespace", "kube-system", "app=x", false},
		{"namespace with a slash", "a/b", "app=x", false},
		{"upper case namespace", "Payments", "app=x", false},
		{"value with a newline", "payments", "app=x\nkind: Namespace", false},
		{"value with a colon", "payments", "app=a: b", false},
		{"key with a space", "payments", "a b=x", false},
		{"no equals sign", "payments", "app", false},
		{"empty value", "payments", "app=", false},
		{"too long value", "payments", "app=" + long, false},
		{"duplicate key", "payments", "app=a,app=b", false},
		{"eleven labels", "payments", strings.Join(many, ","), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := isolate.ParseWorkload(tc.ns, tc.labels)
			if (err == nil) != tc.ok {
				t.Fatalf("ParseWorkload(%q, %q) error = %v, want ok = %v", tc.ns, tc.labels, err, tc.ok)
			}
		})
	}
}

func TestIsolateRendersADenyAllPolicyAndALock(t *testing.T) {
	c := isolate.Isolate("contain", incidentKey, workload(t), 1)
	if len(c.Files) != 2 {
		t.Fatalf("the change has %d files, want the policy and the lock", len(c.Files))
	}
	policy, lock := c.Files[0], c.Files[1]
	if !strings.HasSuffix(policy.Path, ".yaml") || !strings.HasSuffix(lock.Path, ".lock.yaml") {
		t.Fatalf("paths = %q and %q", policy.Path, lock.Path)
	}
	for _, want := range []string{
		"kind: NetworkPolicy", "namespace: payments", `"app": "ledger"`, `"tier": "api"`,
		"policyTypes:\n    - Ingress\n    - Egress\n", isolate.LabelContainment, isolate.AnnotationRule,
	} {
		if !strings.Contains(policy.Content, want) {
			t.Errorf("the policy lacks %q:\n%s", want, policy.Content)
		}
	}
	// A deny-all policy has policyTypes and no rule list.
	for _, bad := range []string{"\n  ingress:", "\n  egress:"} {
		if strings.Contains(policy.Content, bad) {
			t.Errorf("the policy holds a rule list %q, so it allows traffic:\n%s", bad, policy.Content)
		}
	}
	if !strings.Contains(lock.Content, "state: open") || !strings.Contains(lock.Content, policy.Path) {
		t.Errorf("the lock does not name the policy and the open state:\n%s", lock.Content)
	}
	if strings.Contains(policy.Content+lock.Content, incidentKey) {
		t.Errorf("a file holds the incident key. It must hold only the hash")
	}
}

func TestIsolate_OpensAndMergesAndRecords(t *testing.T) {
	g, st, p := setup(t)
	sum, err := p.Isolate(context.Background(), incidentKey, workload(t))
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if !sum.Isolated {
		t.Fatalf("not isolated: %v", sum.Lines)
	}
	want := []string{
		"mcp:github-fixloop:open_merge_request", "mcp:github-fixloop:merge_merge_request",
		"mcp:github-fixloop:merge_request_state",
	}
	if !slices.Equal(g.calls, want) {
		t.Fatalf("calls = %v, want %v", g.calls, want)
	}
	args := g.opened[0]
	if args["project"] != "acme/manifests" || args["base_branch"] != "main" {
		t.Errorf("the merge request targets %v, %v", args["project"], args["base_branch"])
	}
	if _, has := args["inputs"]; has {
		t.Errorf("the open call names a finding. The daemon would then link the cause finding to this merge request")
	}
	ck := isolate.Key(incidentKey, workload(t))
	if got := st.records["ir_isolated_"+ck+"_1"]; got != "acme/manifests#1" {
		t.Errorf("isolated record = %q, records = %v", got, st.records)
	}
	if got := st.records["ir_isolation_opened_"+ck+"_1"]; got != "acme/manifests#1" {
		t.Errorf("opened record = %q", got)
	}
}

func TestIsolate_SecondDispatchMakesNoCall(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("first: %v", err)
	}
	g.calls = nil
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !sum.Isolated || len(g.opened) != 1 {
		t.Fatalf("isolated = %v, opened = %d, records = %v", sum.Isolated, len(g.opened), st.records)
	}
	for _, c := range g.calls {
		if !strings.HasSuffix(c, "merge_request_state") {
			t.Errorf("the second dispatch called %s, and it may only read the state", c)
		}
	}
}

func TestIsolate_PendingChecksKeepOneMergeRequest(t *testing.T) {
	g, st, p := setup(t)
	g.green = false
	w := workload(t)
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	ck := isolate.Key(incidentKey, w)
	if sum.Isolated || st.records["ir_isolated_"+ck+"_1"] != "" {
		t.Fatalf("a merge request that did not merge counts as isolated: %v", sum.Lines)
	}
	if st.records["ir_isolation_opened_"+ck+"_1"] == "" {
		t.Fatalf("the open merge request is not recorded, so the next dispatch opens a second one")
	}
	g.green = true
	sum, err = p.Isolate(context.Background(), incidentKey, w)
	if err != nil || !sum.Isolated {
		t.Fatalf("second: isolated = %v, err = %v, lines = %v", sum.Isolated, err, sum.Lines)
	}
	if len(g.opened) != 1 {
		t.Fatalf("the agent opened %d merge requests, want 1", len(g.opened))
	}
}

func TestIsolate_DaemonRefusalRecordsNothing(t *testing.T) {
	for _, tool := range []string{"open_merge_request", "merge_merge_request"} {
		t.Run(tool, func(t *testing.T) {
			g, st, p := setup(t)
			g.denied["mcp:github-fixloop:"+tool] = true
			sum, err := p.Isolate(context.Background(), incidentKey, workload(t))
			if err != nil {
				t.Fatalf("Isolate: %v", err)
			}
			if sum.Isolated || !strings.Contains(strings.Join(sum.Lines, "\n"), "refused") {
				t.Fatalf("isolated = %v, lines = %v", sum.Isolated, sum.Lines)
			}
			for name := range st.records {
				if strings.HasPrefix(name, "ir_isolated_") {
					t.Fatalf("a refused call wrote %s", name)
				}
			}
		})
	}
}

// The connectors of v0.2.0 have no open_merge_request. The daemon answers
// with an unknown tool, and the pass must change nothing and say why.
func TestIsolate_ConnectorWithoutTheOpenTool(t *testing.T) {
	g, st, p := setup(t)
	g.openTool = false
	sum, err := p.Isolate(context.Background(), incidentKey, workload(t))
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if sum.Isolated || len(st.records) != 0 || len(g.calls) != 1 {
		t.Fatalf("isolated = %v, records = %v, calls = %v", sum.Isolated, st.records, g.calls)
	}
	if !strings.Contains(strings.Join(sum.Lines, "\n"), "failed") {
		t.Fatalf("the report does not say that the open call failed: %v", sum.Lines)
	}
}

func TestIsolate_ForgedRecordIsNotTrusted(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	ck := isolate.Key(incidentKey, w)
	// Another writer of the graph claims a merge request that is still open.
	g.prs["acme/manifests#99"] = "open"
	st.records["ir_isolated_"+ck+"_1"] = "acme/manifests#99"
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if sum.Isolated {
		t.Fatalf("the agent trusted a record that the host contradicts: %v", sum.Lines)
	}
}

func TestRelease_WaitsForVerified(t *testing.T) {
	for _, status := range []string{"open", "fixing", "fixed", ""} {
		t.Run("status "+status, func(t *testing.T) {
			g, st, p := setup(t)
			w := workload(t)
			if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
				t.Fatalf("Isolate: %v", err)
			}
			g.calls = nil
			st.causes = []incident.Cause{{FindingID: "f-9", Status: status}}
			sum, err := p.Release(context.Background(), incidentKey, w)
			if err != nil {
				t.Fatalf("Release: %v", err)
			}
			if sum.Released || sum.Held == "" || st.held == "" || len(g.calls) != 0 {
				t.Fatalf("released = %v, held = %q, calls = %v", sum.Released, sum.Held, g.calls)
			}
		})
	}
}

func TestRelease_AfterVerifiedRemovesTheFilesWithASecondMergeRequest(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	st.causes = []incident.Cause{{FindingID: "f-9", Status: incident.StatusVerified}}
	sum, err := p.Release(context.Background(), incidentKey, w)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !sum.Released || len(g.opened) != 2 {
		t.Fatalf("released = %v, opened = %d, lines = %v", sum.Released, len(g.opened), sum.Lines)
	}
	files, _ := g.opened[1]["files"].([]any)
	if len(files) != 2 {
		t.Fatalf("the release changes %d files, want 2", len(files))
	}
	for _, f := range files {
		m, _ := f.(map[string]any)
		if m["delete"] != true || m["content"] != nil {
			t.Errorf("the release file %v is not a delete", m)
		}
	}
	ck := isolate.Key(incidentKey, w)
	if st.records["ir_isolation_released_"+ck+"_1"] == "" {
		t.Errorf("no released record: %v", st.records)
	}
	// A second release finds nothing to do and calls nothing.
	g.calls = nil
	sum, err = p.Release(context.Background(), incidentKey, w)
	if err != nil || sum.Released || len(g.calls) != 0 {
		t.Fatalf("second release: released = %v, err = %v, calls = %v", sum.Released, err, g.calls)
	}
}

func TestRelease_CauseOfAnotherWriterDoesNotCount(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	g.calls = nil
	p.Causes = causes{id: "f-9"} // this agent raised f-9, and it is not verified
	st.causes = []incident.Cause{
		{FindingID: "f-9", Status: "fixing"},
		{FindingID: "f-evil", Status: incident.StatusVerified},
	}
	sum, err := p.Release(context.Background(), incidentKey, w)
	if err != nil || sum.Released || len(g.calls) != 0 {
		t.Fatalf("released = %v, err = %v, calls = %v", sum.Released, err, g.calls)
	}
}

func TestIsolateAfterReleaseStartsTheNextGeneration(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	ctx := context.Background()
	if _, err := p.Isolate(ctx, incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	st.causes = []incident.Cause{{FindingID: "f-9", Status: incident.StatusVerified}}
	if _, err := p.Release(ctx, incidentKey, w); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := p.Isolate(ctx, incidentKey, w); err != nil {
		t.Fatalf("Isolate again: %v", err)
	}
	if len(g.opened) != 3 {
		t.Fatalf("opened = %d, want 3", len(g.opened))
	}
	b1, b3 := g.opened[0]["branch"], g.opened[2]["branch"]
	if b1 == b3 {
		t.Fatalf("the first and the third merge request share the branch %v", b1)
	}
}

func TestPassRefusesWhenTheIncidentCannotBeRead(t *testing.T) {
	_, st, p := setup(t)
	st.readErr = agent.ErrKnowledgeUnavailable
	for name, run := range map[string]func() (isolate.Summary, error){
		"isolate": func() (isolate.Summary, error) { return p.Isolate(context.Background(), incidentKey, workload(t)) },
		"release": func() (isolate.Summary, error) { return p.Release(context.Background(), incidentKey, workload(t)) },
	} {
		if _, err := run(); !errors.Is(err, agent.ErrKnowledgeUnavailable) {
			t.Errorf("%s: err = %v, want ErrKnowledgeUnavailable", name, err)
		}
	}
}

func TestRepoCheck(t *testing.T) {
	bad := []isolate.Repo{
		{Connector: "okta-response", Project: "a/b", BaseBranch: "main", Dir: "d"},
		{Connector: "github-fixloop", Project: "", BaseBranch: "main", Dir: "d"},
		{Connector: "github-fixloop", Project: "a/b", BaseBranch: "main", Dir: "../etc"},
		{Connector: "github-fixloop", Project: "a/b", BaseBranch: "main", Dir: "/abs"},
		{Connector: "github-fixloop", Project: "a/b", BaseBranch: "ma\nin", Dir: "d"},
	}
	for _, r := range bad {
		if err := r.Check(); err == nil {
			t.Errorf("Check(%+v) = nil, want an error", r)
		}
	}
	good := isolate.Repo{Connector: "gitlab-fixloop", Project: "a/b", BaseBranch: "main", Dir: "d"}
	if err := good.Check(); err != nil {
		t.Errorf("Check(%+v) = %v", good, err)
	}
}
