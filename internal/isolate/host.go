// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package isolate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/zeroroot-ai/incident-agent/internal/respond"
)

// The Git host connectors that the agent can use. The table is closed. A
// connector id from the dispatch selects a row, and only a row builds a tool
// id. These are the connectors that the fix loop uses (gibson catalog
// manifests github-fixloop.yaml and gitlab-fixloop.yaml).
var gitHosts = map[string]bool{"github-fixloop": true, "gitlab-fixloop": true}

// The tools of a Git host connector.
const (
	// ToolOpen opens a merge request with a set of file changes. The two
	// fixloop servers of zeroroot-ai/connectors v0.2.0 do not offer it yet.
	// The call fails with a refusal of the daemon until they do, and it
	// changes nothing. The README states the contract.
	ToolOpen = "open_merge_request"
	// ToolState reads the state of a merge request.
	ToolState = "merge_request_state"
	// ToolMerge merges a merge request.
	ToolMerge = "merge_merge_request"
)

// StateMerged is the state that merge_request_state returns for a merged
// merge request.
const StateMerged = "merged"

// MaxRefBytes bounds a merge request reference.
const MaxRefBytes = 200

// Repo names the GitOps repo of the buyer and the connector that reaches it.
type Repo struct {
	// Connector is the id of the Git host connector.
	Connector string
	// Project is the project of the repo on the host, for example
	// "acme/manifests".
	Project string
	// BaseBranch is the branch that the merge request targets.
	BaseBranch string
	// Dir is the directory of the repo that holds the files of the agent.
	Dir string
}

// Check refuses a repo that the agent cannot use.
func (r Repo) Check() error {
	if !gitHosts[r.Connector] {
		return fmt.Errorf("isolate: %q is not a Git host connector of this agent", respond.Clean(r.Connector))
	}
	if strings.TrimSpace(r.Project) == "" || strings.TrimSpace(r.BaseBranch) == "" {
		return errors.New("isolate: the GitOps repo needs a project and a base branch")
	}
	if strings.IndexFunc(r.Project+r.BaseBranch+r.Dir, unicode.IsControl) >= 0 {
		return errors.New("isolate: the GitOps repo holds a control character")
	}
	if strings.HasPrefix(r.Dir, "/") || strings.Contains(r.Dir, "..") {
		return errors.New("isolate: the directory must stay inside the repo")
	}
	return nil
}

// Call is the outcome of one tool call.
type Call struct {
	Outcome respond.Outcome
	Detail  string
}

// Done reports whether the connector answered.
func (c Call) Done() bool { return c.Outcome == respond.OutcomeDone }

// Host is the Git host of the buyer, reached through the connector.
type Host interface {
	// Open opens the merge request of the change and returns its reference.
	Open(ctx context.Context, c Change) (ref string, call Call, err error)
	// State reads the state of a merge request on the host.
	State(ctx context.Context, ref string) (state string, call Call, err error)
	// Merge merges the merge request. It returns whether the host merged it.
	Merge(ctx context.Context, ref string) (merged bool, call Call, err error)
}

// ToolHost is the Host that calls the tools of the connector through the
// meta-tool invoke_tool. The daemon checks the grant of the call.
type ToolHost struct {
	tools respond.ToolCaller
	repo  Repo
}

// NewToolHost builds a ToolHost.
func NewToolHost(tools respond.ToolCaller, repo Repo) (*ToolHost, error) {
	if tools == nil {
		return nil, errors.New("isolate: no tool caller")
	}
	if err := repo.Check(); err != nil {
		return nil, err
	}
	return &ToolHost{tools: tools, repo: repo}, nil
}

func (h *ToolHost) toolID(tool string) string { return "mcp:" + h.repo.Connector + ":" + tool }

func (h *ToolHost) call(ctx context.Context, tool string, args map[string]any) (respond.Reply, Call, error) {
	r, err := respond.Call(ctx, h.tools, h.toolID(tool), args)
	if err != nil {
		return respond.Reply{}, Call{}, fmt.Errorf("isolate: %w", err)
	}
	return r, Call{Outcome: r.Outcome, Detail: r.Detail}, nil
}

// Open implements Host. The result must name the merge request, and the name
// must be a plain reference: the agent sends it back to the connector.
func (h *ToolHost) Open(ctx context.Context, c Change) (string, Call, error) {
	files := make([]any, 0, len(c.Files))
	for _, f := range c.Files {
		entry := map[string]any{"path": f.Path}
		if f.Delete {
			entry["delete"] = true
		} else {
			entry["content"] = f.Content
		}
		files = append(files, entry)
	}
	r, call, err := h.call(ctx, ToolOpen, map[string]any{
		"project": h.repo.Project, "base_branch": h.repo.BaseBranch, "branch": c.Branch,
		"title": c.Title, "description": c.Description, "files": files,
	})
	if err != nil || !call.Done() {
		return "", call, err
	}
	ref, _ := r.Result["merge_request"].(string)
	if problem := refProblem(ref); problem != "" {
		return "", Call{Outcome: respond.OutcomeFailed, Detail: problem}, nil
	}
	return ref, call, nil
}

// State implements Host.
func (h *ToolHost) State(ctx context.Context, ref string) (string, Call, error) {
	r, call, err := h.call(ctx, ToolState, map[string]any{"merge_request": ref})
	if err != nil || !call.Done() {
		return "", call, err
	}
	state, _ := r.Result["state"].(string)
	return state, call, nil
}

// Merge implements Host. The connector merges only when the checks passed
// and the daemon grants the merge. The result says whether it merged.
func (h *ToolHost) Merge(ctx context.Context, ref string) (bool, Call, error) {
	r, call, err := h.call(ctx, ToolMerge, map[string]any{"merge_request": ref})
	if err != nil || !call.Done() {
		return false, call, err
	}
	merged, _ := r.Result["merged"].(bool)
	return merged, call, nil
}

// refProblem says why a value is not a merge request reference, or "".
func refProblem(ref string) string {
	switch {
	case strings.TrimSpace(ref) == "":
		return "the connector returned no merge request reference"
	case len(ref) > MaxRefBytes:
		return "the connector returned a merge request reference that is too long"
	case strings.IndexFunc(ref, unicode.IsSpace) >= 0 || strings.IndexFunc(ref, unicode.IsControl) >= 0:
		return "the connector returned a merge request reference that holds a space or a control character"
	default:
		return ""
	}
}
