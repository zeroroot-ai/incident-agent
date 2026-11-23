// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package isolate

import (
	"context"
	"crypto/sha1" //nolint:gosec // git object ids are SHA-1 in a SHA-1 repository
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/zeroroot-ai/incident-agent/internal/respond"
)

// The Git host connectors that the agent can use. The table is closed. A
// connector id from the dispatch selects a row, and only a row builds a tool
// id. These are the connectors that the fix loop uses (gibson catalog
// manifests github-fixloop.yaml and gitlab-fixloop.yaml).
var gitHosts = map[string]bool{"github-fixloop": true, "gitlab-fixloop": true}

// The tools of a Git host connector. All five exist in v0.5.0 of the servers
// in zeroroot-ai/connectors. The merge tool takes the expected head as
// expected_head_sha, and it refuses an empty value. The README states the
// contract of each.
const (
	// ToolState reads the state of a merge request.
	ToolState = "merge_request_state"
	// ToolMerge merges a merge request.
	ToolMerge = "merge_merge_request"
	// ToolOpen opens a merge request with a set of file changes.
	ToolOpen = "open_merge_request"
	// ToolClose closes a merge request without a merge.
	ToolClose = "close_merge_request"
	// ToolReadFile reads one file on a branch.
	ToolReadFile = "read_file"
)

// StateMerged is the state that merge_request_state returns for a merged
// merge request.
const StateMerged = "merged"

// StateOpen is the state of a merge request that waits for its merge.
const StateOpen = "open"

// MaxRefBytes bounds a merge request reference.
const MaxRefBytes = 200

// The kinds of policy. Each is a different object in the repo of the buyer.
const (
	// KindCilium is a CiliumNetworkPolicy with egressDeny and ingressDeny.
	// A deny rule wins over each allow rule of Cilium.
	KindCilium = "cilium"
	// KindCluster is a ClusterNetworkPolicy of the tier Admin with the action
	// Deny (policy.networking.k8s.io/v1beta1). The Admin tier is evaluated
	// before each NetworkPolicy. The Kubernetes network policy API replaced
	// AdminNetworkPolicy with it in v0.2.0.
	KindCluster = "cluster"
	// KindNetworkPolicy is a NetworkPolicy. Policies add up, so another
	// policy that allows traffic still allows it. See BypassNote.
	KindNetworkPolicy = "networkpolicy"
)

// BypassNote is what the report and the incident record say about a
// NetworkPolicy isolation.
const BypassNote = "NetworkPolicy objects add up, so another policy that allows traffic still allows it. " +
	"A CNI that does not enforce policy, and a pod with hostNetwork, bypass it. " +
	"Use the policy kind cilium or cluster to get a deny that wins."

// defaultControllerNamespaces hold the GitOps controller of the buyer. A
// policy that denies all traffic there stops the controller, so it can no
// longer apply the release. The dispatch can name more.
var defaultControllerNamespaces = []string{"argocd", "flux-system"}

// shaForm is a git commit id: 40 hexadecimal characters, or 64 for a
// repository with SHA-256 object ids.
var shaForm = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// dirPart is one segment of the directory or of the cluster name.
var dirPart = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

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
	// Cluster names the cluster when one repo serves many clusters. The files
	// go in Dir/Cluster. It can be empty.
	Cluster string
	// PolicyKind is one of KindCilium, KindCluster and KindNetworkPolicy.
	PolicyKind string
	// ControllerNamespaces are namespaces of the GitOps controller, besides
	// the defaults. The agent never isolates a workload in them.
	ControllerNamespaces []string
}

// Check refuses a repo that the agent cannot use.
func (r Repo) Check() error {
	if !gitHosts[r.Connector] {
		return fmt.Errorf("isolate: %q is not a Git host connector of this agent", respond.Clean(r.Connector))
	}
	if strings.TrimSpace(r.Project) == "" || strings.TrimSpace(r.BaseBranch) == "" {
		return errors.New("isolate: the GitOps repo needs a project and a base branch")
	}
	if strings.IndexFunc(r.Project+r.BaseBranch, unicode.IsControl) >= 0 {
		return errors.New("isolate: the GitOps repo holds a control character")
	}
	if err := checkDir(r.Dir); err != nil {
		return err
	}
	if r.Cluster != "" && (strings.Contains(r.Cluster, "/") || !dirPart.MatchString(r.Cluster)) {
		return errors.New("isolate: the cluster name must be one path segment of a-z, 0-9, dot, underscore and dash")
	}
	switch r.PolicyKind {
	case KindCilium, KindCluster, KindNetworkPolicy:
	default:
		return fmt.Errorf("isolate: the policy kind %q is not %s, %s or %s",
			respond.Clean(r.PolicyKind), KindCilium, KindCluster, KindNetworkPolicy)
	}
	return nil
}

// checkDir refuses a directory that is empty, that is not made of plain
// segments, or that starts a hidden segment. A hidden segment such as .github
// holds the workflows of the repo, and a merge request that writes there runs
// code with the credentials of the repo.
func checkDir(dir string) error {
	if dir == "" {
		return errors.New("isolate: the directory is empty")
	}
	for _, seg := range strings.Split(dir, "/") {
		if !dirPart.MatchString(seg) {
			return errors.New("isolate: the directory must hold only segments of a-z, 0-9, dot, underscore and dash, " +
				"and no segment starts with a dot or a dash")
		}
	}
	return nil
}

// base is the directory of the files of one cluster.
func (r Repo) base() string {
	if r.Cluster == "" {
		return r.Dir
	}
	return r.Dir + "/" + r.Cluster
}

// Allows refuses a workload that the agent must not isolate with this repo:
// one in the namespace of the GitOps controller.
func (r Repo) Allows(w Workload) error {
	for _, ns := range append(append([]string(nil), defaultControllerNamespaces...), r.ControllerNamespaces...) {
		if w.Namespace == ns {
			return fmt.Errorf("isolate: the namespace %s holds the GitOps controller, "+
				"and a deny-all policy there stops it from applying the release", ns)
		}
	}
	return nil
}

// refForm is the form of a merge request reference that the agent accepts:
// the configured project, "#" or "!", and the number. A reference to another
// project, or a URL, is refused.
func (r Repo) refProblem(ref string) string {
	switch {
	case strings.TrimSpace(ref) == "":
		return "no merge request reference"
	case len(ref) > MaxRefBytes:
		return "the merge request reference is too long"
	}
	rest, ok := strings.CutPrefix(ref, r.Project)
	if !ok || len(rest) < 2 || (rest[0] != '#' && rest[0] != '!') {
		return "the merge request is not in the configured project " + respond.Clean(r.Project)
	}
	for _, c := range rest[1:] {
		if c < '0' || c > '9' {
			return "the merge request reference does not end in a number"
		}
	}
	return ""
}

// Call is the outcome of one tool call.
type Call struct {
	Outcome respond.Outcome
	Detail  string
}

// Done reports whether the connector answered.
func (c Call) Done() bool { return c.Outcome == respond.OutcomeDone }

// MR is what the host says about one merge request.
type MR struct {
	State string
	// SourceBranch is the branch of the merge request. The connector omits
	// it for a merge request from a fork.
	SourceBranch string
	// Files are the files that the merge request changes, as the host lists
	// them. FilesKnown is false when the host returned no list. Truncated is
	// true when the host cut the list.
	Files      []ChangedFile
	FilesKnown bool
	Truncated  bool
	// FilesError is the reason that the host gave for a list that it could
	// not make. FilesKnown is false then.
	FilesError string
	// HeadSHA is the head commit of the branch. A person with push access can
	// add a commit to the branch, so the agent compares it with the commit
	// that it recorded when it opened the merge request.
	HeadSHA string
}

// Host is the Git host of the buyer, reached through the connector.
type Host interface {
	// Open opens the merge request of the change and returns its reference
	// and the head commit of its branch.
	Open(ctx context.Context, c Change) (ref, sha string, call Call, err error)
	// State reads one merge request on the host.
	State(ctx context.Context, ref string) (mr MR, call Call, err error)
	// Merge merges the merge request at the expected head commit. The host
	// refuses the merge when the head moved. It returns whether the host
	// merged it.
	Merge(ctx context.Context, ref, sha string) (merged bool, call Call, err error)
	// Close closes the merge request without a merge.
	Close(ctx context.Context, ref string) (call Call, err error)
	// ReadFile reads one file on the base branch.
	ReadFile(ctx context.Context, path string) (content string, found bool, call Call, err error)
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

// Open implements Host. The result must name a merge request of the
// configured project, because the agent sends the reference back.
func (h *ToolHost) Open(ctx context.Context, c Change) (ref, sha string, call Call, err error) {
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
		return "", "", call, err
	}
	ref, _ = r.Result["merge_request"].(string)
	if problem := h.repo.refProblem(ref); problem != "" {
		return "", "", Call{Outcome: respond.OutcomeFailed, Detail: problem}, nil
	}
	sha, _ = r.Result["head_sha"].(string)
	if !shaForm.MatchString(sha) {
		return "", "", Call{Outcome: respond.OutcomeFailed, Detail: "the connector returned no head commit"}, nil
	}
	return ref, sha, call, nil
}

// State implements Host.
func (h *ToolHost) State(ctx context.Context, ref string) (MR, Call, error) {
	r, call, err := h.call(ctx, ToolState, map[string]any{"merge_request": ref})
	if err != nil || !call.Done() {
		return MR{}, call, err
	}
	state, _ := r.Result["state"].(string)
	branch, _ := r.Result["source_branch"].(string)
	sha, _ := r.Result["head_sha"].(string)
	files, known := changedFiles(r.Result["changed_files"])
	truncated, _ := r.Result["changed_files_truncated"].(bool)
	ferr, _ := r.Result["changed_files_error"].(string)
	if ferr != "" {
		// The host could not make the list. An empty list is no answer.
		files, known = nil, false
	}
	return MR{State: state, SourceBranch: branch, HeadSHA: sha, Files: files, FilesKnown: known,
		Truncated: truncated, FilesError: ferr}, call, nil
}

// Merge implements Host. The connector merges only when the checks passed
// and the daemon grants the merge. The result says whether it merged.
func (h *ToolHost) Merge(ctx context.Context, ref, sha string) (bool, Call, error) {
	r, call, err := h.call(ctx, ToolMerge, map[string]any{"merge_request": ref, "expected_head_sha": sha})
	if err != nil || !call.Done() {
		return false, call, err
	}
	merged, _ := r.Result["merged"].(bool)
	return merged, call, nil
}

// Close implements Host.
func (h *ToolHost) Close(ctx context.Context, ref string) (Call, error) {
	_, call, err := h.call(ctx, ToolClose, map[string]any{"merge_request": ref})
	return call, err
}

// ReadFile implements Host. It reads the base branch. A result that does not
// say whether the file exists is a failure, never "found".
func (h *ToolHost) ReadFile(ctx context.Context, path string) (content string, found bool, call Call, err error) {
	r, call, err := h.call(ctx, ToolReadFile, map[string]any{
		"project": h.repo.Project, "ref": h.repo.BaseBranch, "path": path,
	})
	if err != nil || !call.Done() {
		return "", false, call, err
	}
	found, ok := r.Result["found"].(bool)
	if !ok {
		return "", false, Call{Outcome: respond.OutcomeFailed, Detail: "the result does not say if the file exists"}, nil
	}
	content, _ = r.Result["content"].(string)
	return content, found, call, nil
}

// BypassNoteCluster is what the report and the incident record say about a
// ClusterNetworkPolicy isolation. The peers of the API are namespaces, pods and
// networks, so it cannot name a node.
const BypassNoteCluster = "A ClusterNetworkPolicy does not deny ingress from nodes, from pods with hostNetwork, " +
	"or from outside traffic that is translated to a node address. The policy API cannot express it. " +
	"Use the policy kind cilium to deny these paths."

// bypassNote returns the note for a kind that can be bypassed, or "" for a
// kind that denies each path.
func bypassNote(kind string) string {
	switch kind {
	case KindNetworkPolicy:
		return BypassNote
	case KindCluster:
		return BypassNoteCluster
	default:
		return ""
	}
}

// ChangedFile is one entry of the list that merge_request_state returns for
// the files that a merge request changes. The list holds no content. It holds
// the git blob id of each file after the change.
type ChangedFile struct {
	Path string
	// Change is added, modified, deleted or renamed.
	Change string
	// PreviousPath is set for a renamed file.
	PreviousPath string
	// BlobSHA is the git blob id of the file after the change. It is empty for
	// a deleted file.
	BlobSHA string
	// Mode is the file mode after the change, for example 100644. The host can
	// leave it empty (GitHub sends none).
	Mode string
}

// changedFiles reads the list changed_files of merge_request_state. It returns
// false for a result that has no list, or a malformed entry. A malformed list
// never reads as an empty change.
func changedFiles(v any) ([]ChangedFile, bool) {
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]ChangedFile, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		f := ChangedFile{}
		f.Path, _ = m["path"].(string)
		f.Change, _ = m["change"].(string)
		f.PreviousPath, _ = m["previous_path"].(string)
		f.BlobSHA, _ = m["blob_sha"].(string)
		f.Mode, _ = m["mode"].(string)
		if f.Path == "" || f.Change == "" {
			return nil, false
		}
		out = append(out, f)
	}
	return out, true
}

// gitBlobSHA is the git object id of a file: the hash of "blob <length>", a
// zero byte and the content. The hash is SHA-256 when the head commit has 64
// hexadecimal characters, and SHA-1 when it has 40.
func gitBlobSHA(headSHA, content string) string {
	header := "blob " + strconv.Itoa(len(content)) + "\x00"
	if len(headSHA) == 64 {
		sum := sha256.Sum256([]byte(header + content))
		return hex.EncodeToString(sum[:])
	}
	sum := sha1.Sum([]byte(header + content)) //nolint:gosec // git object ids are SHA-1 in a SHA-1 repository
	return hex.EncodeToString(sum[:])
}
