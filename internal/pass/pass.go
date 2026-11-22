// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package pass assembles one task of the incident response mission and runs
// it against the harness that the daemon provisions.
//
// # One dispatch is one task on one incident
//
// The mission node names the incident and the task in the task context. The
// task is one of three:
//
//   - contain: make the containment actions on each target of the incident.
//   - cause: raise one finding for the cause and link it with CAUSED_BY.
//   - release: undo each containment that the agent made, after each cause
//     is verified.
//
// # What the agent never says
//
// The report says what the agent did. It never says that the incident is
// resolved. The daemon sets the status of the finding of the cause, and the
// incident report of the daemon states what happened.
package pass

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/zeroroot-ai/incident-agent/internal/cause"
	"github.com/zeroroot-ai/incident-agent/internal/contain"
	"github.com/zeroroot-ai/incident-agent/internal/emit"
	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/isolate"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
	"github.com/zeroroot-ai/sdk/agent"
	"github.com/zeroroot-ai/sdk/finding"
	"github.com/zeroroot-ai/sdk/openresponses"
	"google.golang.org/protobuf/proto"
)

// The task-context keys that the mission node sets. Both are required.
const (
	// ContextKeyIncident is the key of the Incident node.
	ContextKeyIncident = "incident"
	// ContextKeyTask is the task of the dispatch.
	ContextKeyTask = "ir.task"
)

// The tasks of the agent.
const (
	TaskContain = "contain"
	TaskCause   = "cause"
	TaskRelease = "release"
	// TaskIsolate isolates one Kubernetes workload with a merge request to
	// the GitOps repo of the buyer.
	TaskIsolate = "isolate"
	// TaskReleaseWorkload removes that isolation with a second merge request.
	TaskReleaseWorkload = "release_workload"
)

// Platform is everything that this agent needs from the harness: the tool
// call of the meta-tool, the finding calls, the observation write and the
// model client.
//
// agent.Harness satisfies it. Naming the methods and not taking the whole
// harness is what lets a test run the pass without a daemon.
type Platform interface {
	CallToolProto(ctx context.Context, name string, request, response proto.Message, opts ...agent.ToolCallOption) error
	SubmitFinding(ctx context.Context, f *finding.Finding) error
	GetFindings(ctx context.Context, filter finding.Filter) ([]*finding.Finding, error)
	Observe(ctx context.Context, obs agent.Observation) error
	Model(ctx context.Context, slot string) (*openresponses.Client, error)
}

func ctxString(task agent.Task, key string) string {
	if s, ok := task.Context[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// IncidentKey reads the incident of the task. The goal is not a fallback: the
// goal of a mission node is a sentence for a person, not a key.
func IncidentKey(task agent.Task) (string, error) {
	key, err := incident.ValidKey(ctxString(task, ContextKeyIncident))
	if err != nil {
		return "", fmt.Errorf("pass: task context %q: %w", ContextKeyIncident, err)
	}
	return key, nil
}

// TaskOf reads the task of the dispatch.
func TaskOf(task agent.Task) (string, error) {
	switch t := ctxString(task, ContextKeyTask); t {
	case TaskContain, TaskCause, TaskRelease, TaskIsolate, TaskReleaseWorkload:
		return t, nil
	default:
		return "", fmt.Errorf("pass: task context %q is %q: want %q, %q, %q, %q or %q",
			ContextKeyTask, respond.Clean(t), TaskContain, TaskCause, TaskRelease, TaskIsolate, TaskReleaseWorkload)
	}
}

// Run performs one task on one incident and reports what it did. reader
// reads the incident, and calls confirms that a record names a tool call of
// this agent.
func Run(
	ctx context.Context, p Platform, reader incident.Reader, calls contain.CallChecker, task agent.Task,
) (agent.Result, error) {
	if p == nil || reader == nil || calls == nil {
		return failed(), errors.New("pass: no platform, no incident reader or no call checker")
	}
	key, err := IncidentKey(task)
	if err != nil {
		return failed(), err
	}
	kind, err := TaskOf(task)
	if err != nil {
		return failed(), err
	}
	emitter, err := emit.New(p)
	if err != nil {
		return failed(), err
	}
	invoker, err := respond.New(p)
	if err != nil {
		return failed(), err
	}
	if kind == TaskIsolate || kind == TaskReleaseWorkload {
		return runWorkload(ctx, p, reader, emitter, task, kind, key)
	}
	resp := contain.Pass{
		Reader: reader, Invoker: invoker, Recorder: emitter, Calls: calls,
		Causes: cause.Finder{Findings: p},
	}

	switch kind {
	case TaskCause:
		inc, rerr := reader.Incident(ctx, key)
		if rerr != nil {
			return failed(), fmt.Errorf("pass: read incident %s: %w", key, rerr)
		}
		step := cause.Step{LLM: llmAdapter{p: p}, Findings: p, Linker: emitter}
		res, cerr := step.Raise(ctx, inc)
		if cerr != nil {
			return failed(), cerr
		}
		return agent.Result{
			Status: a2a.TaskStateCompleted, Output: CauseReport(key, res),
			Metadata: map[string]any{"task": kind, "incident": key, "cause": res.FindingID},
		}, nil
	case TaskRelease:
		sum, rerr := resp.Release(ctx, key)
		if rerr != nil {
			return failed(), rerr
		}
		return done(kind, key, sum), nil
	default:
		sum, cerr := resp.Contain(ctx, key)
		if cerr != nil {
			return failed(), cerr
		}
		return done(kind, key, sum), nil
	}
}

// runWorkload isolates or releases one Kubernetes workload through the Git
// host connector.
func runWorkload(
	ctx context.Context, p Platform, reader incident.Reader, emitter *emit.Emitter,
	task agent.Task, kind, key string,
) (agent.Result, error) {
	w, repo, err := workloadOf(task)
	if err != nil {
		return failed(), err
	}
	host, err := isolate.NewToolHost(p, repo)
	if err != nil {
		return failed(), fmt.Errorf("pass: %w", err)
	}
	ip := isolate.Pass{Reader: reader, Host: host, Recorder: emitter, Causes: cause.Finder{Findings: p}, Repo: repo}
	var sum isolate.Summary
	if kind == TaskIsolate {
		sum, err = ip.Isolate(ctx, key, w)
	} else {
		sum, err = ip.Release(ctx, key, w)
	}
	if err != nil {
		return failed(), fmt.Errorf("pass: %w", err)
	}
	return agent.Result{
		Status: a2a.TaskStateCompleted, Output: WorkloadReport(kind, sum),
		Metadata: map[string]any{
			"task": kind, "incident": key, "calls": sum.Calls, "isolated": sum.Isolated, "released": sum.Released,
		},
	}, nil
}

// The task-context keys of the workload and of the GitOps repo. The mission
// node sets them.
const (
	ContextKeyNamespace  = "ir.workload.namespace"
	ContextKeyLabels     = "ir.workload.labels"
	ContextKeyConnector  = "ir.gitops.connector"
	ContextKeyProject    = "ir.gitops.project"
	ContextKeyBaseBranch = "ir.gitops.base_branch"
	ContextKeyDir        = "ir.gitops.dir"
)

func workloadOf(task agent.Task) (isolate.Workload, isolate.Repo, error) {
	w, err := isolate.ParseWorkload(ctxString(task, ContextKeyNamespace), ctxString(task, ContextKeyLabels))
	if err != nil {
		return isolate.Workload{}, isolate.Repo{}, fmt.Errorf("pass: task context: %w", err)
	}
	repo := isolate.Repo{
		Connector:  ctxString(task, ContextKeyConnector),
		Project:    ctxString(task, ContextKeyProject),
		BaseBranch: ctxString(task, ContextKeyBaseBranch),
		Dir:        ctxString(task, ContextKeyDir),
	}
	if repo.Dir == "" {
		repo.Dir = isolate.DefaultDir
	}
	if err := repo.Check(); err != nil {
		return isolate.Workload{}, isolate.Repo{}, fmt.Errorf("pass: task context: %w", err)
	}
	return w, repo, nil
}

// WorkloadReport renders an isolate or release pass. It names each step. It
// never says that the incident is resolved.
func WorkloadReport(kind string, s isolate.Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "incident-agent %s: incident %s: containment %s: %d calls", kind, s.Incident, s.Key, s.Calls)
	if s.Held != "" {
		b.WriteString("\n  released nothing: " + s.Held)
	}
	for _, l := range s.Lines {
		b.WriteString("\n  " + l)
	}
	return b.String()
}

func done(kind, key string, sum contain.Summary) agent.Result {
	return agent.Result{
		Status: a2a.TaskStateCompleted,
		Output: Report(kind, sum),
		Metadata: map[string]any{
			"task":     kind,
			"incident": key,
			"done":     sum.Count(respond.OutcomeDone),
			"pending":  sum.Count(respond.OutcomePending),
			"refused":  sum.Count(respond.OutcomeRefused),
			"failed":   sum.Count(respond.OutcomeFailed),
			"unknown":  sum.Count(respond.OutcomeUnknown),
			"already":  len(sum.Already),
		},
	}
}

func failed() agent.Result { return agent.Result{Status: a2a.TaskStateFailed} }

// Report renders a contain or release pass as one readable block. It names
// each action with its outcome. It never says that the incident is resolved.
func Report(kind string, s contain.Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "incident-agent %s: incident %s: %d calls, %d done, %d pending authorization, "+
		"%d refused, %d failed, %d unknown",
		kind, s.Incident, s.Calls, s.Count(respond.OutcomeDone), s.Count(respond.OutcomePending),
		s.Count(respond.OutcomeRefused), s.Count(respond.OutcomeFailed), s.Count(respond.OutcomeUnknown))
	if s.Held != "" {
		b.WriteString("\n  released nothing: " + s.Held)
	}
	for _, a := range s.Already {
		fmt.Fprintf(&b, "\n  %s %s: contained already by this agent: no call", a.ToolID(), a.Target.VendorID)
	}
	for _, r := range s.Results {
		fmt.Fprintf(&b, "\n  %s %s: %s", r.Action.ToolID(), r.Action.Target.VendorID, r.Outcome)
		if r.Detail != "" {
			b.WriteString(": " + r.Detail)
		}
	}
	for _, sk := range s.Skipped {
		if sk.Record != "" {
			fmt.Fprintf(&b, "\n  the record %s is not trusted: %s", sk.Record, sk.Reason)
			continue
		}
		fmt.Fprintf(&b, "\n  no action on %s %s: %s", respond.Clean(sk.Place.Label), respond.Clean(sk.Place.Key), sk.Reason)
	}
	if s.Capped {
		fmt.Fprintf(&b, "\n  stopped at %d calls: the next dispatch makes the rest", contain.MaxActions)
	}
	if s.Count(respond.OutcomePending) > 0 {
		b.WriteString("\n  a call that waits for a person stays in the approval queue: the next dispatch calls it again")
	}
	if s.Count(respond.OutcomeUnknown) > 0 {
		b.WriteString("\n  a call with the outcome unknown timed out or lost its transport: the vendor can have " +
			"taken the action. The agent wrote no contained record for it, and the next dispatch calls it again")
	}
	return b.String()
}

// CauseReport renders the cause step.
func CauseReport(key string, r cause.Result) string {
	switch {
	case r.Existing:
		return fmt.Sprintf("incident-agent cause: incident %s names the cause %s already: no finding raised",
			key, respond.Clean(r.FindingID))
	case r.Reused:
		return fmt.Sprintf("incident-agent cause: incident %s: linked the finding %s that an earlier run raised",
			key, r.FindingID)
	default:
		return fmt.Sprintf("incident-agent cause: incident %s: raised the finding %s and linked it with CAUSED_BY: %s\n"+
			"  the fix loop fixes it, and the daemon sets its status", key, r.FindingID, r.Title)
	}
}

// llmAdapter narrows the Open Responses client to the one shape that the
// cause step needs: a system item and a user item, and the text back.
type llmAdapter struct {
	p Platform
}

func (a llmAdapter) Complete(ctx context.Context, slot, system, user string) (string, error) {
	model, err := a.p.Model(ctx, slot)
	if err != nil {
		return "", fmt.Errorf("pass: resolve slot %q: %w", slot, err)
	}
	if model == nil {
		return "", fmt.Errorf("pass: slot %q has no model client", slot)
	}
	resp, err := model.Create(ctx, &openresponses.Request{
		Input: []openresponses.Item{
			openresponses.NewSystemMessage(system),
			openresponses.NewUserMessage(user),
		},
	})
	if err != nil {
		return "", fmt.Errorf("pass: complete on slot %q: %w", slot, err)
	}
	if resp == nil {
		return "", errors.New("pass: the model returned no response")
	}
	return resp.Text(), nil
}
