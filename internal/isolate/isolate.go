// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package isolate

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/zeroroot-ai/incident-agent/internal/contain"
	"github.com/zeroroot-ai/incident-agent/internal/emit"
	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
)

// The record names. Each holds the key of the containment and a generation,
// and the value is a merge request reference. A name has letters, digits and
// "_" only, so the graph projector keeps it (emit.RecordNamePattern).
const (
	recIsolationOpened = "ir_isolation_opened_"
	recIsolated        = "ir_isolation_merged_"
	recReleaseOpened   = "ir_release_opened_"
	recReleased        = "ir_isolation_released_"
	// recReverted says that the host shows the merged policy gone from the
	// base branch. The generation is closed, and the next one isolates again.
	recReverted = "ir_isolation_reverted_"
	// recBypass holds BypassNote for a NetworkPolicy isolation.
	recBypass = "ir_isolation_bypass_"
)

func recName(prefix, key string, gen int) string { return prefix + key + "_" + strconv.Itoa(gen) }

// Recorder writes the records of the pass on the Incident node.
type Recorder interface {
	RecordValue(ctx context.Context, incidentKey, name, value string) error
	Held(ctx context.Context, incidentKey, reason string) error
}

// Pass holds the parts of an isolation pass.
type Pass struct {
	Reader   incident.Reader
	Host     Host
	Recorder Recorder
	// Causes finds the cause finding of this agent. The release needs it.
	Causes contain.CauseFinder
	Repo   Repo
}

// Summary is what one pass did.
type Summary struct {
	Incident string
	Key      string
	// Lines say what each step did, in order.
	Lines []string
	// Calls is the number of tool calls.
	Calls int
	// Merged is true when the host shows the isolation merge request merged.
	// A merge is not an application: the GitOps controller of the buyer
	// applies it to the cluster, and the agent does not see that.
	Merged bool
	// OnBase is true when the policy file is on the base branch.
	OnBase bool
	// Released is true when the host shows the release merged.
	Released bool
	// Held is why a release released nothing.
	Held string
}

func (p Pass) check(w Workload, release bool) error {
	if p.Reader == nil || p.Host == nil || p.Recorder == nil {
		return errors.New("isolate: a pass needs a reader, a host and a recorder")
	}
	if release && p.Causes == nil {
		return errors.New("isolate: a release pass needs a cause finder")
	}
	if err := p.Repo.Check(); err != nil {
		return err
	}
	return p.Repo.Allows(w)
}

// generation returns the generation to work on. It is the last generation
// that holds an opened or a merged record, unless that generation is closed
// by a release or a revert. Then it is the next one. A fresh containment is
// generation 1.
func generation(inc incident.Incident, key string) int {
	gen := 0
	for n := 1; n <= emit.MaxGeneration; n++ {
		if !inc.HasRecord(recName(recIsolationOpened, key, n)) && !inc.HasRecord(recName(recIsolated, key, n)) {
			break
		}
		gen = n
	}
	switch {
	case gen == 0:
		return 1
	case inc.HasRecord(recName(recReleased, key, gen)) || inc.HasRecord(recName(recReverted, key, gen)):
		return gen + 1
	default:
		return gen
	}
}

// Isolate isolates the workload with a merged merge request. A record is
// never enough: the agent reads each merge request on the host and trusts it
// only on the expected branch in the configured project.
func (p Pass) Isolate(ctx context.Context, key string, w Workload) (Summary, error) {
	if err := p.check(w, false); err != nil {
		return Summary{}, err
	}
	inc, err := p.Reader.Incident(ctx, key)
	if err != nil {
		return Summary{Incident: key}, fmt.Errorf("isolate: read incident %s: %w", key, err)
	}
	ck := p.Repo.Key(key, w)
	sum := Summary{Incident: key, Key: ck}
	gen := generation(inc, ck)
	run := step{p: p, inc: key, key: ck, gen: gen, sum: &sum}

	if done := inc.Records[recName(recIsolated, ck, gen)]; done != "" {
		merged, err := run.verify(ctx, done, IsolationBranch(ck, gen))
		if err != nil || !merged {
			return sum, err
		}
		present, err := run.policyOnBase(ctx, p.Repo.PolicyPath(ck), p.Repo.Isolate(key, w, gen).Files[0].Content)
		if err != nil {
			return sum, err
		}
		if present != presentGone {
			sum.Merged, sum.OnBase = true, present == presentYes
			return sum, nil
		}
		// A person or a tool reverted the policy. Close this generation and
		// isolate again in the next.
		if err := run.write(ctx, recName(recReverted, ck, gen), done); err != nil {
			return sum, err
		}
		run.say("the policy is not on the base branch any more: it was reverted or edited. " +
			"The agent isolates again in the next generation")
		gen++
		run.gen = gen
		inc.Records = map[string]string{}
	}

	ref := inc.Records[recName(recIsolationOpened, ck, gen)]
	if ref == "" {
		ref, err = run.open(ctx, p.Repo.Isolate(key, w, gen), recName(recIsolationOpened, ck, gen))
		if err != nil || ref == "" {
			return sum, err
		}
	}
	merged, err := run.drive(ctx, ref, IsolationBranch(ck, gen))
	if err != nil || !merged {
		return sum, err
	}
	if err := run.write(ctx, recName(recIsolated, ck, gen), ref); err != nil {
		return sum, err
	}
	sum.Merged = true
	present, err := run.policyOnBase(ctx, p.Repo.PolicyPath(ck), p.Repo.Isolate(key, w, gen).Files[0].Content)
	if err != nil {
		return sum, err
	}
	sum.OnBase = present == presentYes
	if p.Repo.PolicyKind == KindNetworkPolicy {
		run.say("caution: " + BypassNote)
		return sum, run.write(ctx, recName(recBypass, ck, gen), BypassNote)
	}
	return sum, nil
}

// Release removes the isolation with a second merged merge request, after the
// cause that this agent raised is verified. It also closes an isolation merge
// request that never merged, so nobody merges it later.
func (p Pass) Release(ctx context.Context, key string, w Workload) (Summary, error) {
	if err := p.check(w, true); err != nil {
		return Summary{}, err
	}
	inc, err := p.Reader.Incident(ctx, key)
	if err != nil {
		return Summary{Incident: key}, fmt.Errorf("release: read incident %s: %w", key, err)
	}
	ck := p.Repo.Key(key, w)
	sum := Summary{Incident: key, Key: ck}
	held, err := contain.HeldReason(ctx, p.Causes, inc)
	if err != nil {
		return sum, fmt.Errorf("release: %w", err)
	}
	if held != "" {
		sum.Held = held
		if err := p.Recorder.Held(ctx, key, held); err != nil {
			return sum, fmt.Errorf("release: %w", err)
		}
		return sum, nil
	}
	gen := generation(inc, ck)
	run := step{p: p, inc: key, key: ck, gen: gen, sum: &sum}
	isolated, cont, err := run.isolationRef(ctx, inc)
	if err != nil || !cont {
		return sum, err
	}
	merged, err := run.verify(ctx, isolated, IsolationBranch(ck, gen))
	if err != nil || !merged {
		return sum, err
	}
	present, err := run.policyOnBase(ctx, p.Repo.PolicyPath(ck), "")
	if err != nil {
		return sum, err
	}
	if present == presentGone {
		run.say("the policy is not on the base branch, so there is nothing to release")
		return sum, run.write(ctx, recName(recReverted, ck, gen), isolated)
	}
	if present == presentUnknown {
		return sum, nil
	}
	ref := inc.Records[recName(recReleaseOpened, ck, gen)]
	if ref == "" {
		ref, err = run.open(ctx, p.Repo.Release(key, w, gen), recName(recReleaseOpened, ck, gen))
		if err != nil || ref == "" {
			return sum, err
		}
	}
	merged, err = run.drive(ctx, ref, ReleaseBranch(ck, gen))
	if err != nil || !merged {
		return sum, err
	}
	sum.Released = true
	return sum, run.write(ctx, recName(recReleased, ck, gen), ref)
}

// step runs the calls of one pass and keeps its summary.
type step struct {
	p   Pass
	inc string
	key string
	gen int
	sum *Summary
}

func (s step) say(line string) { s.sum.Lines = append(s.sum.Lines, line) }

func (s step) write(ctx context.Context, name, value string) error {
	if err := s.p.Recorder.RecordValue(ctx, s.inc, name, value); err != nil {
		return fmt.Errorf("isolate: record %s: %w", name, err)
	}
	return nil
}

// isolationRef returns the merge request of the isolation that the release
// works on, and whether the release goes on.
func (s step) isolationRef(ctx context.Context, inc incident.Incident) (string, bool, error) {
	isolated := inc.Records[recName(recIsolated, s.key, s.gen)]
	opened := inc.Records[recName(recIsolationOpened, s.key, s.gen)]
	switch {
	case isolated == "" && opened == "":
		s.say("this agent holds no isolation of the workload to release")
		return "", false, nil
	case isolated == "":
		return s.settleOpen(ctx, opened, IsolationBranch(s.key, s.gen))
	default:
		return isolated, true, nil
	}
}

// settleOpen handles an isolation merge request that the agent opened and did
// not record as merged. A merge request that is still open is closed, so
// nobody merges it after the release. A merge request that merged is
// recorded, and the release goes on with it. It returns the merged reference
// and whether the release goes on.
func (s step) settleOpen(ctx context.Context, ref, branch string) (merged string, cont bool, err error) {
	mr, ok, err := s.read(ctx, ref, branch)
	if err != nil || !ok {
		return "", false, err
	}
	switch mr.State {
	case StateMerged:
		if err := s.write(ctx, recName(recIsolated, s.key, s.gen), ref); err != nil {
			return "", false, err
		}
		return ref, true, nil
	case StateOpen:
		call, err := s.p.Host.Close(ctx, ref)
		if err != nil {
			return "", false, fmt.Errorf("isolate: %w", err)
		}
		if s.outcome("close the open isolation merge request "+respond.Clean(ref), call) {
			return "", false, nil
		}
		s.say("closed the isolation merge request " + respond.Clean(ref) + " that never merged")
	default:
		s.say("the isolation merge request " + respond.Clean(ref) + " is " + strconv.Quote(respond.Clean(mr.State)) +
			" and not merged")
	}
	return "", false, s.write(ctx, recName(recReleased, s.key, s.gen), ref)
}

// outcome counts the call. It returns true, and says why, when the call did
// not finish: the pass then stops.
func (s step) outcome(what string, c Call) bool {
	s.sum.Calls++
	if c.Done() {
		return false
	}
	line := what + ": " + string(c.Outcome)
	if c.Detail != "" {
		line += ": " + c.Detail
	}
	s.say(line)
	return true
}

// open opens the merge request and records its reference at once, so the next
// dispatch merges it and opens no second one.
func (s step) open(ctx context.Context, c Change, record string) (string, error) {
	ref, call, err := s.p.Host.Open(ctx, c)
	if err != nil {
		return "", fmt.Errorf("isolate: %w", err)
	}
	if s.outcome("open the merge request on branch "+respond.Clean(c.Branch), call) {
		return "", nil
	}
	if ref == "" {
		s.say("open the merge request: the host returned no reference")
		return "", nil
	}
	s.say("opened the merge request " + respond.Clean(ref))
	return ref, s.write(ctx, record, ref)
}

// read reads one merge request and refuses it unless it is in the configured
// project and on the expected branch. A record names the reference, and any
// writer of the graph can write a record. The host is the fact.
func (s step) read(ctx context.Context, ref, branch string) (MR, bool, error) {
	if problem := s.p.Repo.refProblem(ref); problem != "" {
		s.say("the merge request " + respond.Clean(ref) + " is not trusted: " + problem)
		return MR{}, false, nil
	}
	mr, call, err := s.p.Host.State(ctx, ref)
	if err != nil {
		return MR{}, false, fmt.Errorf("isolate: %w", err)
	}
	if s.outcome("read the state of "+respond.Clean(ref), call) {
		return MR{}, false, nil
	}
	if mr.SourceBranch != branch {
		s.say("the merge request " + respond.Clean(ref) + " is on the branch " +
			strconv.Quote(respond.Clean(mr.SourceBranch)) + " and the expected branch is " +
			strconv.Quote(branch) + ": it is not trusted")
		return MR{}, false, nil
	}
	return mr, true, nil
}

// verify reports whether the host shows the merge request merged.
func (s step) verify(ctx context.Context, ref, branch string) (bool, error) {
	mr, ok, err := s.read(ctx, ref, branch)
	if err != nil || !ok {
		return false, err
	}
	if mr.State != StateMerged {
		s.say("the host shows " + respond.Clean(ref) + " in the state " + strconv.Quote(respond.Clean(mr.State)) +
			" and not merged")
		return false, nil
	}
	s.say(respond.Clean(ref) + " is merged")
	return true, nil
}

// drive brings the merge request to the merged state. It reads the state
// before it merges, so a merge request that merged already gets no second
// merge call, which the host refuses. It reads the state again after the
// merge call.
func (s step) drive(ctx context.Context, ref, branch string) (bool, error) {
	mr, ok, err := s.read(ctx, ref, branch)
	if err != nil || !ok {
		return false, err
	}
	switch mr.State {
	case StateMerged:
		s.say(respond.Clean(ref) + " is merged already: no merge call")
		return true, nil
	case StateOpen:
	default:
		s.say("the host shows " + respond.Clean(ref) + " in the state " + strconv.Quote(respond.Clean(mr.State)) +
			": a person must decide")
		return false, nil
	}
	merged, call, err := s.p.Host.Merge(ctx, ref)
	if err != nil {
		return false, fmt.Errorf("isolate: %w", err)
	}
	if s.outcome("merge "+respond.Clean(ref), call) {
		return false, nil
	}
	if !merged {
		s.say("the host did not merge " + respond.Clean(ref) + ": the checks are not done or a rule blocks it. " +
			"The next dispatch merges it again")
		return false, nil
	}
	return s.verify(ctx, ref, branch)
}

// The answers of policyOnBase.
type presence int

const (
	presentYes presence = iota
	// presentGone means that the file is not on the base branch, or that it
	// differs from what the agent wrote.
	presentGone
	// presentUnknown means that the read failed.
	presentUnknown
)

// policyOnBase reads the policy file on the base branch. A merge shows that
// the host accepted the change. The file on the base branch shows that no one
// reverted it later. When want is empty, any content counts as present.
func (s step) policyOnBase(ctx context.Context, path, want string) (presence, error) {
	content, found, call, err := s.p.Host.ReadFile(ctx, path)
	if err != nil {
		return presentUnknown, fmt.Errorf("isolate: %w", err)
	}
	if s.outcome("read "+respond.Clean(path)+" on the base branch", call) {
		s.say("the agent cannot confirm that the policy is on the base branch")
		return presentUnknown, nil
	}
	switch {
	case !found:
		return presentGone, nil
	case want != "" && content != want:
		return presentGone, nil
	default:
		s.say("the policy file is on the base branch. The GitOps controller of the buyer applies it, " +
			"and the agent does not see that")
		return presentYes, nil
	}
}
