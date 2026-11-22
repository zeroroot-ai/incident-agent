// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package isolate

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

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
	// recBypass holds the bypass note of a kind that can be bypassed.
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

// step runs the calls of one pass and keeps its summary.
type step struct {
	p   Pass
	inc string
	key string
	gen int
	w   Workload
	sum *Summary
}

// mrRecord is a merge request that the agent opened: its reference and the
// head commit that the host returned. The record value is "<ref>@<sha>". The
// agent trusts the merge request only while its head is that commit. A
// person with push access can add a commit to the branch, and the branch
// name alone does not show it.
type mrRecord struct {
	Ref, SHA string
}

func (m mrRecord) String() string { return m.Ref + "@" + m.SHA }

// parseRecord reads a record value. It returns false for a value that is not
// "<ref>@<sha>".
func parseRecord(v string) (mrRecord, bool) {
	i := strings.LastIndex(v, "@")
	if i < 0 || !shaForm.MatchString(v[i+1:]) {
		return mrRecord{}, false
	}
	return mrRecord{Ref: v[:i], SHA: v[i+1:]}, true
}

// Isolate isolates the workload with a merged merge request. A record is
// never enough: the agent reads each merge request on the host and trusts it
// only on the expected branch, in the configured project, at the head commit
// that it recorded.
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
	run := step{p: p, inc: key, key: ck, gen: gen, w: w, sum: &sum}

	if done := inc.Records[recName(recIsolated, ck, gen)]; done != "" {
		again, err := run.confirmIsolation(ctx, done)
		if err != nil || !again {
			return sum, err
		}
		// A person or a tool reverted the policy. The generation is closed.
		// Isolate again in the next one.
		gen++
		run.gen = gen
		inc.Records = map[string]string{}
	}
	return run.isolate(ctx, inc.Records[recName(recIsolationOpened, ck, gen)])
}

// confirmIsolation checks the merged isolation of the generation. It returns
// true when the policy is gone from the base branch and the generation is
// closed.
func (s step) confirmIsolation(ctx context.Context, done string) (bool, error) {
	m, ok := parseRecord(done)
	if !ok {
		s.say("the record " + recName(recIsolated, s.key, s.gen) + " is not trusted: it holds no head commit")
		return false, nil
	}
	merged, err := s.verify(ctx, m, s.p.Repo.Isolate(s.inc, s.w, s.gen))
	if err != nil || !merged {
		return false, err
	}
	present, err := s.policyOnBase(ctx, s.p.Repo.PolicyPath(s.key), s.p.Repo.Isolate(s.inc, s.w, s.gen).Files[0].Content)
	if err != nil {
		return false, err
	}
	if present != presentGone {
		s.sum.Merged, s.sum.OnBase = true, present == presentYes
		return false, nil
	}
	if err := s.write(ctx, recName(recReverted, s.key, s.gen), done); err != nil {
		return false, err
	}
	s.say("the policy is not on the base branch any more: it was reverted or edited. " +
		"The agent isolates again in the next generation")
	return true, nil
}

// isolate opens the isolation merge request when the Incident holds none, and
// merges it.
func (s step) isolate(ctx context.Context, opened string) (Summary, error) {
	var m mrRecord
	if opened == "" {
		var err error
		m, err = s.open(ctx, s.p.Repo.Isolate(s.inc, s.w, s.gen), recName(recIsolationOpened, s.key, s.gen))
		if err != nil || m.Ref == "" {
			return *s.sum, err
		}
	} else {
		var ok bool
		if m, ok = parseRecord(opened); !ok {
			s.say("the record " + recName(recIsolationOpened, s.key, s.gen) + " is not trusted: it holds no head commit")
			return *s.sum, nil
		}
	}
	merged, err := s.drive(ctx, m, s.p.Repo.Isolate(s.inc, s.w, s.gen))
	if err != nil || !merged {
		return *s.sum, err
	}
	if err := s.write(ctx, recName(recIsolated, s.key, s.gen), m.String()); err != nil {
		return *s.sum, err
	}
	s.sum.Merged = true
	present, err := s.policyOnBase(ctx, s.p.Repo.PolicyPath(s.key), s.p.Repo.Isolate(s.inc, s.w, s.gen).Files[0].Content)
	if err != nil {
		return *s.sum, err
	}
	s.sum.OnBase = present == presentYes
	if bypassNote(s.p.Repo.PolicyKind) != "" {
		note := bypassNote(s.p.Repo.PolicyKind)
		s.say("caution: " + note)
		return *s.sum, s.write(ctx, recName(recBypass, s.key, s.gen), note)
	}
	return *s.sum, nil
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
	run := step{p: p, inc: key, key: ck, gen: gen, w: w, sum: &sum}
	isolated, cont, err := run.isolationRef(ctx, inc)
	if err != nil || !cont {
		return sum, err
	}
	merged, err := run.verify(ctx, isolated, p.Repo.Isolate(key, w, gen))
	if err != nil || !merged {
		return sum, err
	}
	return run.release(ctx, isolated, inc.Records[recName(recReleaseOpened, ck, gen)])
}

// release opens the release merge request and merges it. When the Incident
// holds the release merge request already, the agent drives that one first:
// the policy is gone from the base branch after a release that merged and
// whose record write failed, and that is a release, not a revert.
func (s step) release(ctx context.Context, isolated mrRecord, opened string) (Summary, error) {
	var m mrRecord
	if opened == "" {
		present, err := s.policyOnBase(ctx, s.p.Repo.PolicyPath(s.key), "")
		if err != nil || present == presentUnknown {
			return *s.sum, err
		}
		if present == presentGone {
			s.say("the policy is not on the base branch, so there is nothing to release")
			return *s.sum, s.write(ctx, recName(recReverted, s.key, s.gen), isolated.String())
		}
		m, err = s.open(ctx, s.p.Repo.Release(s.inc, s.w, s.gen), recName(recReleaseOpened, s.key, s.gen))
		if err != nil || m.Ref == "" {
			return *s.sum, err
		}
	} else {
		var ok bool
		if m, ok = parseRecord(opened); !ok {
			s.say("the record " + recName(recReleaseOpened, s.key, s.gen) + " is not trusted: it holds no head commit")
			return *s.sum, nil
		}
	}
	merged, err := s.drive(ctx, m, s.p.Repo.Release(s.inc, s.w, s.gen))
	if err != nil || !merged {
		return *s.sum, err
	}
	s.sum.Released = true
	return *s.sum, s.write(ctx, recName(recReleased, s.key, s.gen), m.String())
}

// isolationRef returns the merge request of the isolation that the release
// works on, and whether the release goes on.
func (s step) isolationRef(ctx context.Context, inc incident.Incident) (m mrRecord, cont bool, err error) {
	isolated := inc.Records[recName(recIsolated, s.key, s.gen)]
	opened := inc.Records[recName(recIsolationOpened, s.key, s.gen)]
	switch {
	case isolated == "" && opened == "":
		s.say("this agent holds no isolation of the workload to release")
		return mrRecord{}, false, nil
	case isolated == "":
		return s.settleOpen(ctx, opened)
	}
	m, ok := parseRecord(isolated)
	if !ok {
		s.say("the record " + recName(recIsolated, s.key, s.gen) + " is not trusted: it holds no head commit")
	}
	return m, ok, nil
}

// settleOpen handles an isolation merge request that the agent opened and did
// not record as merged. A merge request that is still open is closed, so
// nobody merges it after the release. A merge request that merged is
// recorded, and the release goes on with it.
func (s step) settleOpen(ctx context.Context, opened string) (m mrRecord, cont bool, err error) {
	m, ok := parseRecord(opened)
	if !ok {
		s.say("the record " + recName(recIsolationOpened, s.key, s.gen) + " is not trusted: it holds no head commit")
		return mrRecord{}, false, nil
	}
	mr, ok, err := s.read(ctx, m, s.p.Repo.Isolate(s.inc, s.w, s.gen))
	if err != nil || !ok {
		return mrRecord{}, false, err
	}
	switch mr.State {
	case StateMerged:
		if err := s.write(ctx, recName(recIsolated, s.key, s.gen), m.String()); err != nil {
			return mrRecord{}, false, err
		}
		return m, true, nil
	case StateOpen:
		call, err := s.p.Host.Close(ctx, m.Ref)
		if err != nil {
			return mrRecord{}, false, fmt.Errorf("isolate: %w", err)
		}
		if s.outcome("close the open isolation merge request "+respond.Clean(m.Ref), call) {
			return mrRecord{}, false, nil
		}
		s.say("closed the isolation merge request " + respond.Clean(m.Ref) + " that never merged")
	default:
		s.say("the isolation merge request " + respond.Clean(m.Ref) + " is " + strconv.Quote(respond.Clean(mr.State)) +
			" and not merged")
	}
	return mrRecord{}, false, s.write(ctx, recName(recReleased, s.key, s.gen), m.String())
}

func (s step) say(line string) { s.sum.Lines = append(s.sum.Lines, line) }

func (s step) write(ctx context.Context, name, value string) error {
	if err := s.p.Recorder.RecordValue(ctx, s.inc, name, value); err != nil {
		return fmt.Errorf("isolate: record %s: %w", name, err)
	}
	return nil
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

// open opens the merge request and records its reference and head commit at
// once, so the next dispatch merges it and opens no second one.
func (s step) open(ctx context.Context, c Change, record string) (mrRecord, error) {
	ref, sha, call, err := s.p.Host.Open(ctx, c)
	if err != nil {
		return mrRecord{}, fmt.Errorf("isolate: %w", err)
	}
	if s.outcome("open the merge request on branch "+respond.Clean(c.Branch), call) {
		return mrRecord{}, nil
	}
	if ref == "" {
		s.say("open the merge request: the host returned no reference")
		return mrRecord{}, nil
	}
	m := mrRecord{Ref: ref, SHA: sha}
	s.say("opened the merge request " + respond.Clean(ref) + " at the commit " + short(sha))
	return m, s.write(ctx, record, m.String())
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// read reads one merge request and refuses it unless it is in the configured
// project, on the expected branch, and at the head commit that the agent
// recorded. A record names the reference, and any writer of the graph can
// write a record. The host is the fact.
func (s step) read(ctx context.Context, m mrRecord, want Change) (MR, bool, error) {
	if problem := s.p.Repo.refProblem(m.Ref); problem != "" {
		s.say("the merge request " + respond.Clean(m.Ref) + " is not trusted: " + problem)
		return MR{}, false, nil
	}
	mr, call, err := s.p.Host.State(ctx, m.Ref)
	if err != nil {
		return MR{}, false, fmt.Errorf("isolate: %w", err)
	}
	if s.outcome("read the state of "+respond.Clean(m.Ref), call) {
		return MR{}, false, nil
	}
	if mr.SourceBranch != want.Branch {
		s.say("the merge request " + respond.Clean(m.Ref) + " is on the branch " +
			strconv.Quote(respond.Clean(mr.SourceBranch)) + " and the expected branch is " +
			strconv.Quote(want.Branch) + ": it is not trusted")
		return MR{}, false, nil
	}
	if mr.HeadSHA != m.SHA {
		s.say("the head of " + respond.Clean(m.Ref) + " is the commit " + short(respond.Clean(mr.HeadSHA)) +
			" and the agent opened it at " + short(m.SHA) + ": a commit was added after the agent opened it, " +
			"so it is not trusted")
		return MR{}, false, nil
	}
	if problem := filesProblem(mr, want); problem != "" {
		s.say("the merge request " + respond.Clean(m.Ref) + " is not trusted: " + problem)
		return MR{}, false, nil
	}
	return mr, true, nil
}

// filesProblem says why the files that the merge request changes are not the
// files of the expected change, or returns "". The branch name is easy to
// guess, so a person can make the branch first and the commit of the agent
// lands on top of theirs. The head commit then names that history too. So
// the agent compares the files, and it merges only an exact match. The host
// returns no content. It returns the git blob id of each file after the
// change, and the agent computes the blob id of each file that it expects.
func filesProblem(mr MR, want Change) string {
	switch {
	case mr.FilesError != "":
		return "the host could not list the changed files: " + respond.Clean(mr.FilesError)
	case !mr.FilesKnown:
		return "the host does not return the files that the merge request changes"
	case mr.Truncated:
		return "the host cut the list of changed files, so the agent cannot compare it"
	case !shaForm.MatchString(mr.HeadSHA):
		return "the host returned a head commit that is not 40 or 64 hexadecimal characters"
	case len(mr.Files) != len(want.Files):
		return fmt.Sprintf("it changes %d files and the expected change has %d", len(mr.Files), len(want.Files))
	}
	got := map[string]ChangedFile{}
	for _, f := range mr.Files {
		if f.Change == "renamed" || f.PreviousPath != "" {
			return "it renames the file " + respond.Clean(f.Path)
		}
		if f.Change == "mode_changed" {
			return "it changes the mode or the type of the file " + respond.Clean(f.Path)
		}
		got[f.Path] = f
	}
	for _, w := range want.Files {
		g, ok := got[w.Path]
		switch {
		case !ok:
			return "it does not change the expected file " + respond.Clean(w.Path)
		case w.Delete && (g.Change != "deleted" || g.BlobSHA != ""):
			return "it changes the file " + respond.Clean(w.Path) + " in another way than a delete"
		case !w.Delete && ((g.Change != "added" && g.Change != "modified") ||
			g.BlobSHA != gitBlobSHA(mr.HeadSHA, w.Content)):
			return "it changes the file " + respond.Clean(w.Path) + " to a content that the agent did not write"
		case !w.Delete && g.Mode != "" && g.Mode != regularMode:
			return "it writes the file " + respond.Clean(w.Path) + " with the mode " + respond.Clean(g.Mode) +
				" and the agent wrote " + regularMode
		}
	}
	return ""
}

// verify reports whether the host shows the merge request merged.
func (s step) verify(ctx context.Context, m mrRecord, want Change) (bool, error) {
	mr, ok, err := s.read(ctx, m, want)
	if err != nil || !ok {
		return false, err
	}
	if mr.State != StateMerged {
		s.say("the host shows " + respond.Clean(m.Ref) + " in the state " + strconv.Quote(respond.Clean(mr.State)) +
			" and not merged")
		return false, nil
	}
	s.say(respond.Clean(m.Ref) + " is merged")
	return true, nil
}

// drive brings the merge request to the merged state. It reads the state
// before it merges, so a merge request that merged already gets no second
// merge call, which the host refuses. The merge call carries the recorded
// head commit, so the host refuses the merge when a commit came after the
// read. It reads the state again after the merge call.
func (s step) drive(ctx context.Context, m mrRecord, want Change) (bool, error) {
	mr, ok, err := s.read(ctx, m, want)
	if err != nil || !ok {
		return false, err
	}
	switch mr.State {
	case StateMerged:
		s.say(respond.Clean(m.Ref) + " is merged already: no merge call")
		return true, nil
	case StateOpen:
	default:
		s.say("the host shows " + respond.Clean(m.Ref) + " in the state " + strconv.Quote(respond.Clean(mr.State)) +
			": a person must decide")
		return false, nil
	}
	merged, call, err := s.p.Host.Merge(ctx, m.Ref, m.SHA)
	if err != nil {
		return false, fmt.Errorf("isolate: %w", err)
	}
	if s.outcome("merge "+respond.Clean(m.Ref), call) {
		return false, nil
	}
	if !merged {
		s.say("the host did not merge " + respond.Clean(m.Ref) + " at the commit " + short(m.SHA) +
			": the checks are not done, a rule blocks it, or the head moved. The next dispatch reads it again")
		return false, nil
	}
	return s.verify(ctx, m, want)
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
