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
	recIsolated        = "ir_isolated_"
	recReleaseOpened   = "ir_release_opened_"
	recReleased        = "ir_isolation_released_"
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
	// Isolated is true when the host shows the isolation merged.
	Isolated bool
	// Released is true when the host shows the release merged.
	Released bool
	// Held is why a release released nothing.
	Held string
}

func (p Pass) check(release bool) error {
	if p.Reader == nil || p.Host == nil || p.Recorder == nil {
		return errors.New("isolate: a pass needs a reader, a host and a recorder")
	}
	if release && p.Causes == nil {
		return errors.New("isolate: a release pass needs a cause finder")
	}
	return p.Repo.Check()
}

// generation returns the generation to work on. It is the last generation
// that holds an opened or an isolated record, unless that generation is
// released. Then it is the next one. A fresh containment is generation 1.
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
	case inc.HasRecord(recName(recReleased, key, gen)):
		return gen + 1
	default:
		return gen
	}
}

// Isolate isolates the workload with a merged merge request. It skips each
// step that the records and the host show as done.
func (p Pass) Isolate(ctx context.Context, key string, w Workload) (Summary, error) {
	if err := p.check(false); err != nil {
		return Summary{}, err
	}
	inc, err := p.Reader.Incident(ctx, key)
	if err != nil {
		return Summary{Incident: key}, fmt.Errorf("isolate: read incident %s: %w", key, err)
	}
	ck := Key(key, w)
	sum := Summary{Incident: key, Key: ck}
	gen := generation(inc, ck)
	run := step{p: p, inc: key, key: ck, gen: gen, sum: &sum}

	ref := inc.Records[recName(recIsolationOpened, ck, gen)]
	if done := inc.Records[recName(recIsolated, ck, gen)]; done != "" {
		merged, err := run.confirm(ctx, done)
		if err != nil {
			return sum, err
		}
		sum.Isolated = merged
		if merged {
			run.say("the isolation is merged already: no call to open or merge")
		}
		return sum, nil
	}
	if ref == "" {
		ref, err = run.open(ctx, Isolate(p.Repo.Dir, key, w, gen), recName(recIsolationOpened, ck, gen))
		if err != nil || ref == "" {
			return sum, err
		}
	} else if problem := refProblem(ref); problem != "" {
		run.say("the record " + recName(recIsolationOpened, ck, gen) + " is not trusted: " + problem)
		return sum, nil
	}
	merged, err := run.merge(ctx, ref)
	if err != nil || !merged {
		return sum, err
	}
	sum.Isolated = true
	return sum, run.write(ctx, recName(recIsolated, ck, gen), ref)
}

// Release removes the isolation with a second merged merge request, after the
// cause that this agent raised is verified.
func (p Pass) Release(ctx context.Context, key string, w Workload) (Summary, error) {
	if err := p.check(true); err != nil {
		return Summary{}, err
	}
	inc, err := p.Reader.Incident(ctx, key)
	if err != nil {
		return Summary{Incident: key}, fmt.Errorf("release: read incident %s: %w", key, err)
	}
	ck := Key(key, w)
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
	isolated := inc.Records[recName(recIsolated, ck, gen)]
	if isolated == "" || inc.HasRecord(recName(recReleased, ck, gen)) {
		run.say("this agent holds no merged isolation of the workload to release")
		return sum, nil
	}
	merged, err := run.confirm(ctx, isolated)
	if err != nil {
		return sum, err
	}
	if !merged {
		run.say("the host does not show the isolation as merged, so there is nothing to release")
		return sum, nil
	}
	ref := inc.Records[recName(recReleaseOpened, ck, gen)]
	if ref == "" {
		ref, err = run.open(ctx, Release(p.Repo.Dir, key, w, gen), recName(recReleaseOpened, ck, gen))
		if err != nil || ref == "" {
			return sum, err
		}
	} else if problem := refProblem(ref); problem != "" {
		run.say("the record " + recName(recReleaseOpened, ck, gen) + " is not trusted: " + problem)
		return sum, nil
	}
	merged, err = run.merge(ctx, ref)
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

// merge merges the merge request and reads its state back from the host. Only
// the state that the host reports counts as merged.
func (s step) merge(ctx context.Context, ref string) (bool, error) {
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
	return s.confirm(ctx, ref)
}

// confirm reads the state of the merge request on the host.
func (s step) confirm(ctx context.Context, ref string) (bool, error) {
	state, call, err := s.p.Host.State(ctx, ref)
	if err != nil {
		return false, fmt.Errorf("isolate: %w", err)
	}
	if s.outcome("read the state of "+respond.Clean(ref), call) {
		return false, nil
	}
	if state != StateMerged {
		s.say("the host shows " + respond.Clean(ref) + " in the state " + strconv.Quote(respond.Clean(state)) +
			" and not merged")
		return false, nil
	}
	s.say(respond.Clean(ref) + " is merged")
	return true, nil
}
