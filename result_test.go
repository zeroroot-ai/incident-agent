// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/zeroroot-ai/incident-agent/internal/dispatch"
	"github.com/zeroroot-ai/sdk/agent"
)

// decodeLine checks that out holds exactly one line and decodes it.
func decodeLine(t *testing.T, out string) map[string]any {
	t.Helper()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("result line %q does not end with a newline", out)
	}
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("want one line, got %d: %q", n, out)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result line is not one JSON object: %v: %q", err, out)
	}
	if got["type"] != "result" {
		t.Errorf("type = %v, want result", got["type"])
	}
	return got
}

// A pass that succeeds writes a success line with its report as the output.
func TestWriteResult_Success(t *testing.T) {
	var buf bytes.Buffer
	res := agent.Result{
		Status:   a2a.TaskStateCompleted,
		Output:   "app-1: 3 priorities decided, 3 written",
		Findings: []string{"f-1"},
		Metadata: map[string]any{"written": 3},
	}
	if err := writeResult(&buf, res, nil); err != nil {
		t.Fatal(err)
	}
	got := decodeLine(t, buf.String())
	if got["success"] != true {
		t.Errorf("success = %v, want true", got["success"])
	}
	if got["output"] != res.Output {
		t.Errorf("output = %v, want %q", got["output"], res.Output)
	}
	if ids, _ := got["finding_ids"].([]any); len(ids) != 1 || ids[0] != "f-1" {
		t.Errorf("finding_ids = %v, want [f-1]", got["finding_ids"])
	}
	if md, _ := got["metadata"].(map[string]any); md["written"] != "3" {
		t.Errorf("metadata = %v, want written=3 as a string", got["metadata"])
	}
}

// A pass that fails writes a failure line with the reason as the output.
func TestWriteResult_FailureCarriesTheReason(t *testing.T) {
	var buf bytes.Buffer
	runErr := errors.New("task t-1: read findings: permission denied")
	if err := writeResult(&buf, agent.Result{Status: a2a.TaskStateFailed}, runErr); err != nil {
		t.Fatal(err)
	}
	got := decodeLine(t, buf.String())
	if got["success"] != false {
		t.Errorf("success = %v, want false", got["success"])
	}
	if got["output"] != runErr.Error() {
		t.Errorf("output = %v, want %q", got["output"], runErr.Error())
	}
	if _, ok := got["finding_ids"]; ok {
		t.Errorf("finding_ids is present on a failure with none: %v", got["finding_ids"])
	}
}

// A result that is not a success fails even when run returned no error.
// A success line for it would report a containment that did not happen.
func TestWriteResult_StatusThatIsNotSuccessFails(t *testing.T) {
	var buf bytes.Buffer
	if err := writeResult(&buf, agent.Result{Status: a2a.TaskStateFailed}, nil); err != nil {
		t.Fatal(err)
	}
	got := decodeLine(t, buf.String())
	if got["success"] != false {
		t.Errorf("success = %v, want false", got["success"])
	}
	if out, _ := got["output"].(string); out == "" {
		t.Error("a failure line has no reason in output")
	}
}

// A run with no launch contract still has a result line to write: run
// returns an empty result and an error, and the line reports the error.
func TestRun_WithoutALaunchContractWritesAFailureLine(t *testing.T) {
	t.Setenv(dispatch.EnvGrant, "")
	res, err := run(t.Context())
	if err == nil {
		t.Fatal("run with no grant: want an error, got none")
	}
	var buf bytes.Buffer
	if werr := writeResult(&buf, res, err); werr != nil {
		t.Fatal(werr)
	}
	got := decodeLine(t, buf.String())
	if got["success"] != false || got["output"] != err.Error() {
		t.Errorf("line = %v, want success=false and output=%q", got, err.Error())
	}
}
