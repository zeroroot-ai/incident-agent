// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dispatch_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/zeroroot-ai/incident-agent/internal/dispatch"
)

// taskJSON is what gibson actually puts on the wire: context is a
// map<string, TypedValue>, so every value is an object naming its type, not a
// bare string.
const taskJSON = `{
  "id": "task-1",
  "goal": "contain the incident",
  "context": {
    "incident": {"stringValue": "inc-1"},
    "ir.task": {"stringValue": "contain"}
  },
  "metadata": {
    "origin": {"stringValue": "scan"}
  }
}`

func env(m map[string]string) dispatch.Getenv {
	return func(k string) string { return m[k] }
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func complete() map[string]string {
	return map[string]string{
		dispatch.EnvGrant:            "grant-jwt",
		dispatch.EnvCallbackEndpoint: "gibson:50001",
		dispatch.EnvTaskB64:          b64(taskJSON),
		dispatch.EnvModel:            "claude-sonnet-4-5",
		dispatch.EnvMissionID:        "m-1",
		dispatch.EnvMissionRunID:     "mr-1",
		dispatch.EnvAgentRunID:       "ar-1",
	}
}

func TestFrom_ReadsTheWholeContract(t *testing.T) {
	d, err := dispatch.From(env(complete()))
	if err != nil {
		t.Fatalf("From: %v", err)
	}

	if d.Grant != "grant-jwt" {
		t.Errorf("Grant = %q, want grant-jwt", d.Grant)
	}
	if d.CallbackEndpoint != "gibson:50001" {
		t.Errorf("CallbackEndpoint = %q, want gibson:50001", d.CallbackEndpoint)
	}
	if d.Model != "claude-sonnet-4-5" {
		t.Errorf("Model = %q, want claude-sonnet-4-5", d.Model)
	}
	if d.MissionID != "m-1" {
		t.Errorf("MissionID = %q, want m-1", d.MissionID)
	}
	if d.MissionRunID != "mr-1" {
		t.Errorf("MissionRunID = %q, want mr-1", d.MissionRunID)
	}
	if d.AgentRunID != "ar-1" {
		t.Errorf("AgentRunID = %q, want ar-1", d.AgentRunID)
	}
	if d.Task.ID != "task-1" {
		t.Errorf("Task.ID = %q, want task-1", d.Task.ID)
	}
	if d.Task.Goal != "contain the incident" {
		t.Errorf("Task.Goal = %q, want the goal", d.Task.Goal)
	}
}

// The trap this agent must not fall into: context values arrive wrapped as
// TypedValue. Reading them as plain strings yields an empty map, the pass finds
// no incident, and a run over nothing reports as a clean pass.
func TestDecodeTask_UnwrapsTypedValueContext(t *testing.T) {
	task, err := dispatch.DecodeTask(b64(taskJSON))
	if err != nil {
		t.Fatalf("DecodeTask: %v", err)
	}

	if len(task.Context) != 2 {
		t.Fatalf("Context has %d keys, want 2 — a TypedValue map read as strings drops every key", len(task.Context))
	}
	app, ok := task.Context["incident"]
	if !ok {
		t.Fatal(`Context is missing "incident"`)
	}
	if s, ok := app.(string); !ok || s != "inc-1" {
		t.Errorf("Context[incident] = %#v, want the string inc-1", app)
	}
	if got := task.Metadata["origin"]; got != "scan" {
		t.Errorf("Metadata[origin] = %#v, want scan", got)
	}
}

func TestFrom_RequiredVariablesFailLoudlyAndSeparately(t *testing.T) {
	cases := []struct {
		name    string
		unset   string
		wantSub string
	}{
		{"no grant", dispatch.EnvGrant, dispatch.EnvGrant},
		{"no callback endpoint", dispatch.EnvCallbackEndpoint, dispatch.EnvCallbackEndpoint},
		{"no task", dispatch.EnvTaskB64, dispatch.EnvTaskB64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := complete()
			delete(m, tc.unset)

			_, err := dispatch.From(env(m))
			if err == nil {
				t.Fatalf("From with no %s: want an error, got none", tc.unset)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not name %s", err, tc.wantSub)
			}
		})
	}
}

// A grant of only whitespace is absent, not present. Trimming to empty and
// then dialing would send a blank credential and surface as a callback failure
// deep inside the pass instead of as a launch failure.
func TestFrom_BlankGrantIsAbsent(t *testing.T) {
	m := complete()
	m[dispatch.EnvGrant] = "   "

	_, err := dispatch.From(env(m))
	if err == nil {
		t.Fatal("From with a whitespace grant: want an error, got none")
	}
	if !strings.Contains(err.Error(), dispatch.EnvGrant) {
		t.Errorf("error %q does not name the grant variable", err)
	}
}

func TestDecodeTask_RefusesMalformedInput(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"not base64", "!!!not base64!!!"},
		{"base64 of not json", b64("this is not json")},
		{"base64 of a json array", b64(`["not","a","task"]`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dispatch.DecodeTask(tc.in); err == nil {
				t.Fatalf("DecodeTask(%s): want an error, got none", tc.name)
			}
		})
	}
}

// A field gibson adds to Task before this agent is rebuilt is not a reason to
// refuse the run.
func TestDecodeTask_ToleratesUnknownFields(t *testing.T) {
	task, err := dispatch.DecodeTask(b64(`{"id":"t","goal":"g","somethingNew":42}`))
	if err != nil {
		t.Fatalf("DecodeTask with an unknown field: %v", err)
	}
	if task.ID != "t" {
		t.Errorf("Task.ID = %q, want t", task.ID)
	}
}

func TestFrom_NoEnvironmentReader(t *testing.T) {
	if _, err := dispatch.From(nil); err == nil {
		t.Fatal("From(nil): want an error, got none")
	}
}
