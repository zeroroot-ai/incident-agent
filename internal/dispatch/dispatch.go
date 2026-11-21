// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package dispatch reads the contract a sandboxed agent is launched with.
//
// This agent is dispatched, not enrolled (ADR-0116). Gibson launches the image
// once per mission run inside an ephemeral setec sandbox, hands it a
// short-lived capability grant scoped to that tenant and run, and reaps the
// sandbox when it exits. Nothing survives between runs: no enrolled identity,
// no bootstrap token, no standing cross-tenant credential. A containment pass that
// runs for one incident should hold nothing in between, which is exactly what
// this buys.
//
// The variable names below are the launch contract. Gibson sets them when it
// launches the image, and it is the only writer of them. Renaming one here
// would not rename it there; it would only make this agent silently receive
// nothing.
package dispatch

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/zeroroot-ai/sdk/agent"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/serve"
	"google.golang.org/protobuf/encoding/protojson"
)

// The launcher's environment contract. README.md lists the same seven names.
const (
	// EnvGrant carries the per-dispatch capability-grant JWT. It authenticates
	// every callback this run makes and expires with the run.
	EnvGrant = "GIBSON_CG_JWT"
	// EnvCallbackEndpoint is the HarnessCallbackService address to dial back.
	EnvCallbackEndpoint = "GIBSON_CALLBACK_ENDPOINT"
	// EnvTaskB64 carries the base64 protojson of the gibson.types.v1.Task
	// this run was dispatched with.
	EnvTaskB64 = "GIBSON_AGENT_TASK_B64"
	// EnvModel is the model resolved for the tenant at dispatch time.
	EnvModel = "GIBSON_MODEL"
	// EnvMissionID, EnvMissionRunID and EnvAgentRunID scope the run for
	// provenance on everything it writes.
	EnvMissionID    = "GIBSON_MISSION_ID"
	EnvMissionRunID = "GIBSON_MISSION_RUN_ID"
	EnvAgentRunID   = "GIBSON_AGENT_RUN_ID"
)

// Dispatch is one launch: who we are allowed to be, where to call back, and
// what we were asked to do.
type Dispatch struct {
	// Grant is the capability-grant JWT for this run.
	Grant string
	// CallbackEndpoint is the HarnessCallbackService address.
	CallbackEndpoint string
	// Task is the decoded task, with its context map already unwrapped from
	// TypedValue.
	Task agent.Task
	// Model is the model resolved at dispatch, empty when gibson left the
	// choice to the slot.
	Model string
	// MissionID, MissionRunID and AgentRunID scope this run.
	MissionID    string
	MissionRunID string
	AgentRunID   string
}

// Getenv is the environment reader, injectable so the tests never touch the
// process environment.
type Getenv func(string) string

// FromEnv reads the launch contract from the process environment.
func FromEnv() (Dispatch, error) { return From(os.Getenv) }

// From reads the launch contract from getenv.
//
// The three required variables fail loudly and separately. A missing grant in
// particular must never fall through to an unauthenticated dial: gibson would
// reject it, but the failure would surface as a callback error deep in a pass
// rather than as "this run was launched without a credential", and the two
// read nothing alike when someone is debugging at 2am.
func From(getenv Getenv) (Dispatch, error) {
	if getenv == nil {
		return Dispatch{}, errors.New("dispatch: no environment reader")
	}

	d := Dispatch{
		Grant:            strings.TrimSpace(getenv(EnvGrant)),
		CallbackEndpoint: strings.TrimSpace(getenv(EnvCallbackEndpoint)),
		Model:            strings.TrimSpace(getenv(EnvModel)),
		MissionID:        strings.TrimSpace(getenv(EnvMissionID)),
		MissionRunID:     strings.TrimSpace(getenv(EnvMissionRunID)),
		AgentRunID:       strings.TrimSpace(getenv(EnvAgentRunID)),
	}

	if d.Grant == "" {
		return Dispatch{}, fmt.Errorf("dispatch: %s is not set: this agent is launched per dispatch and cannot run without its capability grant", EnvGrant)
	}
	if d.CallbackEndpoint == "" {
		return Dispatch{}, fmt.Errorf("dispatch: %s is not set: there is nowhere to report to", EnvCallbackEndpoint)
	}

	raw := strings.TrimSpace(getenv(EnvTaskB64))
	if raw == "" {
		return Dispatch{}, fmt.Errorf("dispatch: %s is not set: there is no task to run", EnvTaskB64)
	}
	task, err := DecodeTask(raw)
	if err != nil {
		return Dispatch{}, err
	}
	d.Task = task

	return d, nil
}

// DecodeTask turns the base64 protojson gibson hands us into an agent.Task.
//
// The context and metadata maps are map<string, gibson.common.v1.TypedValue>
// on the wire, so they arrive shaped {"stringValue":"…"} rather than as plain
// strings. Reading them as strings drops every key silently — the agent starts,
// finds no incident to contain, and reports a clean pass over nothing. The
// SDK's ProtoToTask unwraps them, which is why the decode goes through proto
// rather than straight into a hand-rolled struct.
func DecodeTask(b64 string) (agent.Task, error) {
	rawJSON, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return agent.Task{}, fmt.Errorf("dispatch: %s is not valid base64: %w", EnvTaskB64, err)
	}

	var pt typespb.Task
	// DiscardUnknown: gibson may add fields to Task before this agent is
	// rebuilt, and a new field it does not read is not a reason to refuse to
	// run.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(rawJSON, &pt); err != nil {
		return agent.Task{}, fmt.Errorf("dispatch: %s is not a valid gibson.types.v1.Task: %w", EnvTaskB64, err)
	}

	return serve.ProtoToTask(&pt), nil
}
