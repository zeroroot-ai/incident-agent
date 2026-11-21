// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroroot-ai/incident-agent/internal/dispatch"
)

// A launch with no contract must fail, not proceed.
//
// run's error is the process exit status, and the exit status is the only
// thing gibson learns about this run. A binary that returned nil here would
// exit 0 having contained nothing, and the mission node would record a clean
// pass over an incident nobody looked at.
func TestRun_WithoutALaunchContractFails(t *testing.T) {
	for _, k := range []string{
		dispatch.EnvGrant,
		dispatch.EnvCallbackEndpoint,
		dispatch.EnvTaskB64,
		dispatch.EnvModel,
		dispatch.EnvMissionID,
		dispatch.EnvMissionRunID,
		dispatch.EnvAgentRunID,
	} {
		t.Setenv(k, "")
	}

	_, err := run(context.Background())
	if err == nil {
		t.Fatal("run with no launch contract: want an error, got none")
	}
	if !strings.Contains(err.Error(), dispatch.EnvGrant) {
		t.Errorf("error %q does not name the missing grant", err)
	}
}

// A run carrying a task but no credential must fail before it dials, and say
// so. Reaching the callback service unauthenticated would surface as a
// transport error from inside the pass rather than as "this run was launched
// without a grant".
func TestRun_WithoutAGrantFailsBeforeDialing(t *testing.T) {
	t.Setenv(dispatch.EnvGrant, "")
	t.Setenv(dispatch.EnvCallbackEndpoint, "127.0.0.1:1")
	t.Setenv(dispatch.EnvTaskB64, "e30=") // {}
	t.Setenv(dispatch.EnvMissionID, "m-1")

	_, err := run(context.Background())
	if err == nil {
		t.Fatal("run without a grant: want an error, got none")
	}
	if !strings.Contains(err.Error(), dispatch.EnvGrant) {
		t.Errorf("error %q does not name the grant variable", err)
	}
	if strings.Contains(err.Error(), "dial") {
		t.Errorf("error %q mentions dialing: the run must fail before it opens a connection", err)
	}
}
