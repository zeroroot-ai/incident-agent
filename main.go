// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command incident-agent is a Gibson agent for a blue team. It contains one
// incident that the security tools of the buyer detected, inside the grant
// that the security team of the buyer gave, and it sends the cause to the fix
// loop. It runs no attack.
//
// One dispatch is one task on one incident: contain the targets, raise the
// finding of the cause, or release the containment after the cause is
// verified. The grant decides each response action. A tool that the manifest
// marks waits for a person in the approval queue.
//
// The agent never states that an incident is resolved. The daemon sets the
// status of the finding of the cause, and the incident report of the daemon
// states what happened.
//
// # How it runs
//
// It is dispatched, not enrolled (ADR-0116). Gibson launches this image once
// per mission run inside an ephemeral setec sandbox, hands it a capability
// grant scoped to that tenant and run, and reaps the sandbox when the process
// exits. The binary reads its task from the environment, runs one task, and
// returns. It never polls, never registers, and holds no identity between
// runs.
//
// See AGENTS.md for the Gibson agent contract this binary implements.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/zeroroot-ai/incident-agent/internal/dispatch"
	"github.com/zeroroot-ai/incident-agent/internal/pass"
	"github.com/zeroroot-ai/incident-agent/internal/read"
	"github.com/zeroroot-ai/sdk/agent"
	"github.com/zeroroot-ai/sdk/serve"
	"github.com/zeroroot-ai/sdk/types"
)

// Version is the agent version this binary reports. It is set at build time
// from the release tag; "dev" is what a local build reports.
//
// It is a var set by -ldflags rather than a const, because a hardcoded version
// here would drift from the release-please tag the moment either moved, and a
// component that misreports its own version is worse than one that says "dev".
var Version = "dev"

func main() {
	res, err := run(context.Background())
	if err != nil {
		slog.Error("incident-agent", "version", Version, "err", err)
	}
	// The result line is written on success and on failure. The launcher
	// reads it for the output of the mission node, and the exit status
	// still says whether the run failed.
	if werr := writeResult(os.Stdout, res, err); werr != nil {
		slog.Error("incident-agent", "version", Version, "err", werr)
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}

// run performs one dispatched pass and returns its result.
//
// Every failure returns an error rather than logging and continuing. Gibson
// learns about this run from the exit status and the result line, so a task
// that could not read, could not act, or could not write must exit
// non-zero: exiting 0 after failing would report a clean containment of an
// incident nobody looked at.
func run(ctx context.Context) (agent.Result, error) {
	d, err := dispatch.FromEnv()
	if err != nil {
		return agent.Result{}, fmt.Errorf("read the launch contract: %w", err)
	}

	slog.Info("incident dispatched",
		"version", Version,
		"task", d.Task.ID,
		"mission", d.MissionID,
		"mission_run", d.MissionRunID,
		"agent_run", d.AgentRunID,
		"model", d.Model,
	)

	harness, closeHarness, err := connect(ctx, d)
	if err != nil {
		return agent.Result{}, err
	}
	defer closeHarness()

	res, err := pass.Run(ctx, harness, read.Daemon{}, d.Task)
	if err != nil {
		return res, fmt.Errorf("task %s: %w", d.Task.ID, err)
	}

	slog.Info("incident task complete", "task", d.Task.ID, "output", res.Output)
	return res, nil
}

// connect dials the harness callback service with this run's grant.
//
// The grant is the whole credential: there is no bootstrap token and no
// enrolled identity to fall back on, which is what keeps a sandboxed run
// unable to act outside the tenant and run it was launched for.
func connect(ctx context.Context, d dispatch.Dispatch) (*serve.CallbackHarness, func(), error) {
	client, err := serve.NewCallbackClient(d.CallbackEndpoint, serve.WithCallbackToken(d.Grant))
	if err != nil {
		return nil, nil, fmt.Errorf("callback client: %w", err)
	}
	if err := client.Connect(ctx); err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", d.CallbackEndpoint, err)
	}

	harness := serve.NewCallbackHarness(client,
		serve.WithCallbackMission(types.MissionContext{
			ID:           d.MissionID,
			CurrentAgent: "incident-agent",
		}),
	)

	return harness, func() {
		if err := client.Close(); err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("close callback client", "err", err)
		}
	}, nil
}
