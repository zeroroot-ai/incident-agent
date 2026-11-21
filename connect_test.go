// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/incident-agent/internal/dispatch"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// runIDServer records the mission run ID of the callbacks that it gets.
type runIDServer struct {
	harnesspb.UnimplementedHarnessCallbackServiceServer
	runIDs chan string
}

func (s *runIDServer) GetTaxonomySchema(_ context.Context, req *harnesspb.GetTaxonomySchemaRequest) (*harnesspb.GetTaxonomySchemaResponse, error) {
	select {
	case s.runIDs <- req.GetContext().GetMissionRunId():
	default:
	}
	return &harnesspb.GetTaxonomySchemaResponse{}, nil
}

// A sandboxed run gets GIBSON_MISSION_RUN_ID from the launcher. The callbacks
// of the run carry it, so the daemon can tell the run from another run of the
// same mission record (gibson#1235).
func TestConnect_CallbacksCarryTheMissionRunID(t *testing.T) {
	t.Setenv(dispatch.EnvMissionRunID, "run-from-launch")

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	rec := &runIDServer{runIDs: make(chan string, 4)}
	harnesspb.RegisterHarnessCallbackServiceServer(srv, rec)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, closeFn, err := connect(ctx, dispatch.Dispatch{CallbackEndpoint: lis.Addr().String(), Grant: "g", MissionID: "m-1"})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer closeFn()

	select {
	case got := <-rec.runIDs:
		if got != "run-from-launch" {
			t.Fatalf("callback mission_run_id = %q, want run-from-launch", got)
		}
	case <-ctx.Done():
		t.Fatal("no callback reached the server")
	}
}
