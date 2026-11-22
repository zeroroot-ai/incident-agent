// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pass_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/pass"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
	"github.com/zeroroot-ai/sdk/agent"
	"github.com/zeroroot-ai/sdk/finding"
	"github.com/zeroroot-ai/sdk/openresponses"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// gitPlatform is a Platform with a mock Git host behind invoke_tool. It
// records the properties that the agent writes on the Incident node.
type gitPlatform struct {
	calls   []string
	records map[string]string
}

func (g *gitPlatform) CallToolProto(
	_ context.Context, _ string, request, response proto.Message, _ ...agent.ToolCallOption,
) error {
	in := request.(*structpb.Struct).AsMap() //nolint:forcetypeassert // the test controls the request type
	id, _ := in["id"].(string)
	g.calls = append(g.calls, id)
	var result map[string]any
	switch id {
	case "mcp:gitlab-fixloop:open_merge_request":
		result = map[string]any{"merge_request": "acme/manifests!4"}
	case "mcp:gitlab-fixloop:merge_merge_request":
		result = map[string]any{"state": "merged", "merged": true}
	case "mcp:gitlab-fixloop:merge_request_state":
		result = map[string]any{"state": "merged"}
	default:
		return errors.New("unknown tool " + id)
	}
	out, err := structpb.NewStruct(map[string]any{"result": result})
	if err != nil {
		return err //nolint:wrapcheck // a test helper
	}
	proto.Merge(response, out)
	return nil
}

func (*gitPlatform) SubmitFinding(context.Context, *finding.Finding) error { return nil }

func (*gitPlatform) GetFindings(context.Context, finding.Filter) ([]*finding.Finding, error) {
	return nil, nil
}

func (g *gitPlatform) Observe(_ context.Context, obs agent.Observation) error {
	if o, ok := obs.(agent.LifecycleEntityObservation); ok {
		for k, v := range o.Properties {
			g.records[k] = v
		}
	}
	return nil
}

func (*gitPlatform) Model(context.Context, string) (*openresponses.Client, error) { return nil, nil }

type liveReader struct{ g *gitPlatform }

func (r liveReader) Incident(_ context.Context, key string) (incident.Incident, error) {
	return incident.Incident{Key: key, Records: r.g.records}, nil
}

type noCalls struct{}

func (noCalls) CheckCall(context.Context, string, respond.Action) error { return nil }

func workloadTask(task string) agent.Task {
	return agent.Task{Context: map[string]any{
		pass.ContextKeyIncident: "incident-7", pass.ContextKeyTask: task,
		pass.ContextKeyNamespace: "payments", pass.ContextKeyLabels: "app=ledger",
		pass.ContextKeyConnector: "gitlab-fixloop", pass.ContextKeyProject: "acme/manifests",
		pass.ContextKeyBaseBranch: "main",
	}}
}

func TestRun_IsolateOpensMergesAndRecords(t *testing.T) {
	g := &gitPlatform{records: map[string]string{}}
	res, err := pass.Run(context.Background(), g, liveReader{g}, noCalls{}, workloadTask(pass.TaskIsolate))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != a2a.TaskStateCompleted || res.Metadata["isolated"] != true {
		t.Fatalf("status = %v, metadata = %v, output = %s", res.Status, res.Metadata, res.Output)
	}
	if len(g.calls) != 3 || !strings.HasPrefix(g.calls[0], "mcp:gitlab-fixloop:") {
		t.Fatalf("calls = %v", g.calls)
	}
	found := false
	for name := range g.records {
		found = found || strings.HasPrefix(name, "ir_isolated_")
	}
	if !found {
		t.Fatalf("no isolated record: %v", g.records)
	}
	if strings.Contains(strings.ToLower(fmt.Sprint(res.Output)), "resolved") {
		t.Fatalf("the report says that the incident is resolved: %s", res.Output)
	}
}

func TestRun_WorkloadTaskRefusesBadContext(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"no namespace":      func(m map[string]any) { delete(m, pass.ContextKeyNamespace) },
		"system namespace":  func(m map[string]any) { m[pass.ContextKeyNamespace] = "kube-system" },
		"no labels":         func(m map[string]any) { m[pass.ContextKeyLabels] = "" },
		"not a git host":    func(m map[string]any) { m[pass.ContextKeyConnector] = "okta-response" },
		"no project":        func(m map[string]any) { delete(m, pass.ContextKeyProject) },
		"label with a line": func(m map[string]any) { m[pass.ContextKeyLabels] = "a=b\nc: d" },
	} {
		t.Run(name, func(t *testing.T) {
			g := &gitPlatform{records: map[string]string{}}
			task := workloadTask(pass.TaskIsolate)
			mutate(task.Context)
			res, err := pass.Run(context.Background(), g, liveReader{g}, noCalls{}, task)
			if err == nil || res.Status != a2a.TaskStateFailed || len(g.calls) != 0 {
				t.Fatalf("err = %v, status = %v, calls = %v", err, res.Status, g.calls)
			}
		})
	}
}
