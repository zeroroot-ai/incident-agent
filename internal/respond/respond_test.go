// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package respond_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/incident-agent/internal/respond"
	"github.com/zeroroot-ai/sdk/agent"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	oktaID   = "00ub0oNGTSWTBKOLGLNR"
	entraID  = "87d349ed-44d7-43e1-9a83-5f2406dee5bd"
	falconID = "0123456789abcdef0123456789abcdef"
	mdeID    = "0123456789abcdef0123456789abcdef01234567"
	s1ID     = "225494730938493804"
)

func place(label, connector, vendorID string) incident.Place {
	return incident.Place{Label: label, Key: placeKey(connector, vendorID)}
}

func TestParseTarget_AcceptsEachConnectorOfTheTable(t *testing.T) {
	for _, tc := range []struct {
		place incident.Place
		tool  string
	}{
		{place(incident.LabelAccount, "okta-response", oktaID), "mcp:okta-response:suspend_user"},
		{place(incident.LabelAccount, "entra-id-response", entraID), "mcp:entra-id-response:disable_account"},
		{place(incident.LabelHost, "crowdstrike-response", falconID), "mcp:crowdstrike-response:contain_host"},
		{place(incident.LabelHost, "defender-endpoint-response", mdeID), "mcp:defender-endpoint-response:isolate_device"},
		{place(incident.LabelHost, "sentinelone-response", s1ID), "mcp:sentinelone-response:disconnect_from_network"},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			got, err := respond.ParseTarget(tc.place)
			if err != nil {
				t.Fatalf("ParseTarget(%q): %v", tc.place.Key, err)
			}
			if id := got.Connector.ToolID(got.Connector.Steps[0].Tool); id != tc.tool {
				t.Errorf("first tool = %s, want %s", id, tc.tool)
			}
		})
	}
}

// A place key is graph data. Each key below must not build a tool id or an
// argument.
func TestParseTarget_RefusesAKeyThatIsNotATargetOfTheTable(t *testing.T) {
	for name, p := range map[string]incident.Place{
		"plain brain id":         {Label: incident.LabelHost, Key: "5f0c3f0e-0000-4000-8000-000000000001"},
		"unknown connector":      place(incident.LabelHost, "shell", falconID),
		"connector in two cases": place(incident.LabelHost, "CrowdStrike-Response", falconID),
		"wrong label":            place(incident.LabelAccount, "crowdstrike-response", falconID),
		"vendor id too short":    place(incident.LabelHost, "crowdstrike-response", "abc"),
		"path in vendor id":      place(incident.LabelAccount, "okta-response", "../../api/v1/users/x"),
		"injected tool":          place(incident.LabelHost, "crowdstrike-response:delete_host", falconID),
		"three parts": {
			Label: incident.LabelHost,
			Key:   placeKey("crowdstrike-response", falconID) + "|tool=delete",
		},
		"no value": {Label: incident.LabelHost, Key: "connector=|vendor_id="},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := respond.ParseTarget(p); err == nil {
				t.Fatalf("ParseTarget(%q) = %+v, want a refusal", p.Key, got)
			}
		})
	}
}

// fakeTools answers invoke_tool in the shapes of the daemon: a result is the
// JSON {"result": <structured content of the MCP tool>}, and a refusal is the
// message of the HarnessError, which the SDK puts behind "CallToolProto
// error: " (serve/callback_harness.go). The SDK sets the call id before it
// returns the error.
type fakeTools struct {
	result string
	errMsg string
	callID string
	got    map[string]any
	calls  int
	cancel context.CancelFunc
}

func (f *fakeTools) CallToolProto(
	_ context.Context, name string, req, resp proto.Message, opts ...agent.ToolCallOption,
) error {
	f.calls++
	if name != respond.InvokeTool {
		return fmt.Errorf("tool %q, want invoke_tool", name)
	}
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	s := &structpb.Struct{}
	if err := protojson.Unmarshal(raw, s); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	f.got = s.AsMap()
	agent.ApplyToolCallOptions(opts).SetToolCallID(f.callID)
	if f.cancel != nil {
		f.cancel()
	}
	if f.errMsg != "" {
		return errors.New("CallToolProto error: " + f.errMsg)
	}
	if err := protojson.Unmarshal([]byte(f.result), resp); err != nil {
		return fmt.Errorf("unmarshal the result: %w", err)
	}
	return nil
}

func action(t *testing.T, p incident.Place) respond.Action {
	t.Helper()
	tg, err := respond.ParseTarget(p)
	if err != nil {
		t.Fatal(err)
	}
	return respond.Action{Kind: respond.KindContain, Target: tg, Tool: tg.Connector.Steps[0].Tool}
}

func TestInvoke_SendsTheCanonicalIDAndTheVendorIDOnly(t *testing.T) {
	f := &fakeTools{
		result: `{"result":{"host_id":"` + falconID + `","action":"contain","accepted":true}}`,
		callID: "call-1",
	}
	inv, err := respond.New(f)
	if err != nil {
		t.Fatal(err)
	}
	r, err := inv.Invoke(context.Background(), action(t, place(incident.LabelHost, "crowdstrike-response", falconID)))
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != respond.OutcomeDone || r.CallID != "call-1" {
		t.Errorf("result = %+v, want done with the call id", r)
	}
	if f.got["id"] != "mcp:crowdstrike-response:contain_host" {
		t.Errorf("id = %v", f.got["id"])
	}
	args, _ := f.got["args"].(map[string]any)
	if len(args) != 1 || args["host_id"] != falconID {
		t.Errorf("args = %v, want only host_id", args)
	}
}

// The messages are the words of callback_metatool.go and metatool on the
// gibson branch integration/blue-team.
func TestInvoke_MapsEachAnswerOfTheDaemon(t *testing.T) {
	for _, tc := range []struct {
		name   string
		errMsg string
		result string
		want   respond.Outcome
	}{
		{
			name: "pending authorization",
			errMsg: "metatool: pending authorization: a person must approve this call before it runs: request r-1. " +
				"Do not retry now. Call again with the same arguments after the approval.",
			want: respond.OutcomePending,
		},
		{
			name: "no grant", errMsg: "metatool: not authorized to invoke tool: mcp:okta-response:suspend_user",
			want: respond.OutcomeRefused,
		},
		{name: "a person denied", errMsg: "metatool: a person denied this call: request r-1", want: respond.OutcomeRefused},
		{
			name: "deny list", errMsg: "metatool: the tool is blocked by mission policy: mcp:okta-response:suspend_user",
			want: respond.OutcomeRefused,
		},
		{name: "run not active", errMsg: "mission run is not active", want: respond.OutcomeRefused},
		{
			name:   "no approval queue",
			errMsg: "metatool: the tool needs approval and the approval queue is not available: mcp:okta-response:suspend_user",
			want:   respond.OutcomeFailed,
		},
		{
			name:   "vendor error",
			errMsg: "metatool: invoke \"x\": connector mcp: suspend_user reported an error: HTTP 400",
			want:   respond.OutcomeFailed,
		},
		{
			name:   "vendor changed nothing",
			result: `{"result":{"user_id":"` + oktaID + `","action":"suspend","done":false}}`,
			want:   respond.OutcomeFailed,
		},
		{name: "no result", result: `{}`, want: respond.OutcomeFailed},
		{
			name:   "vendor took it",
			result: `{"result":{"user_id":"` + oktaID + `","action":"suspend","done":true}}`,
			want:   respond.OutcomeDone,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv, err := respond.New(&fakeTools{errMsg: tc.errMsg, result: tc.result})
			if err != nil {
				t.Fatal(err)
			}
			r, err := inv.Invoke(context.Background(), action(t, place(incident.LabelAccount, "okta-response", oktaID)))
			if err != nil {
				t.Fatal(err)
			}
			if r.Outcome != tc.want {
				t.Errorf("outcome = %s, want %s (detail %q)", r.Outcome, tc.want, r.Detail)
			}
			if tc.want != respond.OutcomeDone && r.Detail == "" {
				t.Error("an outcome that is not done has no detail")
			}
		})
	}
}

func TestInvoke_ConfirmsEachConnectorByItsOwnField(t *testing.T) {
	for _, tc := range []struct {
		place  incident.Place
		result string
	}{
		{place(incident.LabelAccount, "entra-id-response", entraID), `{"result":{"done":true}}`},
		{
			place(incident.LabelHost, "defender-endpoint-response", mdeID),
			`{"result":{"action_id":"ma-1","status":"Pending"}}`,
		},
		{place(incident.LabelHost, "sentinelone-response", s1ID), `{"result":{"affected":1}}`},
	} {
		inv, err := respond.New(&fakeTools{result: tc.result})
		if err != nil {
			t.Fatal(err)
		}
		r, err := inv.Invoke(context.Background(), action(t, tc.place))
		if err != nil || r.Outcome != respond.OutcomeDone {
			t.Errorf("%s: outcome %s err %v, want done", tc.place.Key, r.Outcome, err)
		}
	}
	inv, err := respond.New(&fakeTools{result: `{"result":{"affected":0}}`})
	if err != nil {
		t.Fatal(err)
	}
	r, err := inv.Invoke(context.Background(), action(t, place(incident.LabelHost, "sentinelone-response", s1ID)))
	if err != nil || r.Outcome != respond.OutcomeFailed {
		t.Errorf("affected 0: outcome %s err %v, want failed", r.Outcome, err)
	}
}

func TestInvoke_AnEndedContextStopsThePass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	inv, err := respond.New(&fakeTools{errMsg: "context canceled", cancel: cancel})
	if err != nil {
		t.Fatal(err)
	}
	a := action(t, place(incident.LabelHost, "crowdstrike-response", falconID))
	if _, err := inv.Invoke(ctx, a); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestNew_NoToolCaller(t *testing.T) {
	if _, err := respond.New(nil); err == nil {
		t.Fatal("want an error")
	}
}

func TestClean_RemovesControlCharactersAndCuts(t *testing.T) {
	got := respond.Clean("a\nb\x00c" + strings.Repeat("é", 300))
	if strings.ContainsAny(got, "\n\x00") {
		t.Errorf("Clean kept a control character: %q", got)
	}
	if len(got) > respond.MaxDetailBytes {
		t.Errorf("len = %d, want at most %d", len(got), respond.MaxDetailBytes)
	}
	if !strings.HasPrefix(got, "a b c") || strings.ContainsRune(got, '�') {
		t.Errorf("Clean = %q", got)
	}
}

// placeKey is the key of a place that names a vendor id of a connector: the
// composite key of the identity properties connector and vendor_id.
func placeKey(connectorID, vendorID string) string {
	return "connector=" + connectorID + "|vendor_id=" + vendorID
}
