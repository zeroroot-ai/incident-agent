// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package respond makes one response action through the meta-tool invoke_tool
// and says what happened to it.
//
// # The grant decides
//
// The agent asks. The daemon decides. invoke_tool checks can_execute on the
// connector, the mission deny list and the approval mark of the manifest
// before the call reaches the connector (gibson internal/engine/metatool,
// ADR-0180). The agent does not check the grant itself and does not look for
// a second tool when the daemon refuses the first one.
//
// # Untrusted data
//
// A place in the graph names its target in its key. This package reads that
// key, and it builds a tool id only from the closed table in connectors.go.
// The vendor id from the key goes to the tool as an argument only after it
// matches the form that the connector accepts. A value of a tool result is
// read as a bool or a number, never as text that the agent acts on.
package respond

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/zeroroot-ai/incident-agent/internal/incident"
	"github.com/zeroroot-ai/sdk/agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// InvokeTool is the name of the meta-tool that calls a catalog tool by its
// canonical id (ADR-0065).
const InvokeTool = "invoke_tool"

// MaxDetailBytes bounds the text of an outcome. The text goes into a property
// of the Incident node and into the report of the run.
const MaxDetailBytes = 240

// The two key parts of a place that a response action can contain. The key is
// the composite key that the daemon folds from the identity properties
// {"connector": <id>, "vendor_id": <id>} (ingest.EntityKey in gibson): the
// names in sorted order, joined with "|". The intake agent names an Alert the
// same way, by its connector and its result id.
const (
	keyConnector = "connector"
	keyVendorID  = "vendor_id"
)

// Target is one place that the agent can contain.
type Target struct {
	Connector Connector
	VendorID  string
}

// ParseTarget reads the target of a place. It returns a reason when the
// agent cannot contain the place.
func ParseTarget(p incident.Place) (Target, error) {
	parts := strings.Split(p.Key, "|")
	if len(parts) != 2 {
		return Target{}, errors.New("the place names no connector and vendor id")
	}
	fields := make(map[string]string, 2)
	for _, part := range parts {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			return Target{}, errors.New("the place names no connector and vendor id")
		}
		fields[name] = value
	}
	id, vendorID := fields[keyConnector], fields[keyVendorID]
	if id == "" || vendorID == "" {
		return Target{}, errors.New("the place names no connector and vendor id")
	}
	c, ok := lookup(id)
	if !ok {
		return Target{}, errors.New("the place names a connector that has no response action")
	}
	if c.Label != p.Label {
		return Target{}, fmt.Errorf("the connector %s acts on the label %s, and the place has the label %s",
			c.ID, c.Label, Clean(p.Label))
	}
	if !c.format.MatchString(vendorID) {
		return Target{}, fmt.Errorf("the vendor id is not in the form that the connector %s accepts", c.ID)
	}
	return Target{Connector: c, VendorID: vendorID}, nil
}

// Kind says whether an action contains a target or releases it.
type Kind string

const (
	// KindContain contains a target.
	KindContain Kind = "contain"
	// KindRelease releases a containment.
	KindRelease Kind = "release"
)

// Action is one tool call on one target.
type Action struct {
	Kind   Kind
	Target Target
	Tool   string
}

// ToolID is the canonical id of the tool of the action.
func (a Action) ToolID() string { return a.Target.Connector.ToolID(a.Tool) }

// Args are the arguments of the tool: the vendor id and nothing else.
func (a Action) Args() map[string]any {
	return map[string]any{a.Target.Connector.Arg: a.Target.VendorID}
}

// Outcome is what happened to one action. The values match the outcomes of
// the incident report of the daemon.
type Outcome string

const (
	// OutcomeDone means that the connector took the action.
	OutcomeDone Outcome = "done"
	// OutcomePending means that the call waits in the approval queue. The
	// call did not reach the connector.
	OutcomePending Outcome = "pending_authorization"
	// OutcomeRefused means that the daemon or a person refused the call. The
	// agent does not call it again.
	OutcomeRefused Outcome = "refused"
	// OutcomeFailed means that the call ran and did not take the action.
	OutcomeFailed Outcome = "failed"
	// OutcomeUnknown means that the call timed out or its transport failed
	// after the call left the agent. The vendor can have taken the action or
	// not. The agent writes no contained record for it, and the next dispatch
	// calls it again. The incident report of the daemon has no such outcome:
	// it reads the flight recorder, which holds the error of the call.
	OutcomeUnknown Outcome = "unknown"
)

// Result is the outcome of one action.
type Result struct {
	Action  Action
	Outcome Outcome
	// Detail is the reason of an outcome that is not done, cleaned and cut
	// to MaxDetailBytes.
	Detail string
	// CallID is the id that the daemon recorded for the call. It is empty
	// when the daemon recorded none.
	CallID string
}

// ToolCaller is the one harness capability that this package needs.
type ToolCaller interface {
	CallToolProto(ctx context.Context, name string, request, response proto.Message, opts ...agent.ToolCallOption) error
}

// Invoker makes response actions through invoke_tool.
type Invoker struct {
	tools ToolCaller
}

// New builds an Invoker over tools.
func New(tools ToolCaller) (*Invoker, error) {
	if tools == nil {
		return nil, errors.New("respond: no tool caller")
	}
	return &Invoker{tools: tools}, nil
}

// Invoke makes one action and returns its outcome. It returns an error only
// when the context ends: the pass then stops. Each other failure is an
// outcome, so the pass goes on with the next action.
func (i *Invoker) Invoke(ctx context.Context, a Action) (Result, error) {
	c, err := Call(ctx, i.tools, a.ToolID(), a.Args())
	if err != nil {
		return Result{}, err
	}
	res := Result{Action: a, CallID: c.CallID, Outcome: c.Outcome, Detail: c.Detail}
	if res.Outcome != OutcomeDone {
		return res, nil
	}
	if !confirmed(a.Target.Connector.ID, c.Result) {
		res.Outcome = OutcomeFailed
		res.Detail = "the connector answered, and its result does not confirm the action"
	}
	return res, nil
}

// Reply is the answer of one invoke_tool call.
type Reply struct {
	// Outcome is done when the daemon passed the call to the connector and
	// the connector answered. The caller still checks the result.
	Outcome Outcome
	// Detail is the cleaned text of the daemon for an outcome that is not done.
	Detail string
	// CallID is the id that the daemon recorded for the call, or "".
	CallID string
	// Result is the structured content of the tool. It is untrusted data.
	Result map[string]any
}

// Call makes one invoke_tool call and classifies its outcome. It returns an
// error only when the context ends. Each other failure is an outcome.
func Call(ctx context.Context, tools ToolCaller, toolID string, args map[string]any) (Reply, error) {
	req, err := structpb.NewStruct(map[string]any{"id": toolID, "args": args})
	if err != nil {
		return Reply{}, fmt.Errorf("respond: build the request of %s: %w", toolID, err)
	}
	var resp structpb.Struct
	var callID string
	err = tools.CallToolProto(ctx, InvokeTool, req, &resp, agent.ReceiveToolCallID(&callID))
	if cerr := ctx.Err(); cerr != nil {
		return Reply{}, fmt.Errorf("respond: %s: %w", toolID, cerr)
	}
	if err != nil {
		return Reply{Outcome: Classify(err), Detail: Clean(DaemonText(err.Error())), CallID: callID}, nil
	}
	result, _ := resp.AsMap()["result"].(map[string]any)
	return Reply{Outcome: OutcomeDone, CallID: callID, Result: result}, nil
}

// vendorMarker starts the part of an error text that the vendor wrote. The
// connector client of the daemon puts the text of the MCP tool result after
// it (connector_mcp.go in gibson: "connector mcp: %s on %q reported an
// error: %s").
const vendorMarker = " reported an error:"

// DaemonText returns the part of an error text that the daemon wrote. It cuts
// the text of the vendor, because a vendor message is untrusted data and can
// hold any word.
func DaemonText(errText string) string {
	if i := strings.Index(errText, vendorMarker); i >= 0 {
		return errText[:i] + vendorMarker + " (the vendor text is not kept)"
	}
	return errText
}

// Classify maps the error of a call to an outcome.
//
// A gRPC error is an error of the transport between the agent and the daemon.
// Each other error holds the message of the daemon. The SDK gives that message
// and not its code, so the match is on the words of the daemon
// (callback_metatool.go and internal/engine/metatool in gibson). gibson#1575
// adds typed error codes, and then this match goes away.
//
// The match reads only the text of the daemon. The text of the vendor never
// decides an outcome. A text that matches nothing is a failure, never a
// success.
func Classify(err error) Outcome {
	if err == nil {
		return OutcomeDone
	}
	if st, ok := status.FromError(err); ok {
		code := st.Code()
		if code == codes.PermissionDenied || code == codes.Unauthenticated {
			return OutcomeRefused
		}
		if code == codes.InvalidArgument || code == codes.NotFound || code == codes.Unimplemented ||
			code == codes.FailedPrecondition {
			// The daemon refused the request before it made a call.
			return OutcomeFailed
		}
		// The request left the agent, and no answer came back.
		return OutcomeUnknown
	}
	e := strings.ToLower(DaemonText(err.Error()))
	switch {
	case strings.Contains(e, "pending authorization"):
		return OutcomePending
	case strings.Contains(e, "not authorized"),
		strings.Contains(e, "denied"),
		strings.Contains(e, "blocked"),
		strings.Contains(e, "permission"),
		strings.Contains(e, "not active"):
		return OutcomeRefused
	case unknownAfterSend(e):
		return OutcomeUnknown
	default:
		return OutcomeFailed
	}
}

// unknownAfterSend reports whether the text of the daemon says that the call
// went to the connector and no usable answer came back. Each phrase is a
// message of the daemon or the SDK after the call was sent.
func unknownAfterSend(e string) bool {
	for _, phrase := range []string{
		// connector_mcp.go: the MCP exchange with the connector failed.
		"connector mcp: call ",
		"connector mcp: decode the tool result",
		"connector mcp: encode the tool result",
		// callback_service.go: the tool ran and its answer did not encode.
		"failed to marshal response",
		// serve/callback_harness.go: the answer did not decode.
		"failed to unmarshal tool output",
		context.DeadlineExceeded.Error(),
		"timed out",
		"timeout",
	} {
		if strings.Contains(e, phrase) {
			return true
		}
	}
	return false
}

// Clean makes a text from the daemon or the graph safe to store and to show:
// it removes control characters and cuts the text to MaxDetailBytes.
func Clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) <= MaxDetailBytes {
		return s
	}
	cut := MaxDetailBytes
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut]
}

// utf8Start reports whether b starts a UTF-8 sequence, so a cut never splits
// a rune.
func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
