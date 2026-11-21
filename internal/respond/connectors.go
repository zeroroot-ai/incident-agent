// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package respond

import (
	"regexp"
	"strings"

	"github.com/zeroroot-ai/incident-agent/internal/incident"
)

// Connector is one response connector of the platform catalog that the agent
// can use. The table below is closed. A connector name from the graph selects
// an entry of the table, and only the entry builds a tool id.
type Connector struct {
	// ID is the id of the connector in the platform catalog. It is the
	// connector part of each tool id, mcp:<ID>:<tool>.
	ID string
	// Label is the taxonomy label of the place that the connector acts on.
	Label string
	// Arg is the name of the one argument of each tool: the vendor id of the
	// target.
	Arg string
	// format is the form of a vendor id that the connector accepts. It is the
	// same check that the MCP server makes (zeroroot-ai/connectors v0.1.0).
	format *regexp.Regexp
	// Steps are the containment actions, in the order that the agent makes
	// them.
	Steps []Step
}

// Step is one containment action of a connector.
type Step struct {
	// Tool is the tool that contains the target.
	Tool string
	// Undo is the tool that releases the containment. Empty means that the
	// action has no undo. A revoked session has none: the user signs in
	// again.
	Undo string
}

// connectors is the closed table of the response connectors. The source of
// each row is the README.md and server.go of the directory in
// zeroroot-ai/connectors v0.1.0, and the manifest *-response.yaml in gibson
// (branch integration/blue-team).
var connectors = []Connector{
	{
		ID: "okta-response", Label: incident.LabelAccount, Arg: "user_id",
		format: regexp.MustCompile(`^[A-Za-z0-9]{20}$`),
		Steps: []Step{
			{Tool: "suspend_user", Undo: "unsuspend_user"},
			{Tool: "revoke_user_sessions"},
		},
	},
	{
		// Microsoft: a disabled account keeps the sessions that exist, so the
		// revoke comes after the disable.
		ID: "entra-id-response", Label: incident.LabelAccount, Arg: "user_id",
		format: regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`),
		Steps: []Step{
			{Tool: "disable_account", Undo: "enable_account"},
			{Tool: "revoke_sign_in_sessions"},
		},
	},
	{
		ID: "crowdstrike-response", Label: incident.LabelHost, Arg: "host_id",
		format: regexp.MustCompile(`^[0-9a-fA-F]{32}$`),
		Steps:  []Step{{Tool: "contain_host", Undo: "lift_containment"}},
	},
	{
		ID: "defender-endpoint-response", Label: incident.LabelHost, Arg: "device_id",
		format: regexp.MustCompile(`^[0-9a-fA-F]{40}$`),
		Steps:  []Step{{Tool: "isolate_device", Undo: "release_device"}},
	},
	{
		ID: "sentinelone-response", Label: incident.LabelHost, Arg: "agent_id",
		format: regexp.MustCompile(`^\d{10,24}$`),
		Steps:  []Step{{Tool: "disconnect_from_network", Undo: "reconnect_to_network"}},
	},
}

// lookup returns the table entry for a connector id. The match is exact. A
// name that differs only in case or space is a different name.
func lookup(id string) (Connector, bool) {
	for _, c := range connectors {
		if c.ID == id {
			return c, true
		}
	}
	return Connector{}, false
}

// ToolID returns the canonical tool id of one tool of the connector.
func (c Connector) ToolID(tool string) string {
	return "mcp:" + c.ID + ":" + tool
}

// confirmed reads the one field of a tool result that says the vendor took
// the action. The result is untrusted data: the agent reads a bool or a
// number from it and nothing else.
func confirmed(connectorID string, result map[string]any) bool {
	switch connectorID {
	case "okta-response", "entra-id-response":
		done, _ := result["done"].(bool)
		return done
	case "crowdstrike-response":
		accepted, _ := result["accepted"].(bool)
		return accepted
	case "defender-endpoint-response":
		id, _ := result["action_id"].(string)
		return strings.TrimSpace(id) != ""
	case "sentinelone-response":
		n, _ := result["affected"].(float64)
		return n > 0
	default:
		return false
	}
}
