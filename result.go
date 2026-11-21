// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/zeroroot-ai/sdk/agent"
)

// writeResult writes the terminal result line of one run to w.
//
// The line is one JSON object on one line, and it is the last line on
// stdout. The sandbox launcher of gibson takes the last line with
// "type":"result" and gives it to the mission node (gibson#682). A run with
// no such line is an error there. The shape is the one that zerocool writes
// (formatTerminalResult in zerocool-plugins:
// packages/opencode-gibson/src/dispatch.ts).
//
// A run that returned an error fails, and the error is the output. A run that
// returned no error but a result that is not a success also fails. slog
// writes to stderr, so stdout holds only this line.
func writeResult(w io.Writer, res agent.Result, runErr error) error {
	success := runErr == nil && res.Status == a2a.TaskStateCompleted
	output := outputText(res.Output)
	if runErr != nil {
		output = runErr.Error()
	} else if !success && output == "" {
		output = fmt.Sprintf("the pass ended with status %q", res.Status)
	}

	// A map, not a struct: the reader of each key is the launcher in
	// gibson, outside this process, so no field of this binary reads it.
	line := map[string]any{
		"type":    "result",
		"success": success,
		"output":  output,
	}
	if len(res.Findings) > 0 {
		line["finding_ids"] = res.Findings
	}
	if len(res.Metadata) > 0 {
		md := make(map[string]string, len(res.Metadata))
		for k, v := range res.Metadata {
			md[k] = fmt.Sprint(v)
		}
		line["metadata"] = md
	}

	b, err := json.Marshal(line)
	if err != nil {
		return fmt.Errorf("encode the result line: %w", err)
	}
	if _, err := fmt.Fprintf(w, "%s\n", b); err != nil {
		return fmt.Errorf("write the result line: %w", err)
	}
	return nil
}

// outputText turns the output of a pass into the text of the result line.
func outputText(out any) string {
	switch v := out.(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(b)
	}
}
