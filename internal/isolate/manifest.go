// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package isolate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/zeroroot-ai/incident-agent/internal/cause"
)

// The label and the annotations that mark a policy of this agent.
const (
	// LabelContainment is on the policy. Its value is the key of the
	// containment.
	LabelContainment = "zeroroot.ai/containment"
	// AnnotationIncident names the incident by its short hash.
	AnnotationIncident = "zeroroot.ai/incident"
	// AnnotationRule states the rule against a revert.
	AnnotationRule = "zeroroot.ai/do-not-revert"
)

// DefaultDir is the directory of the GitOps repo that holds the files of the
// agent, when the dispatch names none.
const DefaultDir = "zeroroot-containment"

// File is one file of a change to the repo of the buyer.
type File struct {
	Path string
	// Content is the text of the file. It is empty for a deleted file.
	Content string
	// Delete says that the change removes the file.
	Delete bool
}

// Change is one commit of one merge request.
type Change struct {
	// Branch is the branch of the merge request. It is the same for the same
	// containment and generation, so a second call opens no second merge
	// request.
	Branch      string
	Title       string
	Description string
	Files       []File
}

// Key is the key of one containment: the first 16 hexadecimal characters of
// the SHA-256 of the incident key, the namespace and the labels. A name that
// the agent writes into a repo, a branch or a record holds the key and never
// a value of the graph.
func Key(incidentKey string, w Workload) string {
	h := sha256.New()
	for _, part := range append([]string{incidentKey, w.Namespace}, w.sortedLabels()...) {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// PolicyName is the name of the NetworkPolicy of one containment.
func PolicyName(key string) string { return "zeroroot-isolate-" + key }

func policyPath(dir, key string) string { return dir + "/" + PolicyName(key) + ".yaml" }
func lockPath(dir, key string) string   { return dir + "/" + PolicyName(key) + ".lock.yaml" }

// quote writes a string as a YAML double-quoted scalar. A JSON string is one.
func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// A string always encodes. The empty scalar is the safe answer.
		return `""`
	}
	return string(b)
}

// Isolate returns the change that isolates the workload: a NetworkPolicy that
// denies all ingress and all egress, and the lock file.
func Isolate(dir, incidentKey string, w Workload, gen int) Change {
	key := Key(incidentKey, w)
	ref := cause.Ref(incidentKey)
	return Change{
		Branch: "zeroroot/isolate-" + key + "-" + strconv.Itoa(gen),
		Title:  "contain(incident-" + ref + "): isolate a workload",
		Description: "The incident agent isolates one workload of the incident " + ref + ".\n" +
			"The policy denies all ingress and all egress for the pods with the labels below.\n" +
			"Do not revert this merge request while the incident is open.\n" +
			"The agent removes the policy after the cause of the incident is verified.\n",
		Files: []File{
			{Path: policyPath(dir, key), Content: policyYAML(key, ref, w)},
			{Path: lockPath(dir, key), Content: lockYAML(dir, key, ref, w)},
		},
	}
}

// Release returns the change that removes the two files of a containment.
func Release(dir, incidentKey string, w Workload, gen int) Change {
	key := Key(incidentKey, w)
	ref := cause.Ref(incidentKey)
	return Change{
		Branch: "zeroroot/release-" + key + "-" + strconv.Itoa(gen),
		Title:  "contain(incident-" + ref + "): release a workload",
		Description: "The cause of the incident " + ref + " is verified.\n" +
			"The incident agent removes the policy that isolated one workload.\n",
		Files: []File{
			{Path: policyPath(dir, key), Delete: true},
			{Path: lockPath(dir, key), Delete: true},
		},
	}
}

func policyYAML(key, ref string, w Workload) string {
	var b strings.Builder
	b.WriteString("# Written by the Zero Root incident agent.\n")
	b.WriteString("# Do not revert or edit this file while the incident is open.\n")
	b.WriteString("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n")
	fmt.Fprintf(&b, "  name: %s\n  namespace: %s\n", PolicyName(key), w.Namespace)
	fmt.Fprintf(&b, "  labels:\n    %s: %s\n", LabelContainment, quote(key))
	b.WriteString("  annotations:\n")
	fmt.Fprintf(&b, "    %s: %s\n", AnnotationIncident, quote(ref))
	fmt.Fprintf(&b, "    %s: %s\n", AnnotationRule, quote("while the incident "+ref+" is open"))
	b.WriteString("spec:\n  podSelector:\n    matchLabels:\n")
	for _, kv := range w.sortedLabels() {
		k, v, _ := strings.Cut(kv, "=")
		fmt.Fprintf(&b, "      %s: %s\n", quote(k), quote(v))
	}
	b.WriteString("  policyTypes:\n    - Ingress\n    - Egress\n")
	return b.String()
}

func lockYAML(dir, key, ref string, w Workload) string {
	var b strings.Builder
	b.WriteString("# Written by the Zero Root incident agent.\n")
	b.WriteString("# While state is open, nobody reverts the merge request that added the policy.\n")
	b.WriteString("# The incident agent removes this file and the policy after the cause is verified.\n")
	fmt.Fprintf(&b, "containment: %s\nincident: %s\nstate: open\n", quote(key), quote(ref))
	fmt.Fprintf(&b, "policy: %s\nnamespace: %s\n", quote(policyPath(dir, key)), quote(w.Namespace))
	return b.String()
}
