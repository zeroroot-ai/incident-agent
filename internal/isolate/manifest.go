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

// ClusterPriority is the priority of a ClusterNetworkPolicy in the Admin
// tier. A lower number is evaluated first. The policy of a cluster admin
// starts at 0 only by choice, so 1 is ahead of nearly each other policy.
const ClusterPriority = 1

// regularMode is the git mode of a regular file that is not executable. The
// connector writes each file with it.
const regularMode = "100644"

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
// the SHA-256 of the cluster, the incident key, the namespace and the labels.
// A name that the agent writes into a repo, a branch or a record holds the
// key and never a value of the graph.
func (r Repo) Key(incidentKey string, w Workload) string {
	h := sha256.New()
	for _, part := range append([]string{r.Cluster, incidentKey, w.Namespace}, w.sortedLabels()...) {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// PolicyName is the name of the policy of one containment.
func PolicyName(key string) string { return "zeroroot-isolate-" + key }

// IsolationBranch is the branch of the isolation merge request of a generation.
func IsolationBranch(key string, gen int) string {
	return "zeroroot/isolate-" + key + "-" + strconv.Itoa(gen)
}

// ReleaseBranch is the branch of the release merge request of a generation.
func ReleaseBranch(key string, gen int) string {
	return "zeroroot/release-" + key + "-" + strconv.Itoa(gen)
}

// PolicyPath is the path of the policy file of a containment.
func (r Repo) PolicyPath(key string) string { return r.base() + "/" + PolicyName(key) + ".yaml" }

func (r Repo) lockPath(key string) string { return r.base() + "/" + PolicyName(key) + ".lock.yaml" }

// quote writes a string as a YAML double-quoted scalar. A JSON string is one.
func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// A string always encodes. The empty scalar is the safe answer.
		return `""`
	}
	return string(b)
}

// Isolate returns the change that isolates the workload: a policy that
// denies all ingress and all egress, and the lock file.
func (r Repo) Isolate(incidentKey string, w Workload, gen int) Change {
	key := r.Key(incidentKey, w)
	ref := cause.Ref(incidentKey)
	return Change{
		Branch: IsolationBranch(key, gen),
		Title:  "contain(incident-" + ref + "): isolate a workload",
		Description: "The incident agent isolates one workload of the incident " + ref + ".\n" +
			"The policy denies all ingress and all egress for the pods with the labels below.\n" +
			"Do not revert this merge request while the incident is open.\n" +
			"The agent removes the policy after the cause of the incident is verified.\n",
		Files: []File{
			{Path: r.PolicyPath(key), Content: r.policyYAML(key, ref, w)},
			{Path: r.lockPath(key), Content: r.lockYAML(key, ref, w)},
		},
	}
}

// Release returns the change that removes the two files of a containment.
func (r Repo) Release(incidentKey string, w Workload, gen int) Change {
	key := r.Key(incidentKey, w)
	ref := cause.Ref(incidentKey)
	return Change{
		Branch: ReleaseBranch(key, gen),
		Title:  "contain(incident-" + ref + "): release a workload",
		Description: "The cause of the incident " + ref + " is verified.\n" +
			"The incident agent removes the policy that isolated one workload.\n",
		Files: []File{
			{Path: r.PolicyPath(key), Delete: true},
			{Path: r.lockPath(key), Delete: true},
		},
	}
}

// meta writes the metadata of the policy. A cluster-scoped kind has no
// namespace.
func (r Repo) meta(b *strings.Builder, key, ref, namespace string) {
	b.WriteString("metadata:\n")
	fmt.Fprintf(b, "  name: %s\n", PolicyName(key))
	if namespace != "" {
		fmt.Fprintf(b, "  namespace: %s\n", namespace)
	}
	fmt.Fprintf(b, "  labels:\n    %s: %s\n", LabelContainment, quote(key))
	b.WriteString("  annotations:\n")
	fmt.Fprintf(b, "    %s: %s\n", AnnotationIncident, quote(ref))
	fmt.Fprintf(b, "    %s: %s\n", AnnotationRule, quote("while the incident "+ref+" is open"))
}

func matchLabels(b *strings.Builder, indent string, w Workload) {
	b.WriteString(indent + "matchLabels:\n")
	for _, kv := range w.sortedLabels() {
		k, v, _ := strings.Cut(kv, "=")
		fmt.Fprintf(b, "%s  %s: %s\n", indent, quote(k), quote(v))
	}
}

// policyYAML renders the policy of the kind of the repo. No kind has a DNS
// allow. A workload that is isolated cannot resolve a name, on purpose.
func (r Repo) policyYAML(key, ref string, w Workload) string {
	var b strings.Builder
	b.WriteString("# Written by the Zero Root incident agent.\n")
	b.WriteString("# Do not revert or edit this file while the incident is open.\n")
	switch r.PolicyKind {
	case KindCilium:
		b.WriteString("apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\n")
		r.meta(&b, key, ref, w.Namespace)
		b.WriteString("spec:\n  endpointSelector:\n")
		matchLabels(&b, "    ", w)
		b.WriteString("  ingressDeny:\n    - fromEntities:\n        - all\n")
		b.WriteString("  egressDeny:\n    - toEntities:\n        - all\n")
	case KindCluster:
		b.WriteString("apiVersion: policy.networking.k8s.io/v1beta1\nkind: ClusterNetworkPolicy\n")
		r.meta(&b, key, ref, "")
		fmt.Fprintf(&b, "spec:\n  tier: Admin\n  priority: %d\n", ClusterPriority)
		b.WriteString("  subject:\n    pods:\n      namespaceSelector:\n")
		fmt.Fprintf(&b, "        matchLabels:\n          kubernetes.io/metadata.name: %s\n", quote(w.Namespace))
		b.WriteString("      podSelector:\n")
		matchLabels(&b, "        ", w)
		b.WriteString("  ingress:\n    - name: deny-all-ingress\n      action: Deny\n      from:\n        - namespaces: {}\n")
		b.WriteString("  egress:\n    - name: deny-all-egress\n      action: Deny\n      to:\n        - namespaces: {}\n")
		b.WriteString("        - networks:\n            - 0.0.0.0/0\n            - \"::/0\"\n")
	default:
		b.WriteString("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n")
		r.meta(&b, key, ref, w.Namespace)
		b.WriteString("spec:\n  podSelector:\n")
		matchLabels(&b, "    ", w)
		b.WriteString("  policyTypes:\n    - Ingress\n    - Egress\n")
	}
	return b.String()
}

func (r Repo) lockYAML(key, ref string, w Workload) string {
	var b strings.Builder
	b.WriteString("# Written by the Zero Root incident agent.\n")
	b.WriteString("# While state is open, nobody reverts the merge request that added the policy.\n")
	b.WriteString("# The incident agent removes this file and the policy after the cause is verified.\n")
	fmt.Fprintf(&b, "containment: %s\nincident: %s\nstate: open\n", quote(key), quote(ref))
	fmt.Fprintf(&b, "kind: %s\npolicy: %s\n", quote(r.PolicyKind), quote(r.PolicyPath(key)))
	fmt.Fprintf(&b, "namespace: %s\n", quote(w.Namespace))
	return b.String()
}
