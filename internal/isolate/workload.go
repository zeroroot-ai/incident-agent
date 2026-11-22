// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package isolate contains one Kubernetes workload and releases it.
//
// # No direct change
//
// The agent never touches the cluster. It asks the Git host connector of the
// buyer to open a merge request in the GitOps repo of the buyer. The merge
// request adds a NetworkPolicy that denies all ingress and all egress for the
// labels of the workload. The GitOps tool of the buyer applies it. The release
// is a second merge request that removes the policy.
//
// # The rule against a revert
//
// The merge request also adds a lock file. The policy and the lock file say
// that nobody reverts the change while the incident is open. The daemon side
// of this rule is not built (see the README).
//
// # The release
//
// The release acts only when the cause finding that this agent raised is
// verified. The daemon sets that status, and contain.HeldReason reads it. The
// agent does not read the health signal of an isolated workload. A
// containment stops its workload on purpose (ADR-0180).
package isolate

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// MaxLabels bounds the labels of one workload. A pod selector with more
// labels is not a selector that a person wrote for one workload.
const MaxLabels = 10

// The forms of a namespace, of the prefix of a label key and of a label name
// or value (Kubernetes DNS-1123 and label syntax).
var (
	dnsLabel  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	dnsPrefix = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
	labelPart = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
)

// systemNamespaces hold the parts of the cluster itself. A policy that
// denies all traffic there can stop the cluster, so the agent refuses them.
var systemNamespaces = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true,
}

// Workload is the set of pods that the agent isolates: the pods of one
// namespace that carry every label.
type Workload struct {
	Namespace string
	// Labels is the match set of the pod selector.
	Labels map[string]string
}

// ParseWorkload reads a workload from the namespace and from labels in the
// form "key=value,key=value". Each value is checked against the rules of
// Kubernetes. It becomes part of a file in the repo of the buyer, so a
// value that fails a check never reaches the file.
func ParseWorkload(namespace, labels string) (Workload, error) {
	ns := strings.TrimSpace(namespace)
	if ns == "" || len(ns) > 63 || !dnsLabel.MatchString(ns) {
		return Workload{}, errors.New("isolate: the namespace is not a Kubernetes namespace name")
	}
	if systemNamespaces[ns] {
		return Workload{}, fmt.Errorf("isolate: the agent does not isolate the system namespace %s", ns)
	}
	out := Workload{Namespace: ns, Labels: map[string]string{}}
	for _, pair := range strings.Split(labels, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return Workload{}, errors.New("isolate: a label is not in the form key=value")
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if err := checkLabel(k, v); err != nil {
			return Workload{}, err
		}
		if _, dup := out.Labels[k]; dup {
			return Workload{}, errors.New("isolate: a label key appears two times")
		}
		out.Labels[k] = v
	}
	if len(out.Labels) == 0 {
		// An empty selector matches each pod of the namespace.
		return Workload{}, errors.New("isolate: the workload has no label, and an empty selector is the whole namespace")
	}
	if len(out.Labels) > MaxLabels {
		return Workload{}, fmt.Errorf("isolate: the workload has more than %d labels", MaxLabels)
	}
	return out, nil
}

func checkLabel(k, v string) error {
	name := k
	if prefix, rest, ok := strings.Cut(k, "/"); ok {
		if prefix == "" || len(prefix) > 253 || !dnsPrefix.MatchString(prefix) {
			return errors.New("isolate: a label key has a prefix that is not a DNS name")
		}
		name = rest
	}
	if name == "" || len(name) > 63 || !labelPart.MatchString(name) {
		return errors.New("isolate: a label key is not a Kubernetes label key")
	}
	if v == "" || len(v) > 63 || !labelPart.MatchString(v) {
		return errors.New("isolate: a label value is not a Kubernetes label value")
	}
	return nil
}

// sortedLabels returns the labels as key=value strings in key order.
func (w Workload) sortedLabels() []string {
	out := make([]string, 0, len(w.Labels))
	for k, v := range w.Labels {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}
