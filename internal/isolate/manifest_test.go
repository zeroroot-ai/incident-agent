// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package isolate_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zeroroot-ai/incident-agent/internal/isolate"
	"go.yaml.in/yaml/v3"
)

func parse(t *testing.T, text string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := yaml.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("the file is not YAML: %v\n%s", err, text)
	}
	return out
}

func at(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var cur any = m
	for _, p := range path {
		next, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%v is not a map at %q", cur, p)
		}
		cur, ok = next[p]
		if !ok {
			t.Fatalf("no key %q on the path %v", p, path)
		}
	}
	return cur
}

func selector(t *testing.T, m map[string]any, path ...string) map[string]any {
	t.Helper()
	sel, ok := at(t, m, path...).(map[string]any)
	if !ok || len(sel) == 0 {
		t.Fatalf("the selector at %v is empty: an empty selector isolates the whole namespace", path)
	}
	return sel
}

func TestPolicyYAML(t *testing.T) {
	w := workload(t)
	for _, kind := range []string{isolate.KindCilium, isolate.KindAdmin, isolate.KindNetworkPolicy} {
		t.Run(kind, func(t *testing.T) {
			r := repoOf(kind)
			c := r.Isolate(incidentKey, w, 1)
			if len(c.Files) != 2 {
				t.Fatalf("the change has %d files, want the policy and the lock", len(c.Files))
			}
			policy := parse(t, c.Files[0].Content)
			lock := parse(t, c.Files[1].Content)
			if lock["state"] != "open" || lock["policy"] != c.Files[0].Path || lock["kind"] != kind {
				t.Errorf("the lock = %v", lock)
			}
			if strings.Contains(strings.ToLower(c.Files[0].Content), "dns") || strings.Contains(c.Files[0].Content, "53") {
				t.Errorf("the policy holds a DNS allow:\n%s", c.Files[0].Content)
			}
			if strings.Contains(c.Files[0].Content+c.Files[1].Content, incidentKey) {
				t.Errorf("a file holds the incident key. It must hold only the hash")
			}
			want := map[string]any{"app": "ledger", "tier": "api"}
			var got map[string]any
			switch kind {
			case isolate.KindCilium:
				if at(t, policy, "kind") != "CiliumNetworkPolicy" || at(t, policy, "metadata", "namespace") != "payments" {
					t.Errorf("policy = %v", policy)
				}
				got = selector(t, policy, "spec", "endpointSelector", "matchLabels")
				if fmt.Sprint(at(t, policy, "spec", "ingressDeny")) != "[map[fromEntities:[all]]]" ||
					fmt.Sprint(at(t, policy, "spec", "egressDeny")) != "[map[toEntities:[all]]]" {
					t.Errorf("the deny rules are not deny all: %v", policy["spec"])
				}
				if _, has := at(t, policy, "spec").(map[string]any)["egress"]; has {
					t.Errorf("the policy has an allow list")
				}
			case isolate.KindAdmin:
				if at(t, policy, "kind") != "AdminNetworkPolicy" {
					t.Errorf("policy = %v", policy)
				}
				if _, has := at(t, policy, "metadata").(map[string]any)["namespace"]; has {
					t.Errorf("an AdminNetworkPolicy is cluster scoped")
				}
				if at(t, policy, "spec", "priority") != isolate.AdminPriority {
					t.Errorf("priority = %v", at(t, policy, "spec", "priority"))
				}
				got = selector(t, policy, "spec", "subject", "pods", "podSelector", "matchLabels")
				ns := selector(t, policy, "spec", "subject", "pods", "namespaceSelector", "matchLabels")
				if ns["kubernetes.io/metadata.name"] != "payments" {
					t.Errorf("the namespace selector = %v", ns)
				}
				for _, dir := range []string{"ingress", "egress"} {
					rules, _ := at(t, policy, "spec", dir).([]any)
					if len(rules) != 1 || rules[0].(map[string]any)["action"] != "Deny" { //nolint:forcetypeassert // test
						t.Errorf("%s rules = %v, want one Deny", dir, rules)
					}
				}
				if !strings.Contains(c.Files[0].Content, "0.0.0.0/0") || !strings.Contains(c.Files[0].Content, `"::/0"`) {
					t.Errorf("the egress deny does not cover the networks outside the cluster")
				}
			default:
				if at(t, policy, "kind") != "NetworkPolicy" || at(t, policy, "metadata", "namespace") != "payments" {
					t.Errorf("policy = %v", policy)
				}
				got = selector(t, policy, "spec", "podSelector", "matchLabels")
				types := fmt.Sprint(at(t, policy, "spec", "policyTypes"))
				spec, _ := at(t, policy, "spec").(map[string]any)
				_, ingress := spec["ingress"]
				_, egress := spec["egress"]
				if types != "[Ingress Egress]" || ingress || egress {
					t.Errorf("policyTypes = %s, ingress rules = %v, egress rules = %v", types, ingress, egress)
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("the selector = %v, want %v", got, want)
			}
			if at(t, policy, "metadata", "annotations", isolate.AnnotationRule) == "" {
				t.Errorf("no rule against a revert")
			}
		})
	}
}

func TestParseWorkload(t *testing.T) {
	long := strings.Repeat("a", 64)
	many := make([]string, 0, 11)
	for i := range 11 {
		many = append(many, fmt.Sprintf("k%d=v", i))
	}
	tests := []struct {
		name, ns, labels string
		ok               bool
	}{
		{"one label", "payments", "app=ledger", true},
		{"prefixed key", "payments", "app.kubernetes.io/name=ledger", true},
		{"empty value", "payments", "app=", true},
		{"no label is the whole namespace", "payments", "", false},
		{"system namespace", "kube-system", "app=x", false},
		{"namespace with a slash", "a/b", "app=x", false},
		{"upper case namespace", "Payments", "app=x", false},
		{"value with a newline", "payments", "app=x\nkind: Namespace", false},
		{"value with a colon", "payments", "app=a: b", false},
		{"key with a space", "payments", "a b=x", false},
		{"no equals sign", "payments", "app", false},
		{"too long value", "payments", "app=" + long, false},
		{"duplicate key", "payments", "app=a,app=b", false},
		{"eleven labels", "payments", strings.Join(many, ","), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := isolate.ParseWorkload(tc.ns, tc.labels)
			if (err == nil) != tc.ok {
				t.Fatalf("ParseWorkload(%q, %q) error = %v, want ok = %v", tc.ns, tc.labels, err, tc.ok)
			}
		})
	}
}

// An empty value is a valid label. The selector must keep it and stay valid
// YAML.
func TestEmptyLabelValueRenders(t *testing.T) {
	w, err := isolate.ParseWorkload("payments", "app=,tier=api")
	if err != nil {
		t.Fatalf("ParseWorkload: %v", err)
	}
	policy := parse(t, repoOf(isolate.KindCilium).Isolate(incidentKey, w, 1).Files[0].Content)
	got := selector(t, policy, "spec", "endpointSelector", "matchLabels")
	if v, has := got["app"]; !has || v != "" || got["tier"] != "api" {
		t.Fatalf("the selector = %v", got)
	}
}
