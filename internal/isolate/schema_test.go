// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package isolate_test

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/zeroroot-ai/incident-agent/internal/isolate"
	"go.yaml.in/yaml/v3"
)

// This file checks each rendered policy against the OpenAPI schema of its
// upstream API. The schemas are in testdata. SOURCES.txt names the URL and the
// version of each. The validator reads the keywords that these schemas use:
// $ref, allOf, anyOf, oneOf, type, enum, required, properties,
// additionalProperties, min and max for numbers, strings, items and
// properties, and pattern. It does not evaluate CEL rules
// (x-kubernetes-validations). The test checks the CIDR rule by hand.

type schemaSet struct {
	root map[string]any // components for $ref
}

func load(t *testing.T, file string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + file) //nolint:gosec // the name is a constant of this test
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return out
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

// crdSchema returns the schema of one version of a CRD, and checks the group,
// the kind and the scope against the document.
func crdSchema(t *testing.T, crd, doc map[string]any) map[string]any {
	t.Helper()
	spec := asMap(crd["spec"])
	apiVersion, _ := doc["apiVersion"].(string)
	group, version, _ := strings.Cut(apiVersion, "/")
	if spec["group"] != group || asMap(spec["names"])["kind"] != doc["kind"] {
		t.Fatalf("the document is %v %v, and the CRD is %v %v",
			apiVersion, doc["kind"], spec["group"], asMap(spec["names"])["kind"])
	}
	_, hasNamespace := asMap(doc["metadata"])["namespace"]
	if (spec["scope"] == "Namespaced") != hasNamespace {
		t.Errorf("the CRD scope is %v, and the document has a namespace: %v", spec["scope"], hasNamespace)
	}
	for _, v := range spec["versions"].([]any) { //nolint:forcetypeassert // the CRD has a list
		m := asMap(v)
		if m["name"] == version {
			if m["served"] != true {
				t.Fatalf("the version %s is not served", version)
			}
			return asMap(asMap(m["schema"])["openAPIV3Schema"])
		}
	}
	t.Fatalf("the CRD has no version %s", version)
	return nil
}

func (s schemaSet) resolve(n map[string]any) map[string]any {
	ref, ok := n["$ref"].(string)
	if !ok {
		return n
	}
	name := strings.TrimPrefix(ref, "#/components/schemas/")
	return asMap(asMap(asMap(s.root["components"])["schemas"])[name])
}

func isInt(v any) bool {
	switch x := v.(type) {
	case int, int64:
		return true
	case float64:
		return x == float64(int64(x))
	}
	return false
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

// validate returns the problems of v against the schema n.
func (s schemaSet) validate(v any, n map[string]any, path string) []string {
	n = s.resolve(n)
	var errs []string
	fail := func(f string, a ...any) { errs = append(errs, path+": "+fmt.Sprintf(f, a...)) }
	errs = append(errs, s.combine(v, n, path)...)
	if n["x-kubernetes-int-or-string"] == true {
		return errs
	}
	if _, isMap := v.(map[string]any); isMap && n["type"] == nil && (n["properties"] != nil || n["required"] != nil) {
		// A branch of oneOf or anyOf can state required and properties and no type.
		errs = append(errs, s.object(v, n, path, false)...)
	}
	switch n["type"] {
	case "object":
		errs = append(errs, s.object(v, n, path, true)...)
	case "array":
		errs = append(errs, s.array(v, n, path)...)
	case "string":
		errs = append(errs, str(v, n, path)...)
	case "integer", "number":
		errs = append(errs, number(v, n, path)...)
	case "boolean":
		if _, ok := v.(bool); !ok {
			fail("%v is not a boolean", v)
		}
	}
	return errs
}

// combine checks allOf, anyOf, oneOf and enum.
func (s schemaSet) combine(v any, n map[string]any, path string) []string {
	var errs []string
	fail := func(f string, a ...any) { errs = append(errs, path+": "+fmt.Sprintf(f, a...)) }
	for _, sub := range listOf(n["allOf"]) {
		errs = append(errs, s.validate(v, asMap(sub), path)...)
	}
	if subs := listOf(n["anyOf"]); len(subs) > 0 && countValid(s, v, subs, path) == 0 {
		fail("matches none of anyOf")
	}
	if subs := listOf(n["oneOf"]); len(subs) > 0 && countValid(s, v, subs, path) != 1 {
		fail("does not match exactly one of oneOf")
	}
	if enum := listOf(n["enum"]); len(enum) > 0 && !contains(enum, v) {
		fail("%v is not in %v", v, enum)
	}
	return errs
}

func number(v any, n map[string]any, path string) []string {
	x, ok := num(v)
	switch lo, hasLo := num(n["minimum"]); {
	case !ok || (n["type"] == "integer" && !isInt(v)):
		return []string{fmt.Sprintf("%s: %v is not a %v", path, v, n["type"])}
	case hasLo && x < lo:
		return []string{fmt.Sprintf("%s: %v is below the minimum %v", path, x, lo)}
	}
	if hi, has := num(n["maximum"]); has && x > hi {
		return []string{fmt.Sprintf("%s: %v is above the maximum %v", path, x, hi)}
	}
	return nil
}

func (s schemaSet) object(v any, n map[string]any, path string, strict bool) []string {
	var errs []string
	m, ok := v.(map[string]any)
	if !ok {
		return []string{fmt.Sprintf("%s: %v is not an object", path, v)}
	}
	if lim, has := num(n["minProperties"]); has && float64(len(m)) < lim {
		errs = append(errs, fmt.Sprintf("%s: has %d properties, the minimum is %v", path, len(m), lim))
	}
	if lim, has := num(n["maxProperties"]); has && float64(len(m)) > lim {
		errs = append(errs, fmt.Sprintf("%s: has %d properties, the maximum is %v", path, len(m), lim))
	}
	for _, r := range listOf(n["required"]) {
		if _, has := m[r.(string)]; !has { //nolint:forcetypeassert // the schema has strings
			errs = append(errs, fmt.Sprintf("%s: missing the required field %v", path, r))
		}
	}
	props := asMap(n["properties"])
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch {
		case props[k] != nil:
			errs = append(errs, s.validate(m[k], asMap(props[k]), path+"."+k)...)
		case asMap(n["additionalProperties"]) != nil:
			errs = append(errs, s.validate(m[k], asMap(n["additionalProperties"]), path+"."+k)...)
		case strict && len(props) > 0 && n["x-kubernetes-preserve-unknown-fields"] != true &&
			n["additionalProperties"] != true:
			errs = append(errs, fmt.Sprintf("%s: unknown field %q: the API server prunes it", path, k))
		}
	}
	return errs
}

func (s schemaSet) array(v any, n map[string]any, path string) []string {
	items, ok := v.([]any)
	if !ok {
		return []string{fmt.Sprintf("%s: %v is not an array", path, v)}
	}
	var errs []string
	if lim, has := num(n["minItems"]); has && float64(len(items)) < lim {
		errs = append(errs, fmt.Sprintf("%s: has %d items, the minimum is %v", path, len(items), lim))
	}
	if lim, has := num(n["maxItems"]); has && float64(len(items)) > lim {
		errs = append(errs, fmt.Sprintf("%s: has %d items, the maximum is %v", path, len(items), lim))
	}
	if sub := asMap(n["items"]); sub != nil {
		for i, it := range items {
			errs = append(errs, s.validate(it, sub, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return errs
}

func str(v any, n map[string]any, path string) []string {
	x, ok := v.(string)
	if !ok {
		return []string{fmt.Sprintf("%s: %v is not a string", path, v)}
	}
	var errs []string
	if lim, has := num(n["minLength"]); has && float64(utf8.RuneCountInString(x)) < lim {
		errs = append(errs, fmt.Sprintf("%s: %q is shorter than %v", path, x, lim))
	}
	if lim, has := num(n["maxLength"]); has && float64(utf8.RuneCountInString(x)) > lim {
		errs = append(errs, fmt.Sprintf("%s: %q is longer than %v", path, x, lim))
	}
	if pat, has := n["pattern"].(string); has {
		if re, err := regexp.Compile(pat); err == nil && !re.MatchString(x) {
			errs = append(errs, fmt.Sprintf("%s: %q does not match %s", path, x, pat))
		}
	}
	return errs
}

func listOf(v any) []any { l, _ := v.([]any); return l }

func contains(list []any, v any) bool {
	for _, x := range list {
		if fmt.Sprint(x) == fmt.Sprint(v) {
			return true
		}
	}
	return false
}

func countValid(s schemaSet, v any, subs []any, path string) int {
	n := 0
	for _, sub := range subs {
		if len(s.validate(v, asMap(sub), path)) == 0 {
			n++
		}
	}
	return n
}

// schemaOf returns the schema that the policy kind of the repo is validated
// against, and the document.
func schemaOf(t *testing.T, kind string) (set schemaSet, schema, doc map[string]any) {
	t.Helper()
	doc = parse(t, repoOf(kind).Isolate(incidentKey, workload(t), 1).Files[0].Content)
	switch kind {
	case isolate.KindCilium:
		return schemaSet{}, crdSchema(t, load(t, "ciliumnetworkpolicies.v1.19.11.yaml"), doc), doc
	case isolate.KindCluster:
		return schemaSet{}, crdSchema(t, load(t, "clusternetworkpolicies.v0.3.1.yaml"), doc), doc
	default:
		set = schemaSet{root: load(t, "networkpolicy.v1.36.6.schema.json")}
		if doc["apiVersion"] != "networking.k8s.io/v1" || doc["kind"] != "NetworkPolicy" {
			t.Fatalf("the document is %v %v", doc["apiVersion"], doc["kind"])
		}
		return set, set.resolve(map[string]any{"$ref": "#/components/schemas/io.k8s.api.networking.v1.NetworkPolicy"}), doc
	}
}

func TestPolicyValidatesAgainstTheUpstreamSchema(t *testing.T) {
	for _, kind := range []string{isolate.KindCilium, isolate.KindCluster, isolate.KindNetworkPolicy} {
		t.Run(kind, func(t *testing.T) {
			set, schema, doc := schemaOf(t, kind)
			if errs := set.validate(doc, schema, kind); len(errs) != 0 {
				t.Fatalf("the policy does not match the upstream schema:\n%s", strings.Join(errs, "\n"))
			}
		})
	}
}

// A ClusterNetworkPolicy has the CEL rule that each network is a CIDR with
// no host bits. The validator does not run CEL, so this test checks the rule.
func TestClusterPolicyNetworksAreMaskedCIDRs(t *testing.T) {
	_, _, doc := schemaOf(t, isolate.KindCluster)
	egress, _ := at(t, doc, "spec", "egress").([]any)
	found := 0
	for _, rule := range egress {
		peers, _ := asMap(rule)["to"].([]any)
		for _, peer := range peers {
			for _, c := range listOf(asMap(peer)["networks"]) {
				cidr, _ := c.(string)
				p, err := netip.ParsePrefix(cidr)
				if err != nil || p != p.Masked() {
					t.Errorf("the network %v is not a masked CIDR: %v", c, err)
				}
				found++
			}
		}
	}
	if found != 2 {
		t.Errorf("found %d networks, want the two default routes", found)
	}
}

// The validator must be able to fail. Each document below breaks one rule of
// the upstream schema.
func TestSchemaValidatorRejectsABrokenPolicy(t *testing.T) {
	cases := map[string]struct {
		kind   string
		mutate func(doc map[string]any)
	}{
		"an unknown tier": {isolate.KindCluster, func(d map[string]any) {
			at(t, d, "spec").(map[string]any)["tier"] = "Bogus"
		}},
		"two peers in one entry": {isolate.KindCluster, func(d map[string]any) {
			rule := at(t, d, "spec", "ingress").([]any)[0].(map[string]any)
			rule["from"] = []any{map[string]any{"namespaces": map[string]any{}, "pods": map[string]any{}}}
		}},
		"an unknown field": {isolate.KindCluster, func(d map[string]any) {
			at(t, d, "spec").(map[string]any)["selector"] = 1
		}},
		"a number for the pod selector": {isolate.KindNetworkPolicy, func(d map[string]any) {
			at(t, d, "spec").(map[string]any)["podSelector"] = 3
		}},
		"policy types that are not a list": {isolate.KindNetworkPolicy, func(d map[string]any) {
			at(t, d, "spec").(map[string]any)["policyTypes"] = "Ingress"
		}},
		"neither selector in Cilium": {isolate.KindCilium, func(d map[string]any) {
			delete(at(t, d, "spec").(map[string]any), "endpointSelector")
		}},
		"a number for the selector": {isolate.KindCilium, func(d map[string]any) {
			at(t, d, "spec").(map[string]any)["endpointSelector"] = 3
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			set, schema, doc := schemaOf(t, tc.kind)
			tc.mutate(doc)
			if errs := set.validate(doc, schema, tc.kind); len(errs) == 0 {
				t.Fatalf("the validator accepted a broken policy")
			}
		})
	}
}
