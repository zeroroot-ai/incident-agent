# incident-agent

A Gibson agent for a blue team. It contains an incident that the security tools of the buyer detected, with the response actions that the security team of the buyer granted. It sends the cause of the incident to the fix loop. It runs no attack.

One dispatch is one task on one incident: `contain`, `cause` or `release`. The grant decides each response action. A tool that the manifest marks waits for a person in the approval queue. The agent never states that an incident is resolved. The daemon sets the status of the finding of the cause, and the incident report of the daemon states what happened. The agent contract is in [AGENTS.md](./AGENTS.md).

It is built with the ADK the way `cve-triage` and `fix-agent` are built. The process exits when the task ends.

## Layout

| Path | What it is | State |
|---|---|---|
| `internal/incident` | The shape of one incident: alerts, places, causes, records. | done |
| `internal/respond` | The closed table of response connectors, the call of `invoke_tool`, and the outcome of each call. | done, tested with a fake in the shapes of the daemon |
| `internal/contain` | The containment pass and the release pass. | done, tested with fakes |
| `internal/isolate` | The isolation of one Kubernetes workload and its release, as merge requests to the GitOps repo of the buyer. | done, tested with a mock Git host. Three connector tools do not exist yet (open item 9) |
| `internal/cause` | One model call, one finding of the cause, and the `CAUSED_BY` link. | done, tested with fakes |
| `internal/emit` | The records on the Incident node and the cause link. | done, tested with fakes |
| `internal/read` | The read of one incident, and the check of a tool call of the agent. | not served: the daemon has no incident read and no tool call read for an agent |
| `internal/pass` | Assembles one task and runs it against the harness. | done, tested over gRPC against a fake callback service |
| `internal/dispatch` | The launch contract: grant, callback endpoint, task. | done, tested with a fake environment |
| Tasks `triage` and `reach` | Join an alert to an Incident, and record what it reaches. | not built |
| Image build | Build, cosign signature and SBOM. | `.github/workflows/image.yml`, runs on `main` |
| Catalog manifest | The entry in `gibson` that makes the agent dispatchable. | not in this repo |
| End to end on kind | One alert from a mock tool to a contained incident. | not built |

## Open items

These items need a change in another repo.

1. **The incident read** (gibson#1573). The harness callback service has no call that reads an incident. The daemon has the queries (`internal/platform/incidentreport`), but only the tenant API serves them. Add a harness call, for example `IncidentFacts(incident_key)`, that returns the alerts (`PART_OF`), the places that they reach (`AFFECTS`, with the label and the key), the causes (`CAUSED_BY`, with the status that the daemon set), and the properties of the Incident node. Until it exists, each task fails with `ErrKnowledgeUnavailable`.
2. **The id of a submitted finding** ([gibson#1574](https://github.com/zeroroot-ai/gibson/issues/1574)). `SubmitFinding` returns no id. The cause step reads the findings of the mission and takes the one that it wrote (`cause.Own`): the title starts with the prefix of the incident, which holds a hash of the incident key, and the category is `incident-cause`. A finding that carries an author must name this agent, and a finding that carries tags must carry the two tags of this agent. The daemon drops the tags and the author today (`protoFindingToFinding`, `agentFindingToProto`), so the match rests on the prefix and the category. **Remaining risk:** another writer in the same mission can raise a finding with the same prefix and category before this agent does. The cause step then links that finding, and the release waits for its status. The risk ends when `SubmitFinding` returns the id and the agent keeps it.
3. **The remediation of a finding.** The harness callback of the daemon drops `remediation` (`protoFindingToFinding`). The cause step also puts the fix in the description.
4. **The error code of a tool call** (gibson#1575). The SDK gives the message of a refused call and not its code. The agent matches the words of the daemon, and it ignores the text of the vendor. A typed error in the SDK would remove the text match.
5. **The fix loop and the cause.** The fix loop reads the findings of one Application. The finding of the cause names its place with `AFFECTS` (an `Account` or a `Host`), and no Application reaches that place yet. The fix loop must also take a finding that an Incident names with `CAUSED_BY`.
6. **The writer of the places.** No code writes the `AFFECTS` edge from an alert to an `Account` or a `Host` with the key `connector=<id>|vendor_id=<id>`. The intake agent writes an alert with its title and detail only.
7. **The report of a refusal.** The incident report of the daemon classifies `metatool: not authorized to invoke tool` as `failed`, not `refused`, because its match looks for "permission denied" or "grant".
8. **The read of a tool call of the agent.** The release trusts a `contained` record only when the daemon confirms that this agent made the call that the record names. The harness has no call for it. The flight recorder holds each call (`ToolCallRecord`), but an agent cannot read it, and the record does not name the component that made the call. A `tool_call_id` in `SubmitFinding` is checked against the mission, not the agent. No store exists that only this agent writes: the session context store is keyed by the tenant and a session id that any component can choose. So `read.Daemon.CheckCall` fails with `ErrKnowledgeUnavailable`. A contain or release pass that finds a `contained` record fails and releases nothing. Add a harness call, for example `GetToolCall(tool_call_id)`, that returns the tool, the arguments and the outcome of a call only when the authenticated caller made it, and record the component identity in `ToolCallRecord`.

9. **Isolate a Kubernetes workload** (gibson#1477). The agent builds the merge requests. Parts are missing in other repos. See the section "Isolate a Kubernetes workload".

10. **The binding of a cause finding to this agent** (gibson). The release and the release of a workload trust only a finding that carries the author and the two tags of this agent. The daemon drops both. So each release waits until the daemon keeps them. This includes the existing `release` task, which now waits too.

## Isolate a Kubernetes workload

The task `isolate` contains one workload. The task `release_workload` releases it. The agent never changes the cluster. It asks the Git host connector of the buyer (`github-fixloop` or `gitlab-fixloop`) for a merge request in the GitOps repo of the buyer.

The isolation merge request adds two files in the directory `zeroroot-containment` (or the directory that the dispatch names).

1. A policy that denies all ingress and all egress for the pods with the labels of the workload. The kind of the policy is a choice of the dispatch (see the table below). No kind has a DNS allow, so an isolated workload cannot resolve a name.
2. A lock file with the state `open`. The policy and the lock file say that nobody reverts the change while the incident is open.

The release merge request deletes both files. It runs only after the cause finding that this agent raised is `verified`. The agent reads that status the same way as the `release` task: it reads the Incident with its `CAUSED_BY` causes (`contain.HeldReason`). The daemon sets the status, and the agent only reads it. The agent does not read the health signal of an isolated workload (ADR-0180).

### The kind of the policy

Policies of the kind NetworkPolicy add up. A deny-all NetworkPolicy does not block traffic that another policy allows. So the dispatch must name the kind.

| `ir.gitops.policy_kind` | Object | Deny wins over an allow |
|---|---|---|
| `cilium` | `CiliumNetworkPolicy` with `ingressDeny` and `egressDeny` for all entities. See https://docs.cilium.io/en/stable/security/policy/language/ | Yes |
| `cluster` | `ClusterNetworkPolicy` of the tier `Admin` with the action `Deny` at the priority 1 (`policy.networking.k8s.io/v1beta1`). The object is cluster-scoped, so it has no namespace. Its subject selects the namespace of the workload with the label `kubernetes.io/metadata.name`, and the pods by their labels. The ingress peer is every namespace. The egress peers are every namespace and the networks `0.0.0.0/0` and `::/0`. An ingress peer is a namespace or a pod, and the API cannot name a node. So the policy does not deny ingress from nodes, from pods with `hostNetwork`, or from outside traffic that is translated to a node address. The report and the record `ir_isolation_bypass_<key>_<generation>` say so. Use `cilium` to deny these paths. The Admin tier is evaluated before each NetworkPolicy. It replaced `AdminNetworkPolicy` in network-policy-api v0.2.0. See https://network-policy-api.sigs.k8s.io/ and https://github.com/kubernetes-sigs/network-policy-api/blob/v0.3.1/config/crd/standard/policy.networking.k8s.io_clusternetworkpolicies.yaml | Yes |
| `networkpolicy` | `NetworkPolicy` with `Ingress` and `Egress` and no rule. See https://kubernetes.io/docs/concepts/services-networking/network-policies/ | No |

For `networkpolicy` and `cluster`, the agent still writes the policy. The report and the record `ir_isolation_bypass_<key>_<generation>` state the paths that bypass it. For `networkpolicy`: another allow policy, a CNI that does not enforce policy, and a pod with `hostNetwork`. For `cluster`: ingress from nodes, from pods with `hostNetwork`, and from outside traffic that is translated to a node address. The kind `cilium` has no such note, because it denies all entities.

### What the agent does not trust

- **A record.** Any writer of the graph can write a record. So the agent reads each merge request on the host before it merges or counts it. It trusts a merge request only when its reference is in the configured project (`<project>#<number>` or `<project>!<number>`), its source branch is the expected branch `zeroroot/isolate-<key>-<generation>` or `zeroroot/release-<key>-<generation>`, and its head commit is the commit that the host returned when the agent opened it. A URL, another project, another branch and a moved head get no call. A person with push access can add a commit to the branch, and the branch name alone does not show it. The record value is `<reference>@<head sha>`. The agent sends that sha to `merge_merge_request`, so the host refuses the merge when the head moved after the read.
- **A branch that a person made first.** The head commit stops a commit after the open. It does not stop a commit before it. The branch name is easy to guess, so a person can make the branch first, and the commit of the agent lands on top of theirs. Two defenses work together. First, `open_merge_request` makes the branch from `base_branch` and refuses a branch that exists already with commits other than its own. Second, before each merge the agent reads `changed_files` of `merge_request_state` and refuses unless the files equal its expected change exactly: the same paths, the same content, the same deletes. A result with no `changed_files` is refused. A writer who can both write the graph and push to the repo can still forge a record and a branch. The comparison of the files is the defense, and the agent never merges a change that it did not write.
- **A merge.** A merge is not an application. The GitOps controller of the buyer applies the policy, and the agent does not see that. The report says "merged". It never says "isolated". After the merge, the agent reads the policy file on the base branch. When a person or a tool reverted or edited the policy, the agent records `ir_isolation_reverted_<key>_<generation>` and isolates again in the next generation.
- **The namespace of the GitOps controller.** The agent refuses `argocd`, `flux-system`, and each namespace in `ir.gitops.controller_namespaces`. A deny-all policy there stops the controller, and the release could not apply.
- **The cause finding.** The release takes a cause finding only when its author and its two tags name this agent. A title prefix and a category are text that any writer of the mission can copy. The daemon drops the author and the tags today, so a release waits (open item 10).

The agent reads the merge request again before it merges. A merge request that merged already gets no second merge call. So a failed write of the record after a merge does not stop the release: the next dispatch records the merge.

### The task context

The mission node gives these keys. All are required except the last three.

| Key | Meaning |
|---|---|
| `ir.workload.namespace` | The namespace of the workload. The agent refuses `kube-system`, `kube-public` and `kube-node-lease` and the namespaces of the GitOps controller. |
| `ir.workload.labels` | The labels of the pods, as `key=value,key=value`. An empty value is allowed. An empty list is refused, because an empty selector is the whole namespace. |
| `ir.gitops.connector` | `github-fixloop` or `gitlab-fixloop`. |
| `ir.gitops.project` | The project of the GitOps repo, for example `acme/manifests`. |
| `ir.gitops.base_branch` | The branch of the merge request target. |
| `ir.gitops.policy_kind` | `cilium`, `cluster` or `networkpolicy`. |
| `ir.gitops.dir` | The directory for the files. The default is `zeroroot-containment`. It holds only `a-z`, `0-9`, `.`, `_`, `-` and `/`. No segment starts with a dot or a dash, so the agent never writes under `.github`. |
| `ir.gitops.cluster` | The cluster name, when one repo serves many clusters. The files go in `<dir>/<cluster>`, and the key of the containment holds the cluster. |
| `ir.gitops.controller_namespaces` | More namespaces of the GitOps controller, separated by commas. |

**Limit: the source of the labels.** No mission in `gibson` sets `ir.workload.labels` today. The mission `incident-response` (commit 15c3bd4c) is removed from the catalog, and it never set the workload keys. If a later mission copies the labels from an alert, the labels are data from a security tool and not an instruction. A forged alert could then choose which workload the agent isolates. The mission must take the workload from a source that the buyer controls. The agent checks only the form of each label.

The records on the Incident are `ir_isolation_opened_`, `ir_isolation_merged_`, `ir_release_opened_`, `ir_isolation_released_`, `ir_isolation_reverted_` and `ir_isolation_bypass_`, each with the key of the containment and a generation. The value is the merge request reference. The agent writes the opened record at once. So a dispatch after a pending merge merges the same merge request and opens no second one. When a person closes the release merge request without a merge, the release stops with the line "a person must decide". The agent opens no third merge request, because a person chose to stop it. The same holds for an isolation merge request that a person closes. The release closes an isolation merge request that never merged, so nobody merges it later. A release that merged and whose record write failed is found again through the record `ir_release_opened_`, and the agent records a release and not a revert.

### The tools

| Tool | State | Source |
|---|---|---|
| `merge_request_state`, `merge_merge_request` | Exist in `github-fixloop` and `gitlab-fixloop` v0.2.0. `merge_request_state` returns `source_branch`. It must also return `head_sha`, and `merge_merge_request` must take the input `sha` and refuse the merge when the head differs. GitHub and GitLab both accept a sha on merge. | `zeroroot-ai/connectors` |
| `open_merge_request`, `close_merge_request`, `read_file` | Do not exist. A call fails with a daemon refusal and changes nothing. | Contract below |

The contract, for `zeroroot-ai/connectors`.

- `open_merge_request` takes `project`, `base_branch`, `branch`, `title`, `description` and `files`. Each file has a `path`, and either `content` or `delete: true`. The tool writes a `content` file whether it exists or not. The result is `{"merge_request": "<project>#<number>", "head_sha": "<commit>"}` for GitHub, and `<project>!<number>` for GitLab. `head_sha` is the head commit of the new branch. The same `branch` called two times opens one merge request. The tool commits all files in one commit. It makes the branch from `base_branch`. It refuses a branch that exists already with commits other than its own, and the refusal changes nothing.
- `merge_request_state` adds the result fields `head_sha` and `changed_files`. `changed_files` is the list of the files that the merge request changes. Each entry has a `path`, and either `content` (the text after the change) or `delete: true`. `merge_merge_request` takes the input `sha`. When the head of the merge request is another commit, it merges nothing and returns `merged: false`.
- `close_merge_request` takes `merge_request` and closes it without a merge.
- `read_file` takes `project`, `ref` and `path`. The result is `{"found": <bool>, "content": "<text>"}`. A result with no `found` is a failure.

Vendor endpoints. GitHub: https://docs.github.com/en/rest/git/commits, https://docs.github.com/en/rest/git/refs, https://docs.github.com/en/rest/pulls/pulls#create-a-pull-request and https://docs.github.com/en/rest/repos/contents. GitLab: https://docs.gitlab.com/api/commits/, https://docs.gitlab.com/api/merge_requests/ and https://docs.gitlab.com/api/repository_files/.

### Gaps that need other repos

1. **The three tools** (`zeroroot-ai/connectors`). See the contract above.
2. **The merge slot** (gibson). `merge_merge_request` has the role `merge`. The daemon runs it only when the merge request holds a granted slot. The watcher grants a slot only to a merge request that a finding names with `FIXED_BY`, and only for a finding that an Application owns. An isolation merge request has no finding, so the daemon refuses the merge today. The merge request must not name the cause finding. The daemon would then set the cause to `fixing` and could verify it by the isolation.
3. **The no-revert rule in the daemon** (gibson). The watcher reverts only a merge request that a fix job delivered for a finding. The isolation has no finding, so the watcher does not revert it today. A rule that says so, with a test, does not exist. The incident report also needs a marker to tell an isolation from a fix.
4. **The reads** (gibson#1573). Each task still needs the incident read.
5. **The author and the tags of a finding** (gibson). The daemon drops both on write (`protoFindingToFinding`) and on read (`agentFindingToProto`). Until it keeps them, no cause finding is bound to this agent, and each release waits.
6. **The source of the workload labels** (gibson, the mission). See the limit above.

## Develop

```
make build   # compile
make test    # unit tests
make check   # gofmt, go vet, unwired guard
```
