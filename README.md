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
| `internal/isolate` | The isolation of one Kubernetes workload and its release, as merge requests to the GitOps repo of the buyer. | done, tested with a mock Git host. The connector tool that opens the merge request does not exist yet (open item 9) |
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

9. **Isolate a Kubernetes workload** (gibson#1477). The agent builds the merge requests. Four parts are missing in other repos. See the section "Isolate a Kubernetes workload".

## Isolate a Kubernetes workload

The task `isolate` contains one workload. The task `release_workload` releases it. The agent never changes the cluster. It asks the Git host connector of the buyer (`github-fixloop` or `gitlab-fixloop`) for a merge request in the GitOps repo of the buyer.

The isolation merge request adds two files in the directory `zeroroot-containment` (or the directory that the dispatch names).

1. A NetworkPolicy with the pod selector of the workload and the policy types `Ingress` and `Egress`. It has no rule, so it denies all ingress and all egress. See https://kubernetes.io/docs/concepts/services-networking/network-policies/.
2. A lock file with the state `open`. The policy and the lock file say that nobody reverts the change while the incident is open.

The release merge request deletes both files. It runs only after the cause finding that this agent raised is `verified`. The agent learns the status the same way as the `release` task: it reads the Incident with its `CAUSED_BY` causes (`contain.HeldReason`). The daemon sets the status, and the agent only reads it. The agent does not read the health signal of an isolated workload (ADR-0180).

The mission node gives these task context keys. All are required except `ir.gitops.dir`.

| Key | Meaning |
|---|---|
| `ir.workload.namespace` | The namespace of the workload. The agent refuses `kube-system`, `kube-public` and `kube-node-lease`. |
| `ir.workload.labels` | The labels of the pods, as `key=value,key=value`. An empty list is refused, because an empty selector is the whole namespace. |
| `ir.gitops.connector` | `github-fixloop` or `gitlab-fixloop`. |
| `ir.gitops.project` | The project of the GitOps repo, for example `acme/manifests`. |
| `ir.gitops.base_branch` | The branch of the merge request target. |
| `ir.gitops.dir` | The directory for the files. The default is `zeroroot-containment`. |

Each value is checked against the rules of Kubernetes before it reaches a file. The records on the Incident are `ir_isolation_opened_`, `ir_isolated_`, `ir_release_opened_` and `ir_isolation_released_`, each with the key of the containment and a generation. The value is the merge request reference. The agent writes the opened record at once. So a dispatch after a pending merge merges the same merge request and opens no second one. The agent counts an isolation as done only when `merge_request_state` of the host says `merged`. A record that another writer forged does not change that.

What the agent calls, and what it needs from other repos:

| Tool | State | Source |
|---|---|---|
| `merge_request_state`, `merge_merge_request` | Exist in `github-fixloop` and `gitlab-fixloop` v0.2.0. | `zeroroot-ai/connectors` |
| `open_merge_request` | Does not exist. The call fails with a daemon refusal and changes nothing. | Contract below |

The contract of `open_merge_request`, for `zeroroot-ai/connectors`. The arguments are `project`, `base_branch`, `branch`, `title`, `description` and `files`. Each file has a `path`, and either `content` or `delete: true`. The result is `{"merge_request": "<reference>"}`. The same `branch` called two times opens one merge request. The tool must commit all files in one commit, and it must refuse a base branch that it did not read. Vendor endpoints: GitHub https://docs.github.com/en/rest/git/commits, https://docs.github.com/en/rest/git/refs and https://docs.github.com/en/rest/pulls/pulls#create-a-pull-request. GitLab https://docs.gitlab.com/api/commits/#create-a-commit-with-multiple-files-and-actions and https://docs.gitlab.com/api/merge_requests/#create-mr.

### Gaps that need other repos

1. **The open tool** (`zeroroot-ai/connectors`). See the contract above.
2. **The merge slot** (gibson). `merge_merge_request` has the role `merge`. The daemon runs it only when the merge request holds a granted slot. The watcher grants a slot only to a merge request that a finding names with `FIXED_BY`, and only for a finding that an Application owns. An isolation merge request has no finding, so the daemon refuses the merge today. The merge request must not name the cause finding. The daemon would then set the cause to `fixing` and could verify it by the isolation.
3. **The no-revert rule in the daemon** (gibson). The watcher reverts only a merge request that a fix job delivered for a finding. The isolation has no finding, so the watcher does not revert it today. A rule that says so, with a test, does not exist. The incident report also needs a marker to tell an isolation from a fix.
4. **The reads** (gibson#1573). Each task still needs the incident read.

## Develop

```
make build   # compile
make test    # unit tests
make check   # gofmt, go vet, unwired guard
```
