# AGENTS.md: incident-agent

This directory is a **Gibson agent** for a blue team. Gibson dispatches it. It launches the image once for each mission run, and the process runs one task and exits.
This file is the contract. If this file and the code disagree, the code wins.

## What the agent does

The agent contains an incident that the security tools of the buyer detected. It uses only the response actions that the security team of the buyer granted. It sends the cause of the incident to the fix loop. It runs no attack.

One dispatch is one task on one incident. The task context names both.

| Task | What the agent does | Package |
|---|---|---|
| `contain` | Reads the incident and its records. Skips each target that the agent contained already. Makes each other containment action one time: revoke the sessions of an identity, disable an account, isolate a host. | `internal/contain`, `internal/respond` |
| `cause` | Raises one finding for the cause of the incident and links the Incident to it with `CAUSED_BY`. | `internal/cause` |
| `release` | Releases each containment that the daemon confirms the agent made, after the cause finding that this agent raised is `verified`. | `internal/contain` |
| `isolate` | Opens and merges a merge request in the GitOps repo of the buyer. It adds a policy of the kind that the dispatch names (`cilium`, `cluster` or `networkpolicy`) that denies ingress and egress for the labels of one workload as far as the kind can express (the kinds `cluster` and `networkpolicy` have gaps, and the report and an Incident record state them), and a lock file. It merges a merge request only when it is in the configured project, on the expected branch, at the head commit that the host returned, and when its changed files equal the change that the agent wrote. | `internal/isolate` |
| `release_workload` | After the cause finding that this agent raised is `verified` and that carries its author and tags, opens and merges a merge request that removes both files. It closes an isolation merge request that never merged. | `internal/isolate` |

Each task writes what it did on the Incident node (`internal/emit`).

## How a response action runs

The agent calls the meta-tool `invoke_tool` with the canonical id `mcp:<connector>:<tool>` and one argument, the vendor id of the target. The daemon decides. It checks the grant (`can_execute`), the mission deny list and the approval mark of the manifest before the call reaches the connector (ADR-0180, gibson `internal/engine/metatool`).

| Answer of the daemon | Outcome | What the agent does |
|---|---|---|
| A result that the connector confirms | `done` | Records `ir_contained_<key>_<generation>` on the Incident, with the `tool_call_id` of the call as its value. |
| `pending authorization` | `pending_authorization` | Records it and goes on with the other actions. It does not call it again in the pass. The call stays in the approval queue, and the next dispatch is its retry. |
| Not authorized, denied, blocked, run not active | `refused` | Records it. It never calls it again in the pass and does not look for a second tool with the same effect. |
| A timeout, or a transport error after the call left the agent | `unknown` | Records it and writes no `contained` record. The vendor can have taken the action. The report says so, and the next dispatch calls it again. |
| Any other error, or a result that does not confirm the action | `failed` | Records it. It does not call it again in the pass. |

The SDK gives the message of the daemon and not its code, so `respond.Classify` matches the words of the daemon (gibson#1575 adds typed codes). It reads only the text of the daemon. The text that a vendor wrote after `reported an error:` never decides an outcome, and the report does not keep it. A text that matches nothing is a failure, never a success.

## Records

Each record name has the form `ir_<state>_<key>_<generation>`. The graph projector of the daemon keeps only a property name that matches `^[A-Za-z][A-Za-z0-9_]*$` and drops each other name with no error (`safeTaxonomyLabel`, `graph_projector_neo4j.go` in gibson). So the key is the first 16 hexadecimal characters of the SHA-256 of the connector id, the tool and the vendor id. A test checks each name against a copy of that pattern.

A containment and its release are one generation. A containment after a release starts the next generation, so a second release can run.

Any writer of the graph can write a property on the Incident node or a `CAUSED_BY` edge. So the agent trusts a `contained` record only when the daemon confirms that this agent made the call with that `tool_call_id`, that tool and that target (`contain.CallChecker`). It accepts as a cause only the finding that it raised (`cause.Own`).

One pass makes at most 40 calls (`contain.MaxActions`).

## The response connectors

`internal/respond/connectors.go` is the closed table. Each row comes from `zeroroot-ai/connectors` v0.1.0 and from the manifest `*-response.yaml` in `gibson`.

| Connector id | Label | Argument | Contain | Release |
|---|---|---|---|---|
| `okta-response` | `Account` | `user_id` (20 letters and digits) | `suspend_user`, then `revoke_user_sessions` | `unsuspend_user`. A session has no undo. |
| `entra-id-response` | `Account` | `user_id` (a GUID) | `disable_account`, then `revoke_sign_in_sessions` | `enable_account`. A session has no undo. |
| `crowdstrike-response` | `Host` | `host_id` (32 hexadecimal characters) | `contain_host` | `lift_containment` |
| `defender-endpoint-response` | `Host` | `device_id` (40 hexadecimal characters) | `isolate_device` | `release_device` |
| `sentinelone-response` | `Host` | `agent_id` (10 to 24 digits) | `disconnect_from_network` | `reconnect_to_network` |

## Untrusted data

Each value from the graph and from a tool result is untrusted data.

- A place names its target in its key: the composite key of the identity properties `connector` and `vendor_id`, which is `connector=<id>|vendor_id=<id>`. The agent takes the connector only from the closed table. It sends the vendor id only after the id matches the form that the connector accepts. Any other key gets no action and a reason in the report.
- A record name on the Incident is built only from the table, a hash and a generation number.
- A record value and a cause on the Incident are trusted only after the checks of the section Records.
- The agent reads a bool or a number from a tool result, and nothing else.
- The model of the cause step writes text and picks a place by its number in a closed list. Its answer never builds a tool id and never starts a call. An answer that fails a check is refused whole.

## What the agent never does

- It never states that an incident is resolved. The daemon sets the status of the finding of the cause, and the incident report of the daemon states what happened.
- It never writes the status of a finding.
- It never reads the health signal of a contained target. A containment stops its target on purpose (ADR-0180).
- It never releases a containment that the daemon does not confirm it made.
- It never changes a cluster. It isolates a Kubernetes workload only with a merge request to the GitOps repo of the buyer, through a Git host connector (`internal/isolate`).
- It never names the cause finding as an input of the isolation merge request. The daemon would link the finding to it and set the status of the finding.

## Seams that are not built

**The incident read.** No harness call reads an incident (gibson#1573). `internal/read` returns an error that wraps `agent.ErrKnowledgeUnavailable` for each read, so each task fails with that reason. It never returns an empty incident. The README states the call that the daemon must add.

**The read of a tool call.** No harness call lets an agent read back its own tool calls. `read.Daemon.CheckCall` returns an error that wraps `agent.ErrKnowledgeUnavailable`, so a contain or release pass that finds a `contained` record fails and releases nothing. The README states the call that the daemon must add.

**The tasks `triage` and `reach`.** The mission text of gibson#1478 also gives this agent the steps "join the alert to an Incident" and "record what the alert reaches". This agent does not build them. They need the incident read, and an alert of the intake agent names its target only in free text.

## Task context

| Key | Needed | Meaning |
|---|---|---|
| `incident` | yes | The key of the Incident node. |
| `ir.task` | yes | `contain`, `cause`, `release`, `isolate` or `release_workload`. |
| `ir.workload.*`, `ir.gitops.*` | for `isolate` and `release_workload` | The workload and the GitOps repo. The README lists each key. `ir.gitops.policy_kind` has no default. |

The goal is not a fallback for the incident. The goal of a mission node is a sentence for a person, not a key. A dispatch with a missing or unknown key fails the run before any call.

## Dispatch, not enrollment

This agent is **dispatched**, not enrolled (ADR-0116). It has no bootstrap token, no host key, no `~/.gibson/agent/` state and no run loop. Gibson launches the image once for each mission run inside an ephemeral setec sandbox. It hands the agent a capability grant scoped to that tenant and run, and it reaps the sandbox when the process exits.

**The launch contract** is these seven variables. Gibson sets them, and it is the only writer of these names.

| Variable | Carries |
|---|---|
| `GIBSON_CG_JWT` | The per-dispatch capability grant. It is the whole credential. |
| `GIBSON_CALLBACK_ENDPOINT` | The address of the HarnessCallbackService to dial back. |
| `GIBSON_AGENT_TASK_B64` | The base64 protojson of the `gibson.types.v1.Task`. |
| `GIBSON_MODEL` | The model resolved for the tenant at dispatch. |
| `GIBSON_MISSION_ID` / `GIBSON_MISSION_RUN_ID` / `GIBSON_AGENT_RUN_ID` | The run scope for provenance. |

`internal/dispatch` reads it. A missing grant fails the launch. Decode the task through proto: `Task.context` is a `map<string, TypedValue>`, and a plain string read drops every key.

## Do not

- Call the daemon directly outside the harness. The harness is the contract.
- Call a connector tool other than through `invoke_tool`.
- Build a tool id, a command or a URL from a value of the graph or of a tool result.
- Retry a refused call.
- Read or write secrets through environment variables.
- Use `replace` directives in `go.mod`, or add a `go.work`. Pin the SDK by tag.
- Hand-edit the catalog manifest in `gibson`. It carries the image digest that the release produces.

## Naming

Agents follow `{domain}-{function}`. The name `incident-agent` is the name of the repo, the image and the catalog id.
