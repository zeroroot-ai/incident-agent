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
| `internal/cause` | One model call, one finding of the cause, and the `CAUSED_BY` link. | done, tested with fakes |
| `internal/emit` | The records on the Incident node and the cause link. | done, tested with fakes |
| `internal/read` | The read of one incident. | not served: the daemon has no incident read for an agent |
| `internal/pass` | Assembles one task and runs it against the harness. | done, tested over gRPC against a fake callback service |
| `internal/dispatch` | The launch contract: grant, callback endpoint, task. | done, tested with a fake environment |
| Tasks `triage` and `reach` | Join an alert to an Incident, and record what it reaches. | not built |
| Image build | Build, cosign signature and SBOM. | `.github/workflows/image.yml`, runs on `main` |
| Catalog manifest | The entry in `gibson` that makes the agent dispatchable. | not in this repo |
| End to end on kind | One alert from a mock tool to a contained incident. | not built |

## Open items

These items need a change in another repo.

1. **The incident read.** The harness callback service has no call that reads an incident. The daemon has the queries (`internal/platform/incidentreport`), but only the tenant API serves them. Add a harness call, for example `IncidentFacts(incident_key)`, that returns the alerts (`PART_OF`), the places that they reach (`AFFECTS`, with the label and the key), the causes (`CAUSED_BY`, with the status that the daemon set), and the properties of the Incident node. Until it exists, each task fails with `ErrKnowledgeUnavailable`.
2. **The id of a submitted finding.** `SubmitFinding` returns no id. The cause step reads the findings of the mission and takes the one with its title. The title holds a hash of the incident key. The daemon should return the id.
3. **The remediation of a finding.** The harness callback of the daemon drops `remediation` (`protoFindingToFinding`). The cause step also puts the fix in the description.
4. **The error code of a tool call.** The SDK gives the message of a refused call and not its code. The agent matches the words of the daemon. A typed error in the SDK would remove the text match.
5. **The fix loop and the cause.** The fix loop reads the findings of one Application. The finding of the cause names its place with `AFFECTS` (an `Account` or a `Host`), and no Application reaches that place yet. The fix loop must also take a finding that an Incident names with `CAUSED_BY`.
6. **The writer of the places.** No code writes the `AFFECTS` edge from an alert to an `Account` or a `Host` with the key `connector=<id>|vendor_id=<id>`. The intake agent writes an alert with its title and detail only.
7. **The report of a refusal.** The incident report of the daemon classifies `metatool: not authorized to invoke tool` as `failed`, not `refused`, because its match looks for "permission denied" or "grant".

## Develop

```
make build   # compile
make test    # unit tests
make check   # gofmt, go vet, unwired guard
```
