# CLAUDE.md: incident-agent

Short guidance for Claude Code and other AI coders in this directory.
**Read [AGENTS.md](./AGENTS.md) for the full Gibson contract.**

## Local dev loop

| Command | What it does |
|---|---|
| `make build` | Compile the binary. |
| `make test` | Run the unit tests. |
| `make check` | Run the guards that CI runs on a pull request. |
| `make run` | Run the binary once. Set the launch contract first. |

The agent is dispatched for each mission run. It is not enrolled.

## Things not to do

- Do not add a response action outside `internal/respond/connectors.go`.
- Do not build a tool id from a value of the graph or of a tool result.
- Do not retry a refused call.
- Do not make the agent say that an incident is resolved. The daemon and the incident report decide that.
- Do not add `replace` directives to `go.mod` or a `go.work`.
- Do not commit `~/.gibson/`, `host_key` or `runtime.json`.

## Writing

All prose uses Simplified Technical English: short common words, active voice, one instruction per sentence, no contractions, no semicolons.
