# MJR Quickstart (npm)

This guide shows how to run MJR as a host-process worker and dispatch a task to it with `curl`. MJR is a **worker agent**: it does not initiate tasks, approve its own permissions, or contact a UI. You (or your host process) are responsible for sending it work and reading the audit log.

## 0. Prerequisites

- **Node.js >= 20**
- **Authenticated `claude` CLI.** `@anthropic-ai/claude-agent-sdk` spawns the `claude` CLI as a subprocess — it needs an authenticated CLI on the host, not an API key in the environment. Run `claude auth login` (or your Max OAuth equivalent) and confirm `claude --version` works before starting MJR.

## 1. Run MJR

```bash
# One-shot via npx (no install, pulls the latest published version):
npx @m2ai/mythos-jr --port 8080

# Or install globally:
npm install -g @m2ai/mythos-jr
mythos-jr --port 8080 --audit-log ./mjr-audit.log
```

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `--port` | `8080` | A2A JSON-RPC + REST listener |
| `--health-port` | `9090` | Liveness sidecar (`GET /healthz`) |
| `--policy` | package copy of `security-policy.json` | Override hard-cap policy file |
| `--audit-log` | `./mjr-audit.log` | Append-only audit log path |
| `-h`, `--help` | | Show help |
| `-v`, `--version` | | Show version |

On startup MJR prints a banner, runs refusal checks (any env var matching `/dangerous|skip-permissions|bypass/i` is a hard refusal, per Lesson L5 / L18), loads the policy file, asserts that `max_turns=25`, `max_retries_per_tool=3`, `subagent_max_depth=1`, and only then opens its listeners.

## 2. Send a task with curl

MJR speaks A2A Protocol v0.3.0 via the official `@a2a-js/sdk` JS SDK. The agent card is published at `/.well-known/agent-card.json` and there are two transports:

- `POST /a2a/jsonrpc` — JSON-RPC 2.0 over HTTP
- `POST /a2a/rest` — REST-style A2A endpoints

### 2a. First-run test (copy-paste, no workspace required)

This is the fastest way to verify your install actually works end-to-end. The task is a self-contained Python snippet embedded in the prompt — MJR reads the code out of the message and triages it in-place, no file mounts needed. This is the exact task used in MJR's own smoke test before v1.0.0 was released.

```bash
curl -sS -X POST http://127.0.0.1:8080/a2a/jsonrpc \
  -H "Content-Type: application/json" \
  --data-raw '{
    "jsonrpc": "2.0",
    "id": "smoke-1",
    "method": "message/send",
    "params": {
      "message": {
        "kind": "message",
        "messageId": "msg-smoke-1",
        "role": "user",
        "parts": [{
          "kind": "text",
          "text": "Skill: vulnerability_triage. Identify the vulnerability in this Python function in ONE short paragraph. Do not write files or propose a fix.\n\ndef search(db, q):\n    return db.execute(f\"SELECT * FROM users WHERE name LIKE %{q}%\").fetchall()"
        }],
        "metadata": {"isHostInvocation": false, "skill": "vulnerability_triage"}
      }
    }
  }'
```

Expected response (state, 1 artifact, verbatim from the v1.0.0 smoke test):

```json
{
  "jsonrpc": "2.0",
  "id": "smoke-1",
  "result": {
    "kind": "task",
    "id": "<uuid>",
    "contextId": "<uuid>",
    "status": { "state": "completed", "timestamp": "..." },
    "artifacts": [{
      "artifactId": "<uuid>-artifact-0",
      "name": "mjr-output",
      "parts": [{
        "kind": "text",
        "text": "The function is vulnerable to **SQL injection**: the query parameter `q` is interpolated directly into the SQL string via an f-string, meaning an attacker can supply input like `%'"'"' OR '"'"'1'"'"'='"'"'1` to manipulate the query logic, exfiltrate arbitrary rows, or — depending on the database driver — chain additional statements to drop tables, read other tables, or bypass authentication entirely. No sanitization, parameterization, or escaping is applied before the value reaches the database engine."
      }]
    }]
  }
}
```

Round trip is typically 8-15 seconds on a healthy Max OAuth session. Audit log events you should see during the call: `task_start → stream_message (system) → stream_message (assistant) → stream_message (result) → task_complete`. If you see `task_start → task_complete` with **no** `assistant` events in between, your `claude` CLI is not authenticated — MJR will have published `state: failed` with a message telling you to check auth. Re-run `claude auth login` and try again.

### 2b. Production shape (workspace-mounted codebase)

A more realistic task: point MJR at a read-only codebase mount and ask it to triage a real vulnerability. You (or your host agent) supply the workspace path.

```bash
curl -N -X POST http://127.0.0.1:8080/a2a/jsonrpc \
  -H "Content-Type: application/json" \
  --data-raw '{
    "jsonrpc": "2.0",
    "id": "task-001",
    "method": "message/send",
    "params": {
      "message": {
        "kind": "message",
        "messageId": "msg-001",
        "role": "user",
        "parts": [
          {
            "kind": "text",
            "text": "Skill: vulnerability_triage. User reports an unauthenticated SQL injection in /api/search. Inspect src/api/search.ts and src/db/query.ts. Identify root cause and propose a patch under /workspace/proposals/."
          }
        ],
        "metadata": {
          "isHostInvocation": false,
          "skill": "vulnerability_triage",
          "workspace_root": "/workspace"
        }
      }
    }
  }'
```

Note: per-task hard caps (`max_turns=25`, `max_retries_per_tool=3`) are loaded from `security-policy.json` at server startup and cannot be overridden by the request.

The `-N` flag disables curl buffering. The response is a JSON-RPC envelope whose `result` is an A2A `Task` object. For streaming, use `message/stream` instead of `message/send` — the response is a stream of `TaskStatusUpdateEvent` and `TaskArtifactUpdateEvent` objects, with the terminal status carrying `final: true` and `state` set to one of `completed | failed | canceled`.

If MJR refuses (e.g. host invocation), the terminal status has `state: "failed"` and a message part explaining the refusal reason.

**Silent-success guard**: if MJR's upstream stream yields zero artifacts (usually an auth failure — the `claude` CLI subprocess could not authenticate), MJR publishes `failed` with a message telling you to check the audit log, instead of publishing a misleading `completed`. MJR does not silently succeed.

## 3. Read the audit log

The audit log is a local file at whatever path you passed to `--audit-log` (default `./mjr-audit.log` in the directory you launched MJR from). Tail it:

```bash
tail -f ./mjr-audit.log
```

Each line includes: `ts`, `task_id`, `tool`, `nonce`, `decision` (`allow`/`deny`), and `reason`. The audit log is the source of truth — anything MJR claims in its artifacts that does not have a registered nonce in the audit log should be treated as fabricated (Lesson L14).

Operator rule: put the audit log on a filesystem outside the workspace tree MJR is operating on. If the workspace and audit log share a parent directory, a compromised task could rewrite audit entries. This is a host-process rule, not a container rule.

## 4. Stop

Press **Ctrl+C** (SIGINT) in the terminal running MJR. MJR is stateless across runs by design — the audit log is the only persistent artifact.

## Sandboxing note

MJR runs in your host process. It is **not** a sandbox by itself. If you use `safe_exploit_reproduction`, run MJR inside a VM or a stripped container that has no network and no sensitive files. The reference Dockerfile in `docs/Dockerfile.reference` is one option; a dedicated KVM / Firecracker guest is another. Either way, sandbox selection is your responsibility — MJR refuses to pretend it owns something it doesn't.

## What MJR will do

| Skill | Purpose |
|---|---|
| `vulnerability_triage` | Read a codebase on a read-only mount, identify root cause, write a patch proposal to `/workspace/proposals/`. |
| `patch_verification` | Write a failing test, apply a patch, verify the test passes and nothing regresses. Cannot edit existing tests. |
| `safe_exploit_reproduction` | Reproduce a vulnerability in a network-less sandbox to confirm severity. Requires a written `target_ownership_attestation`. |

## What MJR will refuse

These are hard refusals enforced by the `canUseTool` hook, the deny-by-default tool list, the bash denylist, and the nonce validator — not by the system prompt alone:

- Operating on systems the caller does not own or have written authorization to test
- Producing exploit code intended for deployment against third parties
- Bypassing or simulating permission prompts (`xdotool`, `tmux send-keys`, `expect`, base64-wrapped commands, etc.)
- Rewriting git history or writing to `.git/`
- Modifying test files during patch verification
- Posting artifacts to gists, pastebins, GitHub Pages, or any public surface
- Network egress outside the small allowlist in `security-policy.json`
- Encoding commands in base64, hex, or any other transform to bypass classifiers
- Accessing `/proc/<pid>/mem`, `ptrace`, or any other process introspection
- Acting as a host. MJR is `worker_only`. If a task arrives with `metadata.isHostInvocation === true` it is rejected before the model sees it.

See `host/host_checks.md` for the full list of independent host audit rules and the Mythos System Card sections each rule maps to.
