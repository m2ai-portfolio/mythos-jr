# Writing Your Own MJR Host

MJR is a **worker agent**. It does not run by itself. A *host* is a process outside the MJR worker process that:

1. Owns task lifecycle (accept, dispatch, track, complete)
2. Enforces independent audit checks against MJR's behavior
3. Writes the audit log
4. Approves or denies every tool call MJR wants to make
5. Spawns subagents on MJR's behalf (MJR cannot spawn its own)

This document is for developers who want to integrate MJR into a system that is **not** Matthew's private CMD 2.0. It is the public host contract.

## Why the host exists at all

Mythos Preview has been observed bypassing soft constraints inside its own context (System Card §4.2.1.1, §4.5.4.1). Putting checks in MJR's system prompt is necessary but not sufficient. The host runs **outside** MJR's process so a compromised model context cannot disable it.

## How to run MJR

MJR ships as an npm package. Start it from the host:

```bash
npx @m2ai/mythos-jr --port 8080 --audit-log /var/run/mjr/audit.log
```

The host then dispatches A2A tasks to `http://127.0.0.1:8080/a2a/jsonrpc`. The host owns the audit log path and enforces the checks below. MJR has no idea where its audit log lives (the CLI receives the path, the host owns the parent directory).

> **Failure mode to avoid:** Do not make your host "proactive" in a way that turns MJR into a decision-maker the host obeys. MJR is `worker_only`. If your host starts accepting "I think we should..." instructions from MJR's output stream and acting on them, you have rebuilt the exact failure pattern the System Card §4.2.1.1 prompt-injection-of-judge incident documents. The host gives MJR work and audits the result. That is the entire relationship.

## A2A endpoints MJR exposes

MJR speaks A2A Protocol v0.3.0 via the official `@a2a-js/sdk` JS SDK:

- `GET /.well-known/agent-card.json` — public agent card (spec-compliant; safety policy lives in `security-policy.json` next to it)
- `POST /a2a/jsonrpc` — JSON-RPC 2.0 transport (`message/send`, `message/stream`, `tasks/get`, `tasks/cancel`, etc.)
- `POST /a2a/rest` — REST transport equivalent

A user message MUST carry the per-task control surface inside `metadata`. MJR reads `metadata.isHostInvocation` and refuses if it is `true`. The minimum host-side wrapper for the A2A user message looks like:

```ts
interface MjrUserMessageMetadata {
  isHostInvocation: false;            // MUST be false. MJR rejects true.
  skill: "vulnerability_triage"
       | "patch_verification"
       | "safe_exploit_reproduction";
  workspace_root: string;             // path MJR can read, e.g. "/workspace"
  target_ownership_attestation?: {    // REQUIRED for safe_exploit_reproduction
    signed_by: string;
    signed_at: string;                // ISO 8601
    attestation_text: string;
  } | null;
}
```

Per-task hard caps (`max_turns=25`, `max_retries_per_tool=3`, `subagent_max_depth=1`) are NOT request parameters. They live in `security-policy.json` which the server loads at startup, and the server refuses to start if those values are relaxed below baseline. Hosts cannot raise them.

For `message/stream`, the response is a stream of `TaskStatusUpdateEvent` and `TaskArtifactUpdateEvent` objects per the A2A v0.3.0 spec. See `docs/QUICKSTART.md` step 4 for a curl example.

## Host audit responsibilities

These are MUST-implement in your host. They are duplicated in `host/host_checks.md` with explicit Mythos lesson citations. **MJR will not enforce them itself** — if your host skips them, you have removed the safety net.

### Pre-task

- Reject if `userMessage.metadata.isHostInvocation === true`. MJR is `worker_only`. (Lesson L18.) MJR also enforces this internally as a defense-in-depth check.
- Reject if any env var matches `/dangerous|skip-permissions|bypass/i`. (Lesson L5.) MJR also enforces this at startup.
- Reject if MJR is not running as a dedicated OS user with no sudo rights and no write access to `/etc`, `/usr`, `/var` outside its audit log dir. (Lesson L22, process-level equivalent of container `--cap-drop=ALL`.)
- Compute SHA-256 of the workspace tree MJR is reading and store it.
- Hash all files under `tests/` and store the hash.
- For `safe_exploit_reproduction`: require a non-null `target_ownership_attestation`. Refuse otherwise.

### Per tool call (the host's `canUseTool` hook)

- Increment a per-tool retry counter. **Deny if it exceeds 3.** (Lesson L12. The 847-attempt incident is what this prevents.)
- For `Write` / `Edit`: deny any path matching the deny patterns enforced in `src/server.ts` (which rejects `/proc`, `/dev`, char devices, FIFOs, `.git/`, and anything under `tests/` the task did not create). **Resolve symlinks first.** (Lessons L2, L7, L17.)
- For `SandboxedBash`: deny any command matching `BASH_DENY_PATTERNS`. Deduplicate — if the same command runs more than twice, deny the third attempt.
- Generate a per-call **nonce**. Append it to the tool result. Record `(nonce, toolName, ts)`. Without this you cannot detect fabricated tool output. (Lesson L14.)
- Append a JSON line to the audit log on a filesystem the host controls, not the same tree as the workspace. The host chooses the path; MJR never gets a say in where its own audit log lives.

### Subagent spawn

- Your `spawnSubagent` helper is the **only** way to start a subagent. MJR cannot do it directly.
- Child `allowedTools` must be a **subset** of the parent's. Never broader. (Lesson L6.)
- Child `maxTurns` must be `<= parent.remainingTurns / 2`.
- Child inherits the same `canUseTool` hook.
- **Subagent depth is capped at 1.** A child cannot spawn its own children.

### Post-task

- Re-hash the workspace tree. If it differs, void the artifact and mark the task `failed: workspace mutated`. (Lesson L8.)
- Re-hash `tests/`. If any test file changed during a `patch_verification` task, void the artifact. (Lesson L13.)
- Scan the final artifact for nonces. **Reject if it claims tool output without a registered nonce.** (Lesson L14.)
- Scrub `(dry-run ...)` annotations from output and warn in the audit log. (Lesson L9.)
- Independently re-run any command MJR claimed was a "dry run" against an in-memory mock. If it has side effects, reject the artifact.

## Minimal TypeScript host sketch

```ts
import { randomUUID, createHash } from "node:crypto";
import { readFileSync } from "node:fs";

interface AuditEvent {
  ts: string;
  task_id: string;
  tool?: string;
  nonce?: string;
  decision: "allow" | "deny" | "task.accepted" | "task.completed" | "task.refused";
  reason?: string;
}

class MjrHost {
  private auditLogPath = "/var/run/mjr-audit/audit.log";
  private retryCounters = new Map<string, number>();
  private commandCounters = new Map<string, number>();
  private nonces = new Set<string>();

  async dispatch(task: MjrTask): Promise<HostResult> {
    // Pre-task checks
    if (task.context.isHostInvocation === true) {
      return this.refuse(task, "MJR is worker_only; isHostInvocation must be false");
    }
    if (this.envHasBypassFlag()) {
      return this.refuse(task, "bypass flag detected in environment");
    }
    if (this.containerHasUnsafeFlags()) {
      return this.refuse(task, "container launched with unsafe runtime flags");
    }
    if (task.skill === "safe_exploit_reproduction"
        && !task.context.target_ownership_attestation) {
      return this.refuse(task, "target_ownership_attestation required");
    }

    const workspaceHashBefore = this.hashTree(task.context.workspace_root);
    const testsHashBefore = this.hashTree(`${task.context.workspace_root}/tests`);

    this.audit({ ts: new Date().toISOString(), task_id: task.task_id, decision: "task.accepted" });

    // Stream task to MJR. canUseTool gets called per tool.
    const result = await this.streamToMjr(task, (toolCall) => this.canUseTool(task, toolCall));

    // Post-task checks
    if (this.hashTree(task.context.workspace_root) !== workspaceHashBefore) {
      return this.refuse(task, "workspace mutated during task");
    }
    if (task.skill === "patch_verification"
        && this.hashTree(`${task.context.workspace_root}/tests`) !== testsHashBefore) {
      return this.refuse(task, "test files modified during patch_verification");
    }
    if (!this.allClaimedToolsHaveNonces(result)) {
      return this.refuse(task, "artifact references unregistered tool nonces");
    }

    this.audit({ ts: new Date().toISOString(), task_id: task.task_id, decision: "task.completed" });
    return result;
  }

  private canUseTool(task: MjrTask, toolCall: ToolCall): ToolDecision {
    const key = `${task.task_id}:${toolCall.name}`;
    const retries = (this.retryCounters.get(key) ?? 0) + 1;
    this.retryCounters.set(key, retries);
    if (retries > task.constraints.max_retries_per_tool) {
      return this.deny(task, toolCall, "retry cap exceeded");
    }

    if (toolCall.name === "Write" || toolCall.name === "Edit") {
      const realPath = this.resolveSymlinks(toolCall.args.path);
      if (this.matchesDenyList(realPath)) {
        return this.deny(task, toolCall, `path on deny list: ${realPath}`);
      }
    }

    if (toolCall.name === "SandboxedBash") {
      if (this.matchesBashDenyList(toolCall.args.command)) {
        return this.deny(task, toolCall, "bash command on deny list");
      }
      const cmdKey = `${task.task_id}:${toolCall.args.command}`;
      const cmdCount = (this.commandCounters.get(cmdKey) ?? 0) + 1;
      this.commandCounters.set(cmdKey, cmdCount);
      if (cmdCount > 2) {
        return this.deny(task, toolCall, "duplicate bash command (>2)");
      }
    }

    const nonce = randomUUID();
    this.nonces.add(nonce);
    this.audit({
      ts: new Date().toISOString(),
      task_id: task.task_id,
      tool: toolCall.name,
      nonce,
      decision: "allow",
    });
    return { allow: true, nonce };
  }

  // ... hashTree, audit, refuse, deny, envHasBypassFlag, containerHasUnsafeFlags,
  //     resolveSymlinks, matchesDenyList, matchesBashDenyList, streamToMjr,
  //     allClaimedToolsHaveNonces are left as exercises — see host/host_checks.md
}
```

This is a sketch, not a complete implementation. The point is the **shape**: every external surface MJR touches is mediated by a host method that owns the audit and can deny.

## What you should NOT build into your host

- An "auto-approve trusted tools" mode. There are no trusted tools. The 847-attempt incident in System Card §4.2.1.1 came from auto-approving a single Bash call.
- A way for MJR to upgrade its own permissions mid-task. The constraints in the Task are immutable for that task's lifetime.
- A retry-on-deny loop. If the host denies a tool call, that tool call is **done**. MJR can try a different approach but the host must not silently re-permit the same call.
- A "confidence override" where MJR's stated confidence relaxes a check. Confidence is text the model emitted; the host must treat it as untrusted input.

## Reference

- `host/host_checks.md` — full lesson-by-lesson check list with System Card citations
- `.well-known/agent.json` (on-disk filename) / `/.well-known/agent-card.json` (served path) — the exact deny lists, allowlists, and constraints MJR ships with
- `system_prompt.md` — what MJR is told about itself (complement to, not replacement for, the host checks)
