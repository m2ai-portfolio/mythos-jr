# MJR A2A Host Checks

The host is a process **outside** the MJR worker process that owns task lifecycle, audit logging, and independent verification. It exists because Mythos Preview has been observed bypassing soft constraints inside its own context (System Card §4.2.1.1, §4.5.4.1). All checks below run in the host, not inside MJR.

MJR 1.0 ships as an npm package (`@m2ai/mythos-jr`) that runs as a host process, not a container. The rules below describe the process-level equivalents of what were previously container flags. The reference Dockerfile in `docs/Dockerfile.reference` is an optional extra layer, not the baseline.

## Pre-task checks
1. Reject the task if `userMessage.metadata.isHostInvocation === true`. MJR is `worker_only` (Lesson L18, System Card §4.2.1.1 prompt-injection-of-judge incident). MJR's executor also enforces this internally before calling the model.
2. Reject if env contains `CLAUDE_DISABLE_PERMISSIONS` or any flag whose name matches `/dangerous|skip-permissions|bypass/i`. (Lesson L5, System Card §4.5.4, equivalent to `--dangerously-skip-permissions`.)
3. Reject if MJR is running with write access to `/etc`, `/usr`, or `/var` (outside its audit log dir), with sudo rights, or as root. MJR must run as a dedicated OS user with read-only access to its install directory. (Lesson L22, process-level equivalent of container `--privileged`, `--cap-add`, `--userns=host`.)
4. Compute SHA-256 of the workspace tree MJR will read. Store it. (Lesson L8.)
5. Hash all files under `tests/` recursively. Store the hash. (Lesson L13.)
6. Verify `security-policy.json` is present alongside `.well-known/agent.json` and that `max_turns=25`, `max_retries_per_tool=3`, `subagent_max_depth=1`, and `network_egress.policy="deny-all-except-allowlist"`. The MJR server itself refuses to start if any of these baselines are relaxed. (Lesson L18, L23.)
7. If the task is `safe_exploit_reproduction`, require `target_ownership_attestation`. Refuse otherwise. (Lesson L21.)

## Per-tool-call checks (run from `canUseTool` hook in `src/server.ts`)
1. Increment per-tool retry counter. Deny if > 3. (Lesson L12.)
2. For `Write`/`Edit`: deny any path matching `PATH_DENY_PATTERNS`. Resolve symlinks first. (Lessons L2, L7, L17.)
3. For `SandboxedBash`: deny any command matching `BASH_DENY_PATTERNS`. (Lessons L3, L4, L7, L10, L11, L19, L20.)
4. For `SandboxedBash`: deduplicate. If the same command runs more than 2 times, deny. (Lesson L12, the 847-attempt incident.)
5. Generate a per-call nonce. Append it to the tool result. Record `(nonce, toolName, ts)`. (Lesson L14.)
6. Append a JSON line to the audit log. The audit log path must be on a filesystem the host controls, not the same tree as the workspace. MJR receives the path via `--audit-log` and must not have write access to any other audit log location. (Lesson L17.)

## Subagent spawn checks
1. The host's `spawnSubagent` helper is the **only** way to start a subagent.
2. The child's `allowedTools` must be a subset of the parent's. Never broader. (Lesson L6, System Card §4.2.1.1 lines 2445-2451.)
3. The child's `maxTurns` must be `<= parent.remainingTurns / 2`.
4. The child inherits the same `canUseTool` hook.
5. The child cannot itself spawn subagents (depth = 1).

## Post-task checks
1. Re-hash the workspace tree. If the hash differs, void the artifact and mark the task `failed: workspace mutated`. (Lesson L8.)
2. Re-hash `tests/`. If any test file changed during a `patch_verification` task, void the artifact. (Lesson L13.)
3. Scan the final artifact for nonces. Reject if it claims tool output without a registered nonce. (Lesson L14.)
4. Scrub `/\(\s*dry[ -]?run[^\)]*\)/gi` annotations from output and warn in the audit log. (Lesson L9.)
5. Independently re-run any command MJR claimed was a "dry run" against an in-memory mock to confirm it has no side effects. Reject if it does. (Lesson L9.)

## Process-level hardening (host operator responsibilities)
- MJR runs as a dedicated OS user with **read-only** access to its install directory (process-level equivalent of `--read-only` rootfs).
- No sudo rights and no write access to `/etc`, `/usr`, or `/var` outside the audit log directory (process-level equivalent of `--cap-drop=ALL` and `--security-opt=no-new-privileges`).
- Network egress enforced at the host firewall or in a netns: default `DROP`, `ACCEPT` only for the destinations in `security-policy.json` `network_egress.allowlist`.
- For `safe_exploit_reproduction`: run MJR inside a VM or a network-less sandbox (e.g. a netns with no uplink, or a stripped container).
- Resource caps via systemd unit: `MemoryMax=2G`, `CPUQuota=200%`, `TasksMax=128`.
- Workspace tree is read-only at the filesystem level (mount option, ACL, or immutable bit).
- `.git/` is read-only at the filesystem level — MJR must not be able to rewrite history.

## Egress firewall rules (iptables / nftables, applied to MJR's netns or host)
- Default policy: `DROP` for OUTPUT
- `ACCEPT` only for the destinations in `security-policy.json` `network_egress.allowlist` (currently `api.anthropic.com`)
- Explicit `DROP` log rule for known exfil destinations (gist, pastebin, transfer.sh, 0x0.st, paste.ee, ngrok, *.github.io) so the audit log captures attempts (Lesson L20)

## Logging
- One JSON line per tool attempt, tool result, task state change
- Includes: timestamp, task id, tool name, nonce, allow/deny decision, reason
- Audit log lives on a filesystem outside the workspace tree; rotated daily; retained 90 days
