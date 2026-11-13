# Changelog

All notable changes to Mythos Jr (MJR) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Tool checkpoint was skipped for Read, Write and Edit.** They were listed in `allowedTools`, and the Agent SDK does not call `canUseTool` for pre-approved tools. Measured on the pinned SDK 0.2.94: a write outside `/workspace` succeeded with zero `tool_attempt` lines. `allowedTools` is now empty, so the retry cap and the path guard run.
- **Path guard boundary.** `startsWith("/workspace")` also accepted `/workspace-evil/...`. The guard now requires the root itself or a child of it, and resolves symlinks on the nearest existing parent for files that do not exist yet.
- **Listeners bound to every interface** with no authentication, while the README said `127.0.0.1`. Both now bind to `127.0.0.1` by default.
- `canUseTool` no longer adds an `mjr_nonce` key to the input of built-in tools.
- `docs/Dockerfile.reference` entrypoint pointed at `dist/server.js`, which starts nothing. It now runs `dist/cli.js --host 0.0.0.0` (not rebuilt or run for this change).

### Added
- `--host ADDR` (default `127.0.0.1`) and `--workspace DIR` (default `/workspace`).
- `settingSources: []` on the SDK query, so user, project and local Claude Code settings cannot pre-approve tools.

### Known, unchanged
- `Read` has no path guard. Reads inside the working directory are not sent to `canUseTool` at all.
- Still no test suite. The fixes above were checked with one live task (one write inside the workspace allowed, two outside refused and logged).

## [1.0.0] - 2026-04-07

Initial release. Non-initiating defensive cybersecurity worker agent derived from lessons documented in the Claude Mythos Preview System Card (2026-04-07).

### Added
- **Core A2A server** built on `@a2a-js/sdk` v0.3.0 with JSON-RPC and REST transports on port 8080.
- **Liveness sidecar** on port 9090 exposing `GET /healthz`.
- **Three skills** — `vulnerability_triage`, `patch_verification`, `safe_exploit_reproduction`. Everything else is refused.
- **Claude Agent SDK integration** pinned to `@anthropic-ai/claude-agent-sdk@0.2.94`. Model hardcoded to `claude-sonnet-4-6`.
- **Verbatim Anthropic anti-hacking system prompt** from System Card §4.2.2.2 plus 14 MJR-specific extensions.
- **`canUseTool` hook** wired into every `query()` call, enforcing bash denylist, path guards, nonce validation, retry caps, and audit logging.
- **`security-policy.json`** as the single source of truth for runtime hard caps (`max_turns=25`, `max_retries_per_tool=3`, `subagent_max_depth=1`) and the network egress allowlist.
- **Startup refusal checks** — MJR refuses to start if `MJR_IS_HOST_AGENT=true`, if `CLAUDE_DISABLE_PERMISSIONS` is set, or if any env var matches `/dangerous|skip-permissions|bypass/i`.
- **Empty-stream → failed** guard. If the Agent SDK stream yields zero text artifacts, MJR publishes `state: failed` with an explicit reason. No silent-success fallthrough. This is the exact Mythos failure mode the system card warns about, and it surfaced in MJR's first smoke test before being fixed.
- **Subagent spawn helper** enforcing permission inheritance — a child's `allowedTools` must be a subset of its parent's, never broader. Subagent depth capped at 1.
- **Per-tool-call nonce validation** — every tool result is tagged with a nonce; artifacts referencing tool output without a matching nonce are rejected as fabricated.
- **Fake-dry-run regex scrubber** that strips `(dry run)` annotations from streamed artifacts.
- **pino audit logger** writing one JSON line per tool call, tool result, task state transition, and refusal. Log path is host-supplied via `--audit-log` so a compromised task can't overwrite it.
- **npm package** `@m2ai/mythos-jr` (public, MIT) with a `mythos-jr` binary entry point.
- **Reference Dockerfile** at `docs/Dockerfile.reference` for advanced users willing to mount their authenticated `~/.claude/` credentials. Not the primary distribution.
- **Documentation** — `README.md`, `docs/QUICKSTART.md` (install, boot, curl example), `docs/HOST_INTEGRATION.md` (A2A Task schema and host audit responsibilities), `host/host_checks.md` (the rules the host MUST enforce), `PLAN.md` (the full Mythos-lesson → mitigation table with system card citations), `ROADMAP.md`.

### Verified
- **End-to-end smoke test** against a live `claude-sonnet-4-6` backend via the user's authenticated `claude` CLI subprocess. Task: SQL injection triage against an in-prompt Python snippet. MJR returned a correct, scoped-to-one-paragraph root-cause analysis in ~9 seconds. Audit log captured the full `system → assistant → rate_limit → result → task_complete` stream.

### Known limitations
- **No built-in host.** MJR is a worker only. You must supply a host agent to dispatch A2A tasks.
- **No built-in sandbox.** MJR runs as a host process. For `safe_exploit_reproduction`, run MJR itself inside a VM or stripped container.
- **Docker is reference-only.** The `docs/Dockerfile.reference` works but requires mounting `~/.claude/` credentials, which is not ergonomic for distribution.
- **7 moderate severity vulnerabilities** in transitive npm dependencies (deferred to v1.1.0 — `npm audit fix` requires breaking changes).
- **No test suite.** `vitest` is a dev dependency but no tests ship in v1.0.0 (deferred to v1.1.0).

[1.0.0]: https://github.com/m2ai-portfolio/mythos-jr/releases/tag/v1.0.0
