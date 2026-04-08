// Mythos Jr (MJR) — A2A server (@a2a-js/sdk) + Claude Agent SDK invocation
//
// Implements lessons L1, L2, L3, L4, L5, L6, L9, L10, L11, L12, L14, L17, L18, L19, L23
// from PLAN.md. Every guard here is a HARD barrier (deny-by-default), not a prompt clause.
// The verbatim Anthropic anti-hacking system prompt lives in ../system_prompt.md and is
// loaded at startup. Hardening parameters live in ../security-policy.json and are loaded
// at startup as the source of truth (replaces hardcoded constants).

import { query } from "@anthropic-ai/claude-agent-sdk";
import {
  AgentCard,
  Message,
  AGENT_CARD_PATH,
  Task,
  TaskStatusUpdateEvent,
  TaskArtifactUpdateEvent,
} from "@a2a-js/sdk";
import {
  AgentExecutor,
  RequestContext,
  ExecutionEventBus,
  DefaultRequestHandler,
  InMemoryTaskStore,
} from "@a2a-js/sdk/server";
import {
  agentCardHandler,
  jsonRpcHandler,
  restHandler,
  UserBuilder,
} from "@a2a-js/sdk/server/express";
import express from "express";
import pino from "pino";
import * as fs from "node:fs";
import * as path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import * as http from "node:http";

// ---------------------------------------------------------------------------
// Startup refusals — L5, L18. Exported so the CLI entry point can run them
// BEFORE any heavy module state is initialized. Also invoked defensively
// from startServer() as belt-and-braces.
// ---------------------------------------------------------------------------
export function runStartupRefusalChecks(): void {
  // L18: refuse to run as a host agent
  if (process.env.MJR_IS_HOST_AGENT === "true") {
    // eslint-disable-next-line no-console
    console.error("MJR is worker-only. Refusing to start as host agent.");
    process.exit(1);
  }
  // L5: refuse to run with permissions disabled (equivalent of --dangerously-skip-permissions)
  if (process.env.CLAUDE_DISABLE_PERMISSIONS) {
    // eslint-disable-next-line no-console
    console.error("CLAUDE_DISABLE_PERMISSIONS detected. Refusing to start.");
    process.exit(1);
  }
  for (const k of Object.keys(process.env)) {
    if (/dangerous|skip-permissions|bypass/i.test(k)) {
      // eslint-disable-next-line no-console
      console.error(
        `Refusing to start: env var ${k} matches dangerous/skip-permissions/bypass.`,
      );
      process.exit(1);
    }
  }
}

// ---------------------------------------------------------------------------
// Security policy types — L12, L23.
// ---------------------------------------------------------------------------
interface SecurityPolicy {
  version: string;
  sandbox_required: boolean;
  network_egress: {
    policy: string;
    allowlist: string[];
    denylist_note: string;
  };
  refuses: string[];
  max_turns: number;
  max_retries_per_tool: number;
  subagent_max_depth: number;
}

// Hard caps — populated from security-policy.json in startServer().
// Exposed as `let` so the CLI can resolve the policy path before server boot.
let MAX_TURNS = 25;
let MAX_RETRIES_PER_TOOL = 3;
let SUBAGENT_MAX_DEPTH = 1;
const MAX_DUPLICATE_BASH_INVOCATIONS = 2; // L12 — hardcoded, never in policy file

let securityPolicy: SecurityPolicy | null = null;

// ---------------------------------------------------------------------------
// System prompt — verbatim Anthropic anti-hacking core + MJR extensions.
// Loaded from the package install root (resolved relative to this module file)
// or from an explicit CLI override.
// ---------------------------------------------------------------------------
let SYSTEM_PROMPT = "";

function resolvePackageFile(relative: string): string {
  // Resolve a file that ships inside the npm package tarball. At runtime this
  // module lives in dist/server.js, so the package root is one level up.
  return new URL(`../${relative}`, import.meta.url).pathname;
}

// ---------------------------------------------------------------------------
// Denylists — every entry traces to a specific Mythos lesson
// ---------------------------------------------------------------------------
const BASH_DENY_PATTERNS: RegExp[] = [
  /\bbase64\s+-d\b/, /\bxxd\s+-r\b/, /\beval\b/,                                    // L11
  /\bxdotool\b/, /tmux\s+send-keys/, /\bexpect\b/, /screen\s+-X/,                   // L4
  /\bgit\s+(filter-branch|reset\s+--hard|update-ref|reflog\s+expire|gc\b|push\s+--?force|push\s+-f|commit\s+--amend)/, // L7
  /\brm\s+-rf?\b/, /\bkill\s+-9\b/, /\bpkill\b/, /systemctl\s+(stop|disable|mask)/, // L19
  /\bdocker\s+(stop|rm|kill|exec)\b/, /\btruncate\b/, /\bshred\b/,                  // L19
  /\/proc\/\d+\/(mem|maps|fd)/, /\bgdb\b/, /\bstrace\b/, /PTRACE_ATTACH/,           // L3
  /\bcurl\b.*(gist\.github|pastebin|transfer\.sh|0x0\.st|paste\.ee)/,               // L20
];

const PATH_DENY_PATTERNS: RegExp[] = [
  /^\/proc\b/, /^\/sys\b/, /^\/dev\b/, /^\/etc\b/, /^\/root\b/,                     // L2, L17
  /\.git\/(?!config$)/, /\.ssh\//, /\.bashrc$/, /\.profile$/, /crontab$/,           // L7, L17
  /^\/var\/log\/mjr/,                                                               // L17 audit log
];

// L10: shell metacharacters that enable side-channels.
const SHELL_METACHAR_PATTERNS: RegExp[] = [
  /\$\(/, /`/, /;/, /&&/, /\|\|/, /(^|[^|])\|([^|]|$)/,
];

// Tiny allowlist of "safe" full-command patterns for SandboxedBash. If a command does
// not match this list AND contains shell metacharacters, it is rejected outright.
const SAFE_BASH_ALLOWLIST: RegExp[] = [
  /^make(\s+\w[\w-]*)*\s*$/,
  /^pytest(\s+[\w./-]+)*\s*$/,
  /^cargo\s+test(\s+[\w./-]+)*\s*$/,
  /^npm\s+test(\s+[\w./-]+)*\s*$/,
  /^npm\s+run\s+test(\s+[\w./-]+)*\s*$/,
];

// ---------------------------------------------------------------------------
// Sanitizers / checks — L2, L7, L10, L17
// ---------------------------------------------------------------------------
function sanitizeBashArg(cmd: string): string {
  // L10: strip metacharacters that enable side-channels unless on the tiny allowlist.
  const trimmed = cmd.trim();
  if (SAFE_BASH_ALLOWLIST.some((re) => re.test(trimmed))) {
    return trimmed;
  }
  let cleaned = trimmed;
  for (const re of SHELL_METACHAR_PATTERNS) {
    cleaned = cleaned.replace(new RegExp(re.source, "g"), " ");
  }
  return cleaned;
}

function checkBash(cmd: string): { allow: boolean; reason?: string } {
  const trimmed = cmd.trim();
  for (const p of BASH_DENY_PATTERNS) {
    if (p.test(trimmed)) return { allow: false, reason: `denied: ${p}` };
  }
  // L10: any command containing shell metacharacters must be on the safe allowlist.
  const hasMeta = SHELL_METACHAR_PATTERNS.some((re) => re.test(trimmed));
  if (hasMeta && !SAFE_BASH_ALLOWLIST.some((re) => re.test(trimmed))) {
    return { allow: false, reason: "shell metacharacters not on safe allowlist" };
  }
  return { allow: true };
}

function checkPath(p: string): { allow: boolean; reason?: string } {
  if (!p) return { allow: false, reason: "empty path" };
  let resolved: string;
  try {
    // Resolve symlinks first when the path exists, otherwise fall back to logical resolve.
    resolved = fs.existsSync(p) ? fs.realpathSync(p) : path.resolve(p);
  } catch {
    resolved = path.resolve(p);
  }
  if (!resolved.startsWith("/workspace")) {
    return { allow: false, reason: "outside workspace" };
  }
  for (const re of PATH_DENY_PATTERNS) {
    if (re.test(resolved)) return { allow: false, reason: `denied path: ${re}` };
  }
  return { allow: true };
}

// ---------------------------------------------------------------------------
// L14: nonce injection. Every tool result is tagged with a per-call nonce.
// Final artifacts are scanned; any claim referencing tool output without a real
// nonce is rejected.
// ---------------------------------------------------------------------------
function makeNonce(): string {
  return randomBytes(8).toString("hex");
}
const nonceLog: Map<string, { tool: string; ts: number }> = new Map();

function registerNonce(tool: string): string {
  const n = makeNonce();
  nonceLog.set(n, { tool, ts: Date.now() });
  return n;
}

function validateNonces(text: string, log: Map<string, { tool: string; ts: number }>): boolean {
  // Find every nonce-shaped token in the text. If the artifact references a tool nonce
  // that does not exist in the registry, reject. Artifacts that do not reference any
  // tool output (no nonce mentioned) are allowed through.
  const candidates = text.match(/\bmjr-nonce-[0-9a-f]{16}\b/g) ?? [];
  for (const c of candidates) {
    const id = c.replace(/^mjr-nonce-/, "");
    if (!log.has(id)) return false;
  }
  return true;
}

// L9: scrub fake "(dry run)" annotations from output before streaming to the client.
function scrubFakeDryRun(content: string): string {
  return content.replace(/\(\s*dry[ -]?run[^\)]*\)/gi, "");
}

// ---------------------------------------------------------------------------
// Audit logger — initialized in startServer() with a CLI-configured path.
// ---------------------------------------------------------------------------
let auditLogger: pino.Logger = pino({ level: "info" }); // placeholder until startServer()

// ---------------------------------------------------------------------------
// L12: per-task retry counters and bash dedupe set
// ---------------------------------------------------------------------------
const retryCounts: Map<string, number> = new Map();
const bashSeen: Map<string, number> = new Map();

// ---------------------------------------------------------------------------
// canUseTool — SDK hook that runs before every tool call.
// All hard barriers gate here; the model cannot bypass them.
// ---------------------------------------------------------------------------
type CanUseToolDecision =
  | { behavior: "allow"; updatedInput: Record<string, unknown> }
  | { behavior: "deny"; message: string };

async function canUseTool(
  toolName: string,
  input: Record<string, unknown>,
): Promise<CanUseToolDecision> {
  auditLogger.info({ event: "tool_attempt", toolName, input });

  // L12 retry cap
  const k = `${toolName}:${JSON.stringify(input).slice(0, 200)}`;
  retryCounts.set(k, (retryCounts.get(k) ?? 0) + 1);
  if ((retryCounts.get(k) ?? 0) > MAX_RETRIES_PER_TOOL) {
    const msg = `retry cap (${MAX_RETRIES_PER_TOOL}) exceeded for ${toolName}`;
    auditLogger.warn({ event: "tool_denied", toolName, reason: msg });
    return { behavior: "deny", message: msg };
  }

  // L2, L7, L17: path guard for Write/Edit
  if (toolName === "Write" || toolName === "Edit") {
    const c = checkPath(String(input.file_path ?? input.path ?? ""));
    if (!c.allow) {
      auditLogger.warn({ event: "tool_denied", toolName, reason: c.reason });
      return { behavior: "deny", message: c.reason! };
    }
  }

  // L3, L4, L7, L10, L11, L19, L20: bash guard for SandboxedBash
  if (toolName === "SandboxedBash") {
    const cmd = String(input.command ?? "");
    const c = checkBash(cmd);
    if (!c.allow) {
      auditLogger.warn({ event: "tool_denied", toolName, reason: c.reason });
      return { behavior: "deny", message: c.reason! };
    }
    const seen = (bashSeen.get(cmd) ?? 0) + 1;
    bashSeen.set(cmd, seen);
    if (seen > MAX_DUPLICATE_BASH_INVOCATIONS) {
      const msg = "duplicate bash invocation cap exceeded";
      auditLogger.warn({ event: "tool_denied", toolName, reason: msg });
      return { behavior: "deny", message: msg };
    }
    // Sanitized form is what actually runs.
    const sanitized = sanitizeBashArg(cmd);
    const nonce = registerNonce(toolName);
    return {
      behavior: "allow",
      updatedInput: { ...input, command: sanitized, mjr_nonce: `mjr-nonce-${nonce}` },
    };
  }

  // Native Bash is denied at the disallowedTools layer; this is defense in depth.
  if (toolName === "Bash") {
    const msg = "native Bash tool is disallowed; only SandboxedBash is permitted";
    auditLogger.warn({ event: "tool_denied", toolName, reason: msg });
    return { behavior: "deny", message: msg };
  }

  // L14: tag every other allowed call with a nonce too.
  const nonce = registerNonce(toolName);
  return {
    behavior: "allow",
    updatedInput: { ...input, mjr_nonce: `mjr-nonce-${nonce}` },
  };
}

// ---------------------------------------------------------------------------
// L6: subagent spawning. Inherit parent permission set; never broaden it.
// Subagent depth = SUBAGENT_MAX_DEPTH (1). Children cannot themselves spawn.
// ---------------------------------------------------------------------------
interface PermissionCtx {
  systemPrompt: string;
  allowedTools: string[];
  disallowedTools: string[];
  remainingTurns: number;
  depth: number;
}

function spawnSubagent(parentCtx: PermissionCtx, taskInstr: string) {
  if (parentCtx.depth >= SUBAGENT_MAX_DEPTH) {
    throw new Error(
      `subagent depth cap exceeded (max=${SUBAGENT_MAX_DEPTH})`,
    );
  }
  return query({
    prompt: taskInstr,
    options: {
      model: "claude-sonnet-4-6",
      systemPrompt: parentCtx.systemPrompt,                   // identical
      allowedTools: parentCtx.allowedTools,                   // identical, never broader
      disallowedTools: parentCtx.disallowedTools,
      maxTurns: Math.min(Math.floor(parentCtx.remainingTurns / 2), 10),
      permissionMode: "default",
      canUseTool,                                             // identical hook
    },
  });
}

// ---------------------------------------------------------------------------
// MJR AgentExecutor — the @a2a-js/sdk equivalent of the old onTask callback.
// ---------------------------------------------------------------------------
class MjrExecutor implements AgentExecutor {
  async execute(
    requestContext: RequestContext,
    eventBus: ExecutionEventBus,
  ): Promise<void> {
    const { taskId, contextId, userMessage, task } = requestContext;
    const now = (): string => new Date().toISOString();

    // Reset per-task state
    retryCounts.clear();
    bashSeen.clear();
    nonceLog.clear();

    // ---- Publish initial Task if not already created by the request handler ----
    if (!task) {
      const initialTask: Task = {
        kind: "task",
        id: taskId,
        contextId,
        status: {
          state: "submitted",
          timestamp: now(),
        },
        history: [userMessage],
      };
      eventBus.publish(initialTask);
    }

    // L18: refuse host-mode invocations BEFORE the model sees anything.
    const meta = (userMessage.metadata ?? {}) as Record<string, unknown>;
    if (meta.isHostInvocation === true) {
      const failed: TaskStatusUpdateEvent = {
        kind: "status-update",
        taskId,
        contextId,
        status: {
          state: "failed",
          message: {
            kind: "message",
            messageId: randomUUID(),
            role: "agent",
            taskId,
            contextId,
            parts: [
              {
                kind: "text",
                text: "MJR refuses host-agent invocations. MJR is worker_only (Lesson L18).",
              },
            ],
          },
          timestamp: now(),
        },
        final: true,
      };
      auditLogger.warn({ event: "task_refused", taskId, reason: "host_invocation" });
      eventBus.publish(failed);
      eventBus.finished();
      return;
    }

    // ---- Publish 'working' status update ----
    const working: TaskStatusUpdateEvent = {
      kind: "status-update",
      taskId,
      contextId,
      status: { state: "working", timestamp: now() },
      final: false,
    };
    eventBus.publish(working);

    // ---- Extract task instructions from the user message text parts ----
    const instructions = (userMessage.parts ?? [])
      .filter((p): p is { kind: "text"; text: string } => (p as { kind?: string }).kind === "text")
      .map((p) => p.text)
      .join("\n")
      .trim();

    auditLogger.info({ event: "task_start", taskId, instructions });

    if (!instructions) {
      const failed: TaskStatusUpdateEvent = {
        kind: "status-update",
        taskId,
        contextId,
        status: {
          state: "failed",
          message: {
            kind: "message",
            messageId: randomUUID(),
            role: "agent",
            taskId,
            contextId,
            parts: [{ kind: "text", text: "no text instructions in user message" }],
          },
          timestamp: now(),
        },
        final: true,
      };
      eventBus.publish(failed);
      eventBus.finished();
      return;
    }

    let artifactIndex = 0;
    try {
      const stream = query({
        prompt: `<verbatim_instructions>\n${instructions}\n</verbatim_instructions>`, // L16
        options: {
          model: "claude-sonnet-4-6",
          systemPrompt: SYSTEM_PROMPT,
          allowedTools: ["Read", "Write", "Edit", "SandboxedPython", "SandboxedBash"],
          disallowedTools: ["WebFetch", "WebSearch", "Bash"], // L1, L10, L20 — native Bash forbidden
          permissionMode: "default",                            // L5
          maxTurns: MAX_TURNS,                                  // L12
          canUseTool,
        },
      });

      for await (const message of stream) {
        const mtype = (message as { type?: string }).type;
        auditLogger.info({ event: "stream_message", type: mtype });
        if (mtype === "assistant") {
          // SDKAssistantMessage.message is a BetaMessage whose content is an
          // array of content blocks. Pull out text blocks only.
          const nested = (message as { message?: { content?: Array<{ type?: string; text?: string }> } }).message;
          const blocks = Array.isArray(nested?.content) ? nested!.content : [];
          const raw = blocks
            .filter(b => b?.type === "text" && typeof b.text === "string")
            .map(b => String(b.text))
            .join("\n")
            .trim();
          if (!raw) continue; // skip assistant events with no text (e.g. tool-use-only turns)
          // L9: scrub fake "(dry run)" annotations from artifacts
          const cleaned = scrubFakeDryRun(raw);
          // L14: validate nonces if the model claims tool output
          if (!validateNonces(cleaned, nonceLog)) {
            throw new Error("artifact references tool output with no matching nonce");
          }
          const artifactEvent: TaskArtifactUpdateEvent = {
            kind: "artifact-update",
            taskId,
            contextId,
            artifact: {
              artifactId: `${taskId}-artifact-${artifactIndex++}`,
              name: "mjr-output",
              parts: [{ kind: "text", text: cleaned }],
            },
            append: artifactIndex > 1,
            lastChunk: false,
          };
          eventBus.publish(artifactEvent);
        }
      }

      // --- Silent-success guard (Mythos lesson: do NOT publish completed with
      // zero artifacts). If we streamed nothing, that is almost always an auth
      // failure or an upstream stream error, not a real success. Fail loud. ---
      if (artifactIndex === 0) {
        const noArtifactMsg =
          "MJR produced no artifacts — likely auth failure or upstream stream error. Check audit log. MJR does not silently succeed.";
        auditLogger.error({ event: "task_no_artifacts", taskId, reason: noArtifactMsg });
        const failed: TaskStatusUpdateEvent = {
          kind: "status-update",
          taskId,
          contextId,
          status: {
            state: "failed",
            message: {
              kind: "message",
              messageId: randomUUID(),
              role: "agent",
              taskId,
              contextId,
              parts: [{ kind: "text", text: noArtifactMsg }],
            },
            timestamp: now(),
          },
          final: true,
        };
        eventBus.publish(failed);
        return;
      }

      const completed: TaskStatusUpdateEvent = {
        kind: "status-update",
        taskId,
        contextId,
        status: { state: "completed", timestamp: now() },
        final: true,
      };
      eventBus.publish(completed);
      auditLogger.info({ event: "task_complete", taskId });
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      auditLogger.error({ event: "task_failed", taskId, error: errMsg });
      const failed: TaskStatusUpdateEvent = {
        kind: "status-update",
        taskId,
        contextId,
        status: {
          state: "failed",
          message: {
            kind: "message",
            messageId: randomUUID(),
            role: "agent",
            taskId,
            contextId,
            parts: [{ kind: "text", text: errMsg }],
          },
          timestamp: now(),
        },
        final: true,
      };
      eventBus.publish(failed);
    } finally {
      eventBus.finished();
    }
  }

  cancelTask = async (): Promise<void> => {
    // No long-running side effects to clean up; the SDK stream is GC'd.
  };
}

// ---------------------------------------------------------------------------
// startServer — entry point called from cli.ts. Loads policy, wires up the
// A2A handler, starts express on `config.port` and a liveness sidecar on
// `config.healthPort`. Resolves once listeners are up.
// ---------------------------------------------------------------------------
export interface StartServerConfig {
  port: number;
  healthPort: number;
  policyPath: string;
  auditLogPath: string;
}

export async function startServer(config: StartServerConfig): Promise<void> {
  // Belt-and-braces: CLI runs these first, but run again in case startServer
  // is ever called from a test or another entry point without the CLI guard.
  runStartupRefusalChecks();

  // ---- Load security policy from the CLI-resolved path ----
  try {
    securityPolicy = JSON.parse(
      fs.readFileSync(config.policyPath, "utf8"),
    ) as SecurityPolicy;
  } catch (err) {
    throw new Error(
      `Failed to load security-policy.json at ${config.policyPath}: ${String(err)}`,
    );
  }

  MAX_TURNS = securityPolicy.max_turns;
  MAX_RETRIES_PER_TOOL = securityPolicy.max_retries_per_tool;
  SUBAGENT_MAX_DEPTH = securityPolicy.subagent_max_depth;

  // Sanity assertions: refuse to start if policy was relaxed below baseline
  if (MAX_TURNS !== 25) {
    throw new Error(`MAX_TURNS must be 25 (security baseline). Got ${MAX_TURNS}.`);
  }
  if (MAX_RETRIES_PER_TOOL !== 3) {
    throw new Error(
      `MAX_RETRIES_PER_TOOL must be 3 (security baseline). Got ${MAX_RETRIES_PER_TOOL}.`,
    );
  }
  if (SUBAGENT_MAX_DEPTH !== 1) {
    throw new Error(
      `SUBAGENT_MAX_DEPTH must be 1 (security baseline). Got ${SUBAGENT_MAX_DEPTH}.`,
    );
  }

  // ---- Load system prompt (package-local; not CLI-overridable) ----
  const systemPromptPath = resolvePackageFile("system_prompt.md");
  try {
    SYSTEM_PROMPT = fs.readFileSync(systemPromptPath, "utf8");
  } catch (err) {
    throw new Error(
      `Failed to load system prompt at ${systemPromptPath}: ${String(err)}`,
    );
  }
  if (SYSTEM_PROMPT.trim().length === 0) {
    throw new Error("System prompt is empty. Refusing to start.");
  }

  // ---- Load agent card (package-local) ----
  const agentCardFsPath = resolvePackageFile(".well-known/agent.json");
  let mjrAgentCard: AgentCard;
  try {
    mjrAgentCard = JSON.parse(
      fs.readFileSync(agentCardFsPath, "utf8"),
    ) as AgentCard;
  } catch (err) {
    throw new Error(
      `Failed to load agent card at ${agentCardFsPath}: ${String(err)}`,
    );
  }

  // ---- Initialize audit logger on the CLI-provided path ----
  auditLogger = pino(
    { level: "info" },
    pino.destination({ dest: config.auditLogPath, sync: false, mkdir: true }),
  );
  auditLogger.info({
    event: "server_boot",
    policyPath: config.policyPath,
    auditLogPath: config.auditLogPath,
  });

  // ---- Wire up DefaultRequestHandler + Express app ----
  const requestHandler = new DefaultRequestHandler(
    mjrAgentCard,
    new InMemoryTaskStore(),
    new MjrExecutor(),
  );

  const app = express();
  app.use(express.json({ limit: "1mb" }));

  app.use(`/${AGENT_CARD_PATH}`, agentCardHandler({ agentCardProvider: requestHandler }));
  app.use("/a2a/jsonrpc", jsonRpcHandler({ requestHandler, userBuilder: UserBuilder.noAuthentication }));
  app.use("/a2a/rest", restHandler({ requestHandler, userBuilder: UserBuilder.noAuthentication }));

  app.listen(config.port, () => {
    auditLogger.info({ event: "server_listen", port: config.port });
  });

  // ---- Liveness probe — sidecar HTTP server on healthPort. -------------------
  // Returns a static {"status":"ok"} and nothing else. No auth, no DB, no task
  // queue, no config, no env, no model name exposure. Liveness only; readiness
  // is intentionally out of scope.
  // -----------------------------------------------------------------------------
  const healthServer = http.createServer((req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"status":"ok"}');
      return;
    }
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("not found");
  });
  healthServer.listen(config.healthPort);
}

// Exported for tests / host audit reuse — no runtime effect.
export {
  MAX_TURNS,
  MAX_RETRIES_PER_TOOL,
  MAX_DUPLICATE_BASH_INVOCATIONS,
  SUBAGENT_MAX_DEPTH,
  BASH_DENY_PATTERNS,
  PATH_DENY_PATTERNS,
  sanitizeBashArg,
  checkBash,
  checkPath,
  makeNonce,
  validateNonces,
  scrubFakeDryRun,
  canUseTool,
  spawnSubagent,
  securityPolicy,
};
