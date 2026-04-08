#!/usr/bin/env node
// Mythos Jr CLI entry point. Small by design: parse args, run refusals,
// print banner, hand off to startServer(). No extra deps.

import * as path from "node:path";
import { runStartupRefusalChecks, startServer } from "./server.js";

const VERSION = "1.0.0";

interface CliArgs {
  port: number;
  healthPort: number;
  policy: string;
  auditLog: string;
  help: boolean;
  version: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  // Package-local default for security-policy.json when --policy is not passed.
  const defaultPolicy = new URL("../security-policy.json", import.meta.url).pathname;
  const args: CliArgs = {
    port: 8080,
    healthPort: 9090,
    policy: defaultPolicy,
    auditLog: path.resolve(process.cwd(), "mjr-audit.log"),
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--port":
        args.port = Number(argv[++i]);
        break;
      case "--health-port":
        args.healthPort = Number(argv[++i]);
        break;
      case "--policy":
        args.policy = path.resolve(argv[++i]);
        break;
      case "--audit-log":
        args.auditLog = path.resolve(argv[++i]);
        break;
      case "-h":
      case "--help":
        args.help = true;
        break;
      case "-v":
      case "--version":
        args.version = true;
        break;
      default:
        console.error(`unknown argument: ${a}`);
        process.exit(2);
    }
  }
  return args;
}

function printHelp(): void {
  console.log(`mythos-jr v${VERSION}

Usage:
  mythos-jr [--port N] [--health-port N] [--policy PATH] [--audit-log PATH]

Options:
  --port N          A2A listener port (default 8080)
  --health-port N   Liveness sidecar port (default 9090)
  --policy PATH     security-policy.json (default: package copy)
  --audit-log PATH  Append-only audit log (default ./mjr-audit.log)
  -h, --help        Show this help
  -v, --version     Show version

Mythos Jr is a non-initiating defensive cybersec worker. Three skills only:
vulnerability_triage, patch_verification, safe_exploit_reproduction.
Requires an authenticated \`claude\` CLI on the host.`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    process.exit(0);
  }
  if (args.version) {
    console.log(VERSION);
    process.exit(0);
  }

  // Run refusals BEFORE any heavy import chains run on startServer().
  runStartupRefusalChecks();

  // Banner
  console.error(
    `Mythos Jr v${VERSION} — non-initiating defensive cybersec worker. Three skills only. Refuses everything else.`,
  );

  try {
    await startServer({
      port: args.port,
      healthPort: args.healthPort,
      policyPath: args.policy,
      auditLogPath: args.auditLog,
    });
  } catch (err) {
    console.error(`mythos-jr: startup failure: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

process.on("SIGINT", () => {
  console.error("mythos-jr: SIGINT received, shutting down.");
  process.exit(0);
});
process.on("SIGTERM", () => {
  console.error("mythos-jr: SIGTERM received, shutting down.");
  process.exit(0);
});
process.on("unhandledRejection", (reason) => {
  console.error(`mythos-jr: unhandled rejection: ${String(reason)}`);
  process.exit(2);
});
process.on("uncaughtException", (err) => {
  console.error(`mythos-jr: uncaught exception: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
});

main();
