# MJR Roadmap

MJR 1.0 ships as a Docker image with CLI/curl usage (distribution option **B1**). Everything below is future work and not part of the 1.0 release.

## Future: B2 — Bundled web UI

A read-only inspection UI on `:8081` showing live task state, the audit log tail, the egress denylist hit log, and per-tool retry counters.

- Must remain read-only. The UI cannot create tasks, approve permissions, or modify config.
- Must run as a separate process (not in the MJR container) so a UI compromise cannot reach the agent.
- Blocked on: deciding whether to ship a static SPA bundle vs. require a host-side server.

## Future: B3 — ClaudeClaw worker adapter

A thin adapter that registers MJR as a ClaudeClaw worker so other agents in the EAC ecosystem can dispatch defensive security tasks to it.

- Blocked on: the ClaudeClaw worker plugin spec stabilizing. Today the worker contract is still in flux (see `cmd-eac-consolidation-plan`).
- The adapter must NOT give ClaudeClaw host-agent authority over MJR. MJR remains `worker_only`. ClaudeClaw becomes a host like any other.
- Audit logging is the adapter's responsibility, not MJR's.

## Future: CMD 2.0 worker tile integration

Matthew's private CMD 2.0 dashboard will get a tile that shows MJR task state, recent refusals, and the egress denylist hit log. This is private infrastructure and is **not** part of the public MJR release.

## Future: npm package publish

If/when the TypeScript host integration API stabilizes, publish a `@m2ai/mjr-host-sdk` package so host authors don't have to copy the Task schema and audit hooks by hand. Not planned until at least one external user has built a host from `docs/HOST_INTEGRATION.md`.

## Explicitly out of scope (forever, not just for now)

- A built-in host. MJR is a worker. Hosts are user-supplied. This is a security property, not a missing feature.
- Auto-approval of any permission prompt. The host approves; MJR never self-approves.
- Bundled exploit databases or CVE feeds. MJR reads what the caller mounts; it does not phone home.
- A "convenience" mode that relaxes the container hardening. The hardening IS the product.
