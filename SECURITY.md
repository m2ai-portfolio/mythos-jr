# Security Policy

## Reporting a vulnerability

Mythos Jr is a defensive security tool. If you find a flaw that weakens its hardening or creates a new attack surface, please report it privately before disclosing publicly.

**Preferred**: Open a [GitHub Security Advisory](https://github.com/m2ai-portfolio/mythos-jr/security/advisories/new) on this repository. This is the fastest path and keeps the discussion private until a fix is ready.

**Alternative**: Email the maintainer at `matthew+mjr-security@memyselfplusai.com` with the word `SECURITY` in the subject line. PGP key on request.

### What to include

- A clear description of the flaw and which Mythos lesson (if any) from `PLAN.md` it undermines
- Reproduction steps — minimal proof-of-concept preferred
- Affected version (`mythos-jr --version` or `package.json`)
- Your assessment of severity and blast radius
- Whether you've already disclosed to anyone else

### What you can expect

- Acknowledgement within 48 hours
- A working triage or a clear "not a vulnerability" explanation within 7 days
- A patch release for verified flaws as fast as I can reasonably turn it around
- Public credit in the changelog and advisory (if you want it)

### What is in scope

- Bypasses of any hardening documented in `PLAN.md` (bash denylist, path guards, retry caps, subagent inheritance, nonce validation, audit log tamper, etc.)
- Ways to make MJR produce a `state: completed` result without having actually done the work (silent success — the exact Mythos failure mode MJR exists to prevent)
- Ways to smuggle out-of-scope tasks past the refusal logic
- Ways to cause MJR to initiate action on its own without a host-dispatched task (the worker-only invariant)
- Ways to modify source code, tests, or `.git/` during a task run
- Ways to exfiltrate data outside the `security-policy.json` egress allowlist
- Ways to bypass the permission-inheritance check on spawned subagents

### What is out of scope

- Vulnerabilities in third-party dependencies without a working exploit against MJR (report those upstream)
- Vulnerabilities requiring physical access to an already-compromised host
- Social engineering of the operator
- Denial of service via excessive task submission (rate-limit that at your host agent)
- Weaknesses in the underlying Claude model itself — those belong to Anthropic's [model safety reporting channel](https://www.anthropic.com/)
- Gaps in features MJR explicitly doesn't have yet (bundled UI, native host, published Docker image — see `ROADMAP.md`)

## Operator responsibilities

MJR's hardening is real but incomplete without host-side enforcement. If you run MJR, you are responsible for:

1. **Running MJR as a dedicated OS user** with read-only access to its install directory and no sudo rights.
2. **Keeping the audit log on a filesystem MJR cannot write to directly** — a task could otherwise tamper with its own audit trail.
3. **Enforcing the egress allowlist** at the host firewall or network namespace level. MJR declares the allowlist in `security-policy.json`; it does not configure your firewall for you.
4. **Running MJR inside a VM or network-less container for `safe_exploit_reproduction`** tasks. MJR is a host process, not a sandbox.
5. **Implementing the host audit rules in `host/host_checks.md`** — retry cap enforcement, `.git` protection, dry-run probes, subagent permission inheritance. These run *outside* MJR because anything inside MJR's process can theoretically be subverted by the model.
6. **Keeping the `claude` CLI authenticated** as the user MJR runs under. A compromised auth token compromises MJR.

## The one thing you must never do

**Do not make MJR proactive.** MJR is intentionally a non-initiating worker. It only executes tasks dispatched to it by a host agent. Merging the decider and the doer into a single process rebuilds exactly the architectural shape that produced the Mythos failure modes documented in the system card and mitigated by every single hardening rule in this repository.

If you find yourself writing a cron that calls MJR's A2A endpoint on a schedule without a host agent in the middle, you are recreating the failure mode. Add the host agent. Let the host be the one that decides *when* and *what*. Keep MJR as the thing that only answers when asked.

## Disclosure philosophy

This project publishes its threat model (`PLAN.md` has 23 documented Mythos lessons and their mitigations). Keeping vulnerabilities private beyond a reasonable patch window does not protect users — it just gives attackers a head start. I will coordinate disclosure timelines in good faith, but the default is public disclosure as soon as a fix is shipped.
