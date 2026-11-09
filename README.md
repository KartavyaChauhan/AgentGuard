# AgentGuard

A task-aware MCP runtime security gateway that combines least-privilege intent enforcement, resource validation, data-flow provenance, behavioral analysis, tool-integrity checks, unified trust decisions, and tamper-evident auditing.

```
AI Agent
   ↓
┌──────────────────────────┐
│     AgentGuard Gateway   │
├──────────────────────────┤
│  Intent + Least Privilege│
│  Policy / Resource Check │
│  Data Flow Inspection    │
├──────────────────────────┤
│  ↓ ALLOW or ✕ DENY      │
└──────────────────────────┘
   ↓ (only if allowed)
Tool Execution (upstream MCP)
   ↓
Behavior / Risk / Trust
   ↓
Tamper-Evident Audit
```

## Why AgentGuard?

AI agents can invoke tools, access sensitive resources, and chain individually valid actions into dangerous workflows. A simple per-tool allow/deny list is not enough — an agent that reads `.env`, runs a shell command, and then makes an HTTP request has executed three individually permitted actions that together constitute credential exfiltration.

AgentGuard evaluates the **full behavioral context** of agent actions at runtime. It enforces authorization *before* upstream execution so that denied requests produce zero side effects.

## Demo

```
$ uv run agentguard demo

========================================
Scenario: SAFE DEVELOPMENT
========================================
Tool calls:
  [+] read_file(path='app.py')
  [+] write_file(path='app.py', content='safe code')
  [+] run_tests(test_status='passed')

AgentGuard:  TRUSTED          Risk: LOW

========================================
Scenario: SECRET EXFILTRATION
========================================
Tool calls:
  [x] read_file(path='.env')         ← BLOCKED by deny-read-env

AgentGuard:  BLOCKED          Risk: HIGH

========================================
Scenario: SUSPICIOUS CHAIN
========================================
Tool calls:
  [+] read_file(path='app.py')
  [+] shell(command='...')
  [x] http_request(url='...')        ← BLOCKED (suspicious chain)

AgentGuard:  BLOCKED          Risk: MEDIUM
```

## Core Capabilities

- **MCP Runtime Gateway** — intercepts and proxies Model Context Protocol tool execution
- **Task-Aware Intent Enforcement** — binds agent capabilities to the current authorized task
- **Capability-Level Authorization** — enforces least-privilege resource access
- **Path/URL/Resource Restrictions** — statically and dynamically validates arguments
- **Data-Flow/Provenance Tracking** — tracks sensitive data through the execution lifecycle
- **Behavioral Sequence Analysis** — detects dangerous action chains (read credentials → shell → network)
- **Trajectory Risk Scoring** — accumulates dynamic risk over the session lifetime
- **Outcome/Evidence Verification** — asserts verification steps before critical operations
- **MCP Tool Integrity/Rug-Pull Detection** — detects malicious mutation of tool definitions
- **Tamper-Evident Audit Trail** — cryptographically hash-chains audit events
- **Adversarial Security Benchmarks** — evaluates defenses against red-team evasion suites

## Quickstart

```bash
git clone https://github.com/KartavyaChauhan/AgentGuard.git
cd AgentGuard
uv sync
uv run pytest -q
```

Run the demos and benchmarks:
```bash
uv run agentguard demo              # interactive security scenarios
uv run agentguard adversarial       # 45-case authorization benchmark
uv run agentguard redteam           # 12-scenario red-team evasion suite
uv run agentguard audit attack      # 10-case tamper detection benchmark
uv run agentguard security-gate     # unified regression gate
```

## Architecture

AgentGuard acts as an intermediary MCP server. When an AI client requests a tool execution, the request passes through the **Gateway**, which evaluates it against the **Policy Engine**, **Trust Engine**, and current **Task Intent**. Invariant checks (**Behavior Analyzer**, **Risk Engine**) run pre-execution. If authorized, the request is forwarded to the upstream MCP server. Both the request and result are persisted in the **Event Store** for tamper-evident auditing.

The critical design constraint: **enforcement occurs before upstream execution**. A denied request never reaches the upstream server and produces zero side effects.

## Security Benchmarks

Synthetic internal benchmarks. All results are from the current repository.

**PREVENTED** = blocked before upstream execution (zero side effects).
**DETECTED** = identified after execution via behavioral/integrity analysis.

| Benchmark | Cases | Prevented | Detected | Missed |
| --- | --- | --- | --- | --- |
| Adversarial Authorization | 45 | 45 | — | 0 |
| Red-Team Evasion | 12 | 10 | 2 | 0 |
| Audit Tampering | 10 | — | 10 | 0 |
| Full Test Suite | 591 | — | — | 0 failures |

**Red-Team detail:**
- 10 attacks **PREVENTED** pre-execution (secret exfiltration, credential theft, suspicious chains, privilege escalation, destructive commands, force push)
- 2 attacks **DETECTED** post-execution (repeated-failure pattern, tool poisoning)
- 0 dangerous upstream side effects
- 0 false positives
- 0 critical misses

## Security Model

- **Pre-execution Enforcement**: Authorization checks run *before* upstream execution. Denied requests produce zero upstream side effects.
- **Context-Bound Authorization**: Task intent dynamically restricts which capabilities and resources are accessible.
- **Deterministic Enforcement**: The current security path is fully deterministic — it does not rely on an LLM to make authoritative security decisions.
- **Isolated Auditing**: Audit persistence operates as a side-channel, independent of the enforcement critical path. A persistence failure cannot block or delay a security decision.
- **Tamper-Evident History**: Audit records are hash-chained to detect subsequent modification.
- **Data Sanitization**: Sensitive inputs and credentials are scrubbed before audit persistence.

## Known Limitations

- **Local Persistence**: The SQLite audit database provides cryptographic tamper-evidence, but is not physically immutable against an attacker with host OS root privileges.
- **Secret Detection**: Deterministic secret detection relies on entropy and format matching, which cannot identify every possible obfuscated secret format.
- **Behavioral Rules**: Rules catch known malicious chains, but do not constitute a complete generalized anomaly detector.
- **Benchmark Scope**: Results are from synthetic internal benchmarks and do not establish universal security guarantees against novel attack vectors.
- **Semantic Analysis**: AgentGuard's current enforcement path is deterministic; it does not rely on an LLM to make authoritative security decisions.

## GitHub Security Recommendations

For deployments and forks of this repository, we recommend enabling:
- **Dependabot** for automated dependency updates
- **Secret Scanning / Push Protection** to prevent credential leakage
- **Code Scanning** (e.g., CodeQL) for static analysis

## Development

```bash
uv run pytest                       # run full test suite
uv run pytest --cov                 # run with coverage
uv run agentguard --help            # list all CLI commands
uv run agentguard security-gate     # unified security regression gate
```

### Project Structure
- `src/agentguard/` — core gateway, policy, intent, execution, and audit engines
- `tests/` — unit and integration test suite (591 tests)
- `benchmarks/` — adversarial scenario definitions
- `examples/` — usage examples and rug-pull demos

## License

MIT — see [LICENSE](LICENSE).
