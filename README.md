# AgentGuard

Task-aware runtime security for AI agents and MCP tool execution.

AgentGuard provides a defense-in-depth, runtime security gateway that inspects and authorizes tool executions based on behavioral analysis, task intent, and dynamic risk scoring.

```text
AI Agent
   ↓
MCP Gateway
   ↓
Intent + Least Privilege
   ↓
Policy / Resource Validation
   ↓
Data Flow Inspection
   ↓
Tool Execution
   ↓
Behavior / Risk / Trust
   ↓
Tamper-Evident Audit
```

## Why AgentGuard?

AI agents can invoke tools, access sensitive resources, and chain individually valid actions into dangerous workflows. Traditional static access controls and simple per-tool allow/deny lists are insufficient to protect against sophisticated attacks like prompt injection, malicious tool chaining, or data exfiltration. AgentGuard evaluates the holistic context of agent actions at runtime to detect and prevent dangerous behavioral trajectories.

## Core Capabilities

- **MCP Runtime Gateway**: Intercepts and proxies Model Context Protocol (MCP) tool execution.
- **Task-Aware Intent Enforcement**: Binds agent capabilities strictly to the current authorized task intent.
- **Capability-Level Authorization**: Enforces least-privilege resource access.
- **Path/URL/Resource Restrictions**: Statically and dynamically restricts arguments.
- **Data-Flow/Provenance Tracking**: Tracks sensitive data as it moves through the execution lifecycle.
- **Behavioral Sequence Analysis**: Identifies known dangerous chains (e.g., read credentials -> execute shell -> external network request).
- **Trajectory Risk Scoring**: Accumulates a dynamic risk score over the session lifetime.
- **Outcome/Evidence Verification**: Asserts required verification steps are taken before critical operations.
- **MCP Tool Integrity/Rug-Pull Detection**: Prevents malicious injection into the tool definitions.
- **Tamper-Evident Audit Trail**: Cryptographically hashes and links audit events for irrefutable history.
- **Adversarial Security Benchmarks**: Evaluates defenses against an evolving suite of red-team evasions.

## Quickstart

```bash
git clone https://github.com/KartavyaChauhan/AgentGuard.git
cd AgentGuard
uv sync
uv run pytest -q
```

Useful commands:
```bash
uv run agentguard demo
uv run agentguard adversarial
uv run agentguard redteam
uv run agentguard audit attack
uv run agentguard security-gate
```

## Architecture

AgentGuard acts as an intermediary MCP Server. When an AI client requests a tool execution, the request passes through the **Gateway**. The Gateway evaluates the tool and its arguments against the **Policy Engine** and the **Trust Engine**. It determines the current **Task Intent** and runs invariant checks (such as **Behavior Analyzer** and **Risk Engine**) pre-execution. If the action is permitted, it is forwarded to the upstream MCP Server, and the result is safely returned. Both the request and result are persisted immutably in the **Event Store** for tamper-evident auditing.

## Security Benchmarks

These are synthetic internal benchmarks demonstrating AgentGuard's resilience against known evasion and tampering techniques.

| Benchmark | Cases | Result |
| --- | --- | --- |
| Adversarial Authorization | 45 | 45 blocked |
| Red-Team Prevention | 12 | 10 blocked, 2 detected |
| Audit Tampering | 10 | 10 detected |
| Full Test Suite | 591 | 591 passed |

*Note: Results are based on the latest internal benchmark suite.*

## Security Model

- **Pre-execution Enforcement**: Security checks are performed *before* upstream execution.
- **Zero Dangerous Upstream Side Effects**: Denied requests are blocked completely at the gateway level.
- **Context-Bound Authorization**: Task intent actively restricts which capabilities and resources can be accessed dynamically.
- **Isolated Auditing**: Audit persistence operates alongside but independently of the critical path enforcement.
- **Tamper-Evident History**: Audit records are hash-chained to detect subsequent modifications.
- **Data Sanitization**: Sensitive inputs and credentials are scrubbed before persistence.

## Known Limitations

- **Local Persistence**: The local SQLite database provides cryptographic tamper-evidence, but is not physically immutable against an attacker with host OS root privileges.
- **Secret Detection**: Deterministic secret detection relies on entropy and format matching, which cannot identify every possible obfuscated secret.
- **Anomaly Detection**: Behavioral rules catch known malicious chains, but do not represent a complete generalized anomaly detector.
- **Non-Universal**: Benchmark results do not guarantee absolute safety against all 0-day exploits or completely novel evasion vectors.
- **Semantic Limits**: LLM semantic analysis (when configured) provides heuristic value but is not currently treated as an authoritative enforcement mechanism.

## GitHub Security Recommendations

For deployments and forks of this repository, we strongly recommend enabling:
- Dependabot for dependency updates
- Secret Scanning and Push Protection
- Code Scanning (e.g., CodeQL)

## Development

Run tests and coverage:
```bash
uv run pytest
uv run pytest --cov
```

Run CLI tools:
```bash
uv run agentguard --help
```

### Project Structure
- `src/agentguard/`: Core gateway, policy, intent, execution, and audit engines.
- `tests/`: Extensive unit and integration test suite.
- `benchmarks/`: Adversarial definitions and scenarios.

## License

AgentGuard is licensed under the MIT License.
