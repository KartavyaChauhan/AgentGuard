# AgentGuard

A local runtime security layer for AI agents.

AgentGuard sits between an AI agent and the tools/MCP servers it can access,
inspecting tool calls, applying security policies, and allowing or denying
actions based on configurable rules.

> **Status:** Pre-alpha — foundation + policy engine + execution pipeline.

---

## Quick Start

### Prerequisites

- Python 3.12+

### Create a virtual environment

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Install in development mode

```bash
pip install -e ".[dev]"
```

### Run the CLI

```bash
agentguard --help
agentguard --version
```

### Run the tests

```bash
pytest
```

With coverage:

```bash
pytest --cov
```

---

## Project Structure

```
agentguard/
├── src/
│   └── agentguard/
│       ├── __init__.py      # Package version (from metadata)
│       ├── cli.py           # Command-line interface
│       ├── config.py        # Runtime configuration
│       ├── logging.py       # Structured JSON logging
│       ├── policy/
│       │   ├── __init__.py  # Public API
│       │   ├── models.py    # ToolRequest, PolicyDecision, enums
│       │   ├── rules.py     # Rule types (ToolName, ArgumentPattern, Approval)
│       │   ├── engine.py    # PolicyEngine — deterministic evaluation
│       │   └── defaults.py  # Demo/test rule set
│       └── execution/
│           ├── __init__.py  # Public API
│           ├── models.py    # ExecutionResult, ExecutionStatus
│           └── executor.py  # ToolExecutor — enforcement boundary
├── tests/
│   ├── test_smoke.py        # Smoke / integration tests
│   ├── test_policy.py       # Policy engine tests
│   └── test_execution.py    # Execution pipeline tests
├── pyproject.toml
├── README.md
├── .gitignore
└── .env.example
```

---

## Policy Engine

The policy engine evaluates tool calls against a set of deterministic rules
and returns one of three decisions: **ALLOW**, **DENY**, or **REQUIRE_APPROVAL**.

```python
from agentguard.policy import PolicyEngine, ToolRequest
from agentguard.policy.defaults import DEFAULT_RULES

engine = PolicyEngine(rules=DEFAULT_RULES)
```

### Example — ALLOW (no rule matches)

```python
request = ToolRequest(tool_name="list_files", arguments={"dir": "/tmp"})
decision = engine.evaluate(request)
# decision.action == PolicyAction.ALLOW
```

### Example — DENY (reads .env file)

```python
request = ToolRequest(tool_name="read_file", arguments={"path": ".env"})
decision = engine.evaluate(request)
# decision.action == PolicyAction.DENY
# decision.rule_id == "deny-read-env"
```

### Example — REQUIRE_APPROVAL

```python
request = ToolRequest(tool_name="git_push_force")
decision = engine.evaluate(request)
# decision.action == PolicyAction.REQUIRE_APPROVAL
# decision.rule_id == "approve-force-push"
```

Rules are evaluated by **priority** (highest first). Equal-priority rules
preserve **declaration order**. If a rule raises an exception, the engine
**fails closed** (DENY) for that rule rather than crashing.

---

## Execution Pipeline

The execution layer enforces policy decisions before tool invocation:

```
ToolRequest  →  PolicyEngine  →  ToolExecutor  →  ExecutionResult
```

```python
from agentguard.policy import PolicyEngine, ToolRequest
from agentguard.policy.defaults import DEFAULT_RULES
from agentguard.execution import ToolExecutor

def add(a: int, b: int) -> int:
    return a + b

engine = PolicyEngine(rules=DEFAULT_RULES)
executor = ToolExecutor(policy_engine=engine, tools={"add": add})
```

### Example — EXECUTED

```python
result = executor.execute(ToolRequest(tool_name="add", arguments={"a": 2, "b": 3}))
# result.status == ExecutionStatus.EXECUTED
# result.output == 5
```

### Example — DENIED (tool never runs)

```python
result = executor.execute(ToolRequest(tool_name="read_file", arguments={"path": ".env"}))
# result.status == ExecutionStatus.DENIED
# result.output is None  — tool was never invoked
```

## Session Event Store

AgentGuard includes an in-memory event store that records every tool execution attempt. This session-aware tracking provides a chronological history of actions, which serves as the foundation for future behavioral risk analysis, session anomaly detection, and auditing.

**Architecture Pipeline:**
```text
ToolRequest
    ↓
PolicyEngine
    ↓
ToolExecutor
    ↓
EventStore
    ↓
Session history
```

If a tool is executed, blocked, or requires approval, the `ToolExecutor` automatically records a `ToolEvent` (including duration and status) without modifying the original request.

---

## Behavioral Analysis

While individual policies evaluate a single tool request (e.g., `tool call → ALLOW`), deterministic behavioral analysis evaluates sequences of events to identify suspicious patterns that a single rule might miss.

For example, accessing credentials might be permitted, and making a network request might be permitted, but doing both in the same session could indicate data exfiltration:

```text
event 1 (read_file ".env")
   ↓
event 2 (base64_encode)
   ↓
event 3 (http_request "evil.com")
   ↓
possible suspicious sequence (CRITICAL)
```

The sequence analysis engine inspects the chronological order of executed events and returns deterministic `BehaviorFinding`s when suspicious chains are detected.

> **Note:** AgentGuard currently uses deterministic behavioral rules. Machine-learning/LLM-based analysis is not part of this step.

---

## Outcome Evidence

An allowed tool call proves that an action executed, but it does NOT prove that the intended outcome occurred. 

For example, a tool execution like `run_tests → EXECUTED` does not automatically mean that the outcome `tests_passed` was achieved. 

AgentGuard evaluates a `TaskContract` against the session's event history to deterministically extract explicit evidence (e.g., specific explicit success metadata) required to satisfy a task. It differentiates between what was observed, what failed, and what is missing without relying on semantic LLM-based intent matching.

---

## Security Invariants

Security Invariants evaluate deterministic properties that must remain true over the entire sequence of tool events. They protect against subtle attack chains and regressions.

*   **Policy:** "What may execute?" (Individual tool authorization)
*   **Behavior:** "Does the trajectory look suspicious?" (Analysis of tool chains)
*   **Outcome:** "Did the task actually succeed?" (Evidence of completion)
*   **Invariant:** "What must never become false during the trajectory?" (e.g., sensitive data read must never be followed by a network exfiltration).
*   **Security Testing:** "Would these protections still work against recorded trajectories?" The invariant layer includes a synthetic regression test harness (`agentguard test`) to ensure security rules are not accidentally bypassed by future changes.

---

## Context-Aware Security

AgentGuard uses an immutable `SecurityContext` passed through the system to prevent false positives and adapt security policies to the specific environment.

Rules and invariants define scopes (`RuleScope.GLOBAL`, `RuleScope.SESSION`, `RuleScope.TASK`). If a task-scoped rule (like checking for required evidence) executes, it only applies if a `TaskContract` was provided in the context for that trajectory.

```python
from agentguard.context.models import SecurityContext
from agentguard.outcome.models import TaskContract

contract = TaskContract(contract_id="c1", task_name="Tests", required_evidence=("tests_passed",))
context = SecurityContext(session_id="session-1", agent_id="agent-1", task_contract=contract)
```

---

## Trajectory Risk Analysis

AgentGuard evaluates the accumulated risk of an agent's behavior over time using the deterministic **Trajectory Risk Engine**.

While Policy Risk evaluates individual, immediate actions (e.g. `read_file(".env")` -> `DENY`), Trajectory Risk looks at the broader history of events and behavioral findings in a given session to derive an overall risk score and severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

For example:
```
read_file(".env") alone → HIGH Risk
read_file(".env") + base64_encode() + http_request() → CRITICAL Risk
```

The Risk Engine applies base heuristic points for individual dangerous actions and combinations (e.g., Sensitive Data + Encoding + Network). This score acts as observational insight and does NOT automatically enforce policy or block execution by default.

To analyze your benchmark's trajectory risk, run:
```bash
agentguard risk
agentguard risk --json
```

---

## Security Reporting

AgentGuard produces deterministic heuristic security assessments using a severity weighting formula (CRITICAL, HIGH, MEDIUM, LOW violations). It penalizes false positives and missed attacks.

You can run the built-in benchmark to generate a security assessment report via the CLI:
```bash
agentguard report
agentguard report --json
```


## Red-Team Benchmark

AgentGuard includes a reproducible Red-Team benchmark designed to execute realistic adversarial agent trajectories directly through the MCP Gateway against an upstream server. 

AgentGuard does not claim perfect security. The benchmark specifically measures:

1. prevention (attacks blocked before side-effects)
2. detection (attacks flagged during or after execution)
3. missed attacks
4. false positives
5. dangerous upstream side effects

**Important Distinction:**
`BLOCKED != DETECTED`

A blocked attack was prevented before reaching the upstream server. A detected attack may already have executed but was flagged by AgentGuard's behavioral or invariant analysis post-facto. This distinction must remain visible in all reporting.

To run the benchmark:
```bash
uv run agentguard redteam
uv run agentguard redteam --json
```

---

## External Security Benchmark Evaluation

AgentGuard includes a harness for evaluating external, pre-defined security scenarios (such as those from standardized agent security benchmarks).

This harness deterministically plays back synthetic AI agent trajectories through AgentGuard to determine if an attack was **BLOCKED**, **DETECTED**, or **MISSED**, and whether a safe action resulted in a **FALSE POSITIVE**.

### CLI Usage
-----

AgentGuard exposes a command-line interface with several subcommands:

```bash
# Run a specific behavior test scenario
uv run agentguard test path/to/events.jsonl

# Generate security test suite based on tool capabilities
uv run agentguard test --generate

# Run a synthetic agent benchmark
uv run agentguard benchmark

# Evaluate AgentGuard against external security datasets
uv run agentguard evaluate --baseline --json

# Run an interactive, real MCP agent end-to-end demo
uv run agentguard demo
```

---

## Automatic Security Test Generation

AgentGuard can automatically derive deterministic adversarial trajectories from the security capabilities (tools) already configured.

For example, if you provide `read_file` and `http_request` as available tools, AgentGuard automatically generates a test trajectory representing data exfiltration:

```
read_file(.env)
    ↓
http_request(example.invalid)
```

The resulting trajectory is evaluated by the existing invariant test engine to ensure the security mechanisms catch the breach.

> **Note:** This is **NOT** AI-generated testing. It is a deterministic, explainable security test generation engine that mathematically maps tool categories to known attack chains.

---

## Using AgentGuard with MCP

AgentGuard integrates seamlessly with the Model Context Protocol (MCP). The AgentGuard MCP Adapter converts MCP JSON-RPC tool calls into `ToolRequest` objects, routing them through the Policy Engine and Tool Executor before the underlying function is invoked.

**Architecture:**
```text
MCP Client
    ↓
AgentGuard MCP Adapter
    ↓
Policy Engine
    ↓
Tool Executor
    ↓
MCP Tools
```

This guarantees that the MCP server cannot bypass AgentGuard policies. If a policy blocks a tool, the adapter translates the AgentGuard exception into a safe JSON-RPC error for the MCP client.

### Running the Demo Server
A demo MCP server is provided. It exposes simple tools (`list_files`, `read_file`, `calculate`) protected by AgentGuard:
```bash
python -m agentguard.mcp.server
```

## Configuration

Configuration is read from environment variables prefixed with `AGENTGUARD_`:

| Variable                           | Default        | Description                  |
| ---------------------------------- | -------------- | ---------------------------- |
| `AGENTGUARD_LOG_LEVEL`             | `INFO`         | Logging verbosity            |
| `AGENTGUARD_CONFIG_DIR`            | `.agentguard`  | Path to configuration files  |
| `AGENTGUARD_SESSION_TIMEOUT_SECONDS` | `3600`       | Session timeout (seconds)    |

## License

MIT
