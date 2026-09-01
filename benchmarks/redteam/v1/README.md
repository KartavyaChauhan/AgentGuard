# AgentGuard Red-Team Benchmark v1

This is a deterministic test suite containing explicit adversarial and benign trajectories for benchmarking AgentGuard's security engines.

## Methodology

The benchmark feeds these predefined trajectories through the `AgentGuardGateway` to an upstream `MCPServer`. AgentGuard does not claim perfect security. The benchmark measures:
1. prevention
2. detection
3. missed attacks
4. false positives
5. dangerous upstream side effects

## Important Distinction

**BLOCKED != DETECTED**

A blocked attack was prevented before it reached the upstream server. A detected attack may already have executed (e.g. by behavioral heuristics catching it post-facto). This distinction must remain visible in all reporting.
