# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-01

### Added
- **MCP Runtime Gateway**: A secure proxy intercepting Model Context Protocol tool execution.
- **Task Intent Enforcement**: Dynamic restriction of agent capabilities and target resources.
- **Behavioral Analyzer**: Invariant rule engine successfully intercepting known dangerous action sequences before upstream execution (e.g., suspicious chains).
- **Audit Subsystem**: Tamper-evident, SQLite-backed persistence for security events out of the critical enforcement path.
- **Red-Team Benchmark**: An integrated test suite with robust evasion cases, capable of 100% detection and high prevention rates against complex tool poisoning and credential exfiltration.
- **Adversarial Benchmark**: Baseline zero-bypass authorization against filesystem, network SSRF, and privilege escalation vectors.
- **Security Regression Gate**: Unified CLI validation (`uv run agentguard security-gate`) ensuring absolute zero-regression across all invariant capabilities.
