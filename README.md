# nti-scanner

[![NTI Scan](https://github.com/abisheakp197/nti-scanner/actions/workflows/scan.yml/badge.svg)](https://github.com/abisheakp197/nti-scanner/actions/workflows/scan.yml)
[![PyPI version](https://img.shields.io/pypi/v/nti-scanner.svg)](https://pypi.org/project/nti-scanner/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**nti-scanner** is a professional-grade static analysis tool for AI agent codebases. It performs AST-based analysis, taint tracking, framework detection, CWE mapping, and outputs SARIF for GitHub Security tab integration. It includes unique NTI-specific rules: capability diff, trust boundary mapping, MCP rules, A2A rules, PQC readiness, and behavior graph export.

## Features

- **NTI-1 Compliance Checking**: Scans Python agent codebases across the 5 NTI-1 pillars: Identity, Governance, Consensus, Audit, and Persistence.
- **AI Agent Security Analysis**: Detects prompt injection, command injection, path traversal, SSRF, SQL injection, secret leaks, unsafe deserialization, capability escalation, LLM trust issues, MCP vulnerabilities, and A2A inter-agent protocol flaws.
- **Framework Detection**: Detects LangChain, AutoGen, CrewAI, LlamaIndex, Semantic Kernel, UBE Foundation, MCP, A2A, and more.
- **Agent Behavior Graph**: Builds and exports agent capability, action, and sink graphs.
- **Multiple Output Formats**: Supports Rich terminal rendering, JSON, SARIF (v2.1.0) for GitHub Security integration, and interactive HTML reports.

## Installation

```bash
pip install nti-scanner
```

## Quick Start

### Scan a Directory

```bash
nti-scanner scan /path/to/agent/code
```

### Export SARIF Report for GitHub Security

```bash
nti-scanner scan . --format sarif -o results.sarif
```

### Generate Agent Behavior Graph

```bash
nti-scanner graph . -o behavior_graph.json
```

### List All Available Rules

```bash
nti-scanner rules
```

## License

This project is licensed under the [Apache 2.0 License](LICENSE).
