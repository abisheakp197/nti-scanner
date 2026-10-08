# nti-scanner


Professional SAST tool for AI agent security. AST-based analysis, taint tracking, CWE mapping, and SARIF output.


## Features
- AST-based analysis
- Taint tracking
- 19 rules (NTI-1 + OWASP AI security)
- CWE mapping
- SARIF output for GitHub Security tab
- Framework detection (LangChain, CrewAI, AutoGen, OpenAI, Anthropic)
- MCP + A2A rules (first in the world)
- PQC readiness check
- Capability diff
- Behavior graph export


## Install
pip install nti-scanner


## Usage
nti-scanner scan ./my-agent-project
nti-scanner scan ./my-project --format sarif --output report.sarif
nti-scanner scan . --min-score 80


## License
Apache License 2.0. See LICENSE.


## Links
- NTI-1 Spec: https://abisheakp197.github.io/nti-spec/
- Core SDK: https://pypi.org/project/ube-foundation/
