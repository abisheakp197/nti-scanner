"""Enterprise Auto-Patcher unit tests."""
from pathlib import Path

from nti_scanner.fixer import (
    BADGE_MARKDOWN,
    GUARDRAIL_COMMENT,
    GUARDRAIL_IMPORT,
    REQUIRED_DEP,
    fix_dependencies,
    fix_guardrails,
    fix_readme,
    fix_workflow,
)


def test_missing_files(tmp_path: Path):
    """Test running fixer on an empty directory creates required files without error."""
    fix_workflow(tmp_path)
    fix_dependencies(tmp_path)
    fix_readme(tmp_path)
    fix_guardrails(tmp_path)

    workflow_file = tmp_path / ".github" / "workflows" / "nti-scan.yml"
    req_file = tmp_path / "requirements.txt"
    readme_file = tmp_path / "README.md"

    assert workflow_file.exists()
    assert "abisheakp197/nti-scan-action@v1.0.0" in workflow_file.read_text(encoding="utf-8")
    assert "permissions:" in workflow_file.read_text(encoding="utf-8")
    assert "contents: write" in workflow_file.read_text(encoding="utf-8")

    assert req_file.exists()
    assert REQUIRED_DEP in req_file.read_text(encoding="utf-8")

    assert readme_file.exists()
    assert BADGE_MARKDOWN in readme_file.read_text(encoding="utf-8")


def test_idempotency(tmp_path: Path):
    """Test running fixer twice on a directory does not duplicate content."""
    readme = tmp_path / "README.md"
    readme.write_text("# Existing Project\nSome description.\n", encoding="utf-8")

    fix_workflow(tmp_path)
    fix_dependencies(tmp_path)
    fix_readme(tmp_path)

    agent_file = tmp_path / "agent.py"
    agent_file.write_text(
        '"""Agent module."""\nfrom __future__ import annotations\n\nexecutor = AgentExecutor()\ncrew = Crew()\n',
        encoding="utf-8",
    )
    fix_guardrails(tmp_path)

    readme_content_run1 = readme.read_text(encoding="utf-8")
    req_content_run1 = (tmp_path / "requirements.txt").read_text(encoding="utf-8")
    agent_content_run1 = agent_file.read_text(encoding="utf-8")

    assert readme_content_run1.count(BADGE_MARKDOWN) == 1
    assert req_content_run1.count("ube-foundation") == 1
    assert agent_content_run1.count(GUARDRAIL_IMPORT) == 1
    assert agent_content_run1.count(GUARDRAIL_COMMENT) == 2

    # Second run
    fix_workflow(tmp_path)
    fix_dependencies(tmp_path)
    fix_readme(tmp_path)
    fix_guardrails(tmp_path)

    readme_content_run2 = readme.read_text(encoding="utf-8")
    req_content_run2 = (tmp_path / "requirements.txt").read_text(encoding="utf-8")
    agent_content_run2 = agent_file.read_text(encoding="utf-8")

    assert readme_content_run2 == readme_content_run1
    assert req_content_run2 == req_content_run1
    assert agent_content_run2 == agent_content_run1


def test_guardrails_injection_ast(tmp_path: Path):
    """Test code injection places import after docstring/future imports and TODO comment above AgentExecutor or Crew."""
    agent_code = '''"""My AI Agent Module."""
from __future__ import annotations

import os

class MyAgent:
    def run(self):
        executor = AgentExecutor(agent=None)
        my_crew = Crew(agents=[])
        return executor
'''
    agent_file = tmp_path / "agent.py"
    agent_file.write_text(agent_code, encoding="utf-8")

    fix_guardrails(tmp_path)

    content = agent_file.read_text(encoding="utf-8")
    lines = content.splitlines()

    assert GUARDRAIL_IMPORT in content

    import_idx = lines.index(GUARDRAIL_IMPORT)
    docstring_idx = lines.index('"""My AI Agent Module."""')
    future_idx = lines.index("from __future__ import annotations")

    assert import_idx > docstring_idx
    assert import_idx > future_idx

    comment_count = content.count(GUARDRAIL_COMMENT)
    assert comment_count == 2
