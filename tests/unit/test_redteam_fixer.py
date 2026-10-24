"""Red Team Destruction Tests and Safety Audits for --fix Auto-Patcher."""
import ast
import stat
from pathlib import Path

from click.testing import CliRunner

from nti_scanner.cli import main
from nti_scanner.fixer import (
    fix_dependencies,
    fix_guardrails,
    fix_readme,
    fix_workflow,
)


def test_redteam_empty_void(tmp_path: Path) -> None:
    """1. The Empty Void: A directory with no files."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--fix"])
    assert result.exit_code == 0
    assert (tmp_path / ".github" / "workflows" / "nti-scan.yml").exists()
    assert (tmp_path / "requirements.txt").exists()
    assert (tmp_path / "README.md").exists()


def test_redteam_broken_python(tmp_path: Path) -> None:
    """2. The Broken Python: A .py file with a SyntaxError."""
    broken_file = tmp_path / "broken.py"
    broken_file.write_text("def broken_func(:\n    pass\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--fix"])
    assert result.exit_code == 0
    # The broken file remains uncorrupted
    assert "def broken_func(:" in broken_file.read_text(encoding="utf-8")


def test_redteam_missing_lock_pyproject_toml(tmp_path: Path) -> None:
    """3. The Missing Lock: A project with pyproject.toml but no requirements.txt."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "my-agent"\nversion = "0.1.0"\ndependencies = [\n    "langchain>=0.1.0"\n]\n',
        encoding="utf-8",
    )

    fix_dependencies(tmp_path)

    content = pyproject.read_text(encoding="utf-8")
    assert "ube-foundation" in content
    assert not (tmp_path / "requirements.txt").exists()


def test_redteam_read_only_file(tmp_path: Path) -> None:
    """4. The Read-Only File: Make README.md read-only."""
    readme = tmp_path / "README.md"
    readme.write_text("# Existing Readme\n", encoding="utf-8")
    # Make file read-only
    readme.chmod(stat.S_IREAD)

    try:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path), "--fix"])
        # Should not throw unhandled exception stack trace
        assert result.exit_code == 0 or "Permission" in result.output or "Error" in result.output
        assert "Traceback (most recent call last)" not in result.output
    finally:
        # Restore write permissions for cleanup
        readme.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_redteam_conflict_workflow(tmp_path: Path) -> None:
    """5. The Conflict: An existing .github/workflows/nti-scan.yml."""
    workflows_dir = tmp_path / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    custom_workflow = workflows_dir / "nti-scan.yml"
    custom_content = "name: Custom Workflow\njobs: {}\n"
    custom_workflow.write_text(custom_content, encoding="utf-8")

    fix_workflow(tmp_path)

    assert custom_workflow.read_text(encoding="utf-8") == custom_content


def test_idempotency_five_runs(tmp_path: Path) -> None:
    """Phase 2: Idempotency test when --fix is run 5 times."""
    py_file = tmp_path / "agent.py"
    py_file.write_text(
        'from langchain.agents import AgentExecutor\n\ndef run():\n    agent = AgentExecutor()\n',
        encoding="utf-8",
    )

    for _ in range(5):
        fix_workflow(tmp_path)
        fix_dependencies(tmp_path)
        fix_readme(tmp_path)
        fix_guardrails(tmp_path)

    readme_content = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert readme_content.count("NTI Secured") == 1

    req_content = (tmp_path / "requirements.txt").read_text(encoding="utf-8")
    assert req_content.count("ube-foundation") == 1

    py_content = py_file.read_text(encoding="utf-8")
    assert py_content.count("from langchain_nti import NTICallbackHandler") == 1
    assert py_content.count("# TODO: Pass NTICallbackHandler()") == 1


def test_ast_safety_future_imports_and_docstring(tmp_path: Path) -> None:
    """Phase 2: AST Safety with __future__ imports and docstring."""
    code = (
        '"""Module docstring for agent."""\n'
        'from __future__ import annotations\n'
        'from __future__ import unicode_literals\n'
        '\n'
        'from langchain.agents import AgentExecutor\n'
        '\n'
        'def main():\n'
        '    executor = AgentExecutor()\n'
    )
    py_file = tmp_path / "safe_agent.py"
    py_file.write_text(code, encoding="utf-8")

    fix_guardrails(tmp_path)

    patched_code = py_file.read_text(encoding="utf-8")

    # Must be valid AST
    assert ast.parse(patched_code) is not None

    # Verify order of imports
    lines = patched_code.splitlines()
    doc_line = next(i for i, l in enumerate(lines) if "Module docstring" in l)
    future1_line = next(i for i, l in enumerate(lines) if "from __future__ import annotations" in l)
    future2_line = next(i for i, l in enumerate(lines) if "from __future__ import unicode_literals" in l)
    injected_line = next(i for i, l in enumerate(lines) if "from langchain_nti import NTICallbackHandler" in l)

    assert doc_line < future1_line < future2_line < injected_line
