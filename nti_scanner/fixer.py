"""NTI Auto-Fixer module."""
import ast
import sys
from pathlib import Path

WORKFLOW_YAML = """name: NTI Security Scan
on: [push]
permissions:
  contents: write
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: abisheakp197/nti-scan-action@v1.0.0
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
"""

BADGE_MARKDOWN = "[![NTI Secured](https://img.shields.io/badge/NTI_Score-Pending-green)](https://nti-registry.vercel.app)"
REQUIRED_DEP = "ube-foundation>=0.1.7"
GUARDRAIL_IMPORT = "from langchain_nti import NTICallbackHandler"
GUARDRAIL_COMMENT = "# TODO: Pass NTICallbackHandler() to your agent/crew configuration for runtime enforcement."


def _get_root_dir(repo_path: str | Path) -> Path:
    p = Path(repo_path)
    return p.parent if p.is_file() else p


def fix_workflow(repo_path: str | Path) -> None:
    """Ensure .github/workflows/ exists and nti-scan.yml is present."""
    root = _get_root_dir(repo_path)
    try:
        workflows_dir = root / ".github" / "workflows"
        workflows_dir.mkdir(parents=True, exist_ok=True)
        workflow_file = workflows_dir / "nti-scan.yml"
        if not workflow_file.exists():
            workflow_file.write_text(WORKFLOW_YAML, encoding="utf-8")
    except (PermissionError, OSError) as e:
        print(f"Error updating workflow: {e}", file=sys.stderr)


def fix_dependencies(repo_path: str | Path) -> None:
    """Ensure requirements.txt or pyproject.toml exists and ube-foundation dependency is present."""
    root = _get_root_dir(repo_path)
    pyproject_file = root / "pyproject.toml"
    req_file = root / "requirements.txt"

    try:
        if pyproject_file.exists():
            content = pyproject_file.read_text(encoding="utf-8")
            if "ube-foundation" not in content:
                if "dependencies = [" in content:
                    new_content = content.replace("dependencies = [", 'dependencies = [\n    "ube-foundation>=0.1.7",', 1)
                elif "[project]" in content:
                    new_content = content.replace("[project]", '[project]\ndependencies = [\n    "ube-foundation>=0.1.7",\n]', 1)
                elif "[tool.poetry.dependencies]" in content:
                    new_content = content.replace(
                        "[tool.poetry.dependencies]", '[tool.poetry.dependencies]\nube-foundation = ">=0.1.7"', 1
                    )
                else:
                    prefix = "" if not content or content.endswith("\n") else "\n"
                    new_content = f'{content}{prefix}[project]\ndependencies = [\n    "ube-foundation>=0.1.7",\n]\n'
                pyproject_file.write_text(new_content, encoding="utf-8")

        if req_file.exists():
            content = req_file.read_text(encoding="utf-8")
            if "ube-foundation" not in content:
                prefix = "" if not content or content.endswith("\n") else "\n"
                req_file.write_text(f"{content}{prefix}{REQUIRED_DEP}\n", encoding="utf-8")

        if not pyproject_file.exists() and not req_file.exists():
            req_file.write_text(f"{REQUIRED_DEP}\n", encoding="utf-8")
    except (PermissionError, OSError) as e:
        print(f"Error updating dependencies: {e}", file=sys.stderr)


def fix_readme(repo_path: str | Path) -> None:
    """Ensure README.md exists and contains the NTI compliance badge."""
    root = _get_root_dir(repo_path)
    readme_file = root / "README.md"
    try:
        if not readme_file.exists():
            readme_file.write_text(f"{BADGE_MARKDOWN}\n\n# Project\n", encoding="utf-8")
            return

        content = readme_file.read_text(encoding="utf-8")
        if "NTI Secured" not in content and "NTI_Score" not in content:
            new_content = f"{BADGE_MARKDOWN}\n\n{content}"
            readme_file.write_text(new_content, encoding="utf-8")
    except (PermissionError, OSError) as e:
        print(f"Error updating README.md: {e}", file=sys.stderr)


def fix_guardrails(repo_path: str | Path) -> None:
    """Scan Python files for AgentExecutor or Crew and inject NTI callback guardrails."""
    root = Path(repo_path)
    if not root.exists():
        return

    py_files = [root] if root.is_file() and root.suffix == ".py" else list(root.rglob("*.py"))
    for py_file in py_files:
        # Ignore virtualenv or cache files
        str_f = str(py_file)
        if "site-packages" in str_f or "node_modules" in str_f or "__pycache__" in str_f or ".venv" in str_f:
            continue
        _patch_python_file(py_file)


def _patch_python_file(py_file: Path) -> None:
    try:
        source = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError, OSError):
        return

    target_lines: list[int] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = None
            if isinstance(node.func, ast.Name) and node.func.id in ("AgentExecutor", "Crew"):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute) and node.func.attr in ("AgentExecutor", "Crew"):
                call_name = node.func.attr

            if call_name:
                target_lines.append(node.lineno)

    if not target_lines:
        return

    lines = source.splitlines()

    # 1. Inject import if not present
    has_import = "from langchain_nti import NTICallbackHandler" in source
    if not has_import:
        import_insert_idx = _find_import_insert_index(tree, lines)
        lines.insert(import_insert_idx, GUARDRAIL_IMPORT)
        target_lines = [l + 1 if l > import_insert_idx else l for l in target_lines]

    # 2. Add TODO comments above instantiation lines if not already present
    unique_target_lines = sorted(set(target_lines), reverse=True)

    for line_no in unique_target_lines:
        idx = line_no - 1  # 0-based index in lines
        if idx > 0 and GUARDRAIL_COMMENT in lines[idx - 1]:
            continue

        indent = ""
        if idx < len(lines):
            line_str = lines[idx]
            indent = line_str[: len(line_str) - len(line_str.lstrip())]

        comment_line = f"{indent}{GUARDRAIL_COMMENT}"
        lines.insert(idx, comment_line)

    new_source = "\n".join(lines)
    if source.endswith("\n") and not new_source.endswith("\n"):
        new_source += "\n"

    try:
        py_file.write_text(new_source, encoding="utf-8")
    except (PermissionError, OSError) as e:
        print(f"Error patching {py_file}: {e}", file=sys.stderr)


def _find_import_insert_index(tree: ast.Module, lines: list[str]) -> int:
    insert_idx = 0

    while insert_idx < len(lines) and (lines[insert_idx].startswith("#!") or "coding:" in lines[insert_idx]):
        insert_idx += 1

    if not tree.body:
        return insert_idx

    idx_after_docstring = insert_idx
    first_stmt = tree.body[0]
    if isinstance(first_stmt, ast.Expr) and isinstance(first_stmt.value, ast.Constant) and isinstance(first_stmt.value.value, str):
        end_line = first_stmt.end_lineno
        if end_line is not None:
            idx_after_docstring = max(insert_idx, end_line)
        else:
            idx_after_docstring = max(insert_idx, first_stmt.lineno)

    last_future_idx = idx_after_docstring
    for stmt in tree.body:
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__":
            future_end = stmt.end_lineno
            if future_end is not None:
                last_future_idx = max(last_future_idx, future_end)
            else:
                last_future_idx = max(last_future_idx, stmt.lineno)

    return last_future_idx
