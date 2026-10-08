"""Safe AST parser."""
import ast
from pathlib import Path
from typing import Optional


def parse_python_file(path: Path) -> Optional[ast.AST]:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        return ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError):
        return None


def get_source_segment(path: Path, node: ast.AST) -> str:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        return ast.get_source_segment(source, node) or ""
    except Exception:
        return ""
