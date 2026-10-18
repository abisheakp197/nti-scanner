"""Safe AST parser."""
import ast
from pathlib import Path

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit to prevent memory blowups


def parse_python_file(path: Path) -> ast.AST | None:
    try:
        if path.is_file() and path.stat().st_size > MAX_FILE_SIZE_BYTES:
            return None
        source = path.read_text(encoding="utf-8", errors="ignore")
        if "\x00" in source:
            return None
        return ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError, MemoryError, RecursionError):
        return None


def get_source_segment(path: Path, node: ast.AST) -> str:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        return ast.get_source_segment(source, node) or ""
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError, MemoryError, RecursionError):
        return ""
