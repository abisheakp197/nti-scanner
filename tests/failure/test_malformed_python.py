"""Malformed files must not crash scanner."""
from nti_scanner.ast_analysis.parser import parse_python_file


def test_binary_file_handled(tmp_path):
    f = tmp_path / "test.py"
    f.write_bytes(b"\x00\x01\x02\xff\xfe")
    tree = parse_python_file(f)
    assert tree is None


def test_deeply_nested_file(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("x = " + "(" * 500 + "1" + ")" * 500)
    tree = parse_python_file(f)
    # Must not raise; either parses or returns None
    assert tree is None or tree is not None
