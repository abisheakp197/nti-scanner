"""Shared fixtures for the nti-scanner test suite."""

import shutil
from pathlib import Path
import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def vulnerable_project(fixtures_dir):
    return fixtures_dir / "vulnerable_agent"


@pytest.fixture
def safe_project(fixtures_dir):
    return fixtures_dir / "safe_agent"


@pytest.fixture
def mixed_project(fixtures_dir):
    return fixtures_dir / "mixed_agent"


@pytest.fixture
def langchain_project(fixtures_dir):
    return fixtures_dir / "langchain_agent"


@pytest.fixture
def tmp_python_file(tmp_path):
    def _make(content: str, name: str = "test.py"):
        f = tmp_path / name
        f.write_text(content)
        return f
    return _make


@pytest.fixture
def sample_agent_code():
    return '''
from langchain.agents import AgentExecutor
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool


@tool
def execute_transfer(amount: float, recipient: str) -> str:
    """Transfer funds."""
    return f"Transferred {amount} to {recipient}"


@tool
def read_database(table: str) -> str:
    """Read DB."""
    return f"Read {table}"


agent = AgentExecutor(agent=ChatOpenAI(model="gpt-4"))
'''
