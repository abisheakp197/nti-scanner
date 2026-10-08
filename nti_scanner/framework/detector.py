"""Detect which AI frameworks a codebase uses."""
import ast
from typing import Dict, List


FRAMEWORK_SIGNATURES = {
    "langchain": {"langchain", "langchain_core", "langchain_openai", "ChatOpenAI", "AgentExecutor"},
    "crewai": {"crewai", "Crew", "Agent", "Task"},
    "autogen": {"autogen", "ConversableAgent", "AssistantAgent"},
    "openai": {"openai", "OpenAI", "ChatCompletion"},
    "anthropic": {"anthropic", "Anthropic"},
}


def detect_frameworks(trees: Dict) -> List[str]:
    detected = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names: _match(n.name, detected)
            elif isinstance(node, ast.ImportFrom):
                if node.module: _match(node.module, detected)
            elif isinstance(node, ast.Call):
                name = _name(node.func)
                if name: _match(name, detected)
    return sorted(detected)


def _match(name: str, detected: set):
    for fw, sigs in FRAMEWORK_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in name.lower():
                detected.add(fw); return


def _name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return ""
