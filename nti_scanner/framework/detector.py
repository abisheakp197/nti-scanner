"""Framework detector for AI agent libraries."""

import ast
from pathlib import Path
from typing import Dict, List, Set


FRAMEWORK_IMPORTS = {
    "langchain": "LangChain",
    "langgraph": "LangGraph",
    "autogen": "AutoGen",
    "crewai": "CrewAI",
    "llama_index": "LlamaIndex",
    "semantic_kernel": "Semantic Kernel",
    "ube_foundation": "UBE Foundation",
    "mcp": "Model Context Protocol (MCP)",
    "a2a": "Agent2Agent (A2A)",
    "openai": "OpenAI SDK",
    "anthropic": "Anthropic SDK",
}


def detect_frameworks(trees: Dict[Path, ast.AST]) -> List[str]:
    detected: Set[str] = set()

    for path, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_module = alias.name.split(".")[0]
                    if top_module in FRAMEWORK_IMPORTS:
                        detected.add(FRAMEWORK_IMPORTS[top_module])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top_module = node.module.split(".")[0]
                    if top_module in FRAMEWORK_IMPORTS:
                        detected.add(FRAMEWORK_IMPORTS[top_module])

    return sorted(list(detected))
