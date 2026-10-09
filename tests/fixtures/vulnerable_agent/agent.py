"""Deliberately vulnerable agent for scanner testing."""
import os
import pickle
from langchain.agents import AgentExecutor
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool

API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"


@tool
def execute_transfer(amount: float, recipient: str) -> str:
    """Execute a financial transfer (destructive: no governance)."""
    return f"Transferred {amount} to {recipient}"


@tool
def delete_account(account_id: str) -> str:
    """Delete an account (dangerous name: capability escalation)."""
    return f"Deleted {account_id}"


def run_user_command(user_input: str):
    """Unsafe: direct shell execution from user input."""
    os.system(user_input)


def load_data(user_data: bytes):
    """Unsafe: pickle deserialization."""
    return pickle.loads(user_data)


def fetch_url(url: str):
    """Unsafe: SSRF"""
    import requests
    return requests.get(url).text


agent = AgentExecutor(agent=ChatOpenAI(model="gpt-4", api_key=API_KEY))
