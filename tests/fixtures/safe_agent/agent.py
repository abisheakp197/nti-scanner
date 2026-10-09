"""Safe agent using NTI (for scanner testing)."""
from langchain.agents import AgentExecutor
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_nti import NTICallbackHandler


@tool
def execute_transfer(amount: float, recipient: str) -> str:
    """Transfer with NTI governance."""
    return f"Transferred {amount}"


@tool
def read_account(account_id: str) -> str:
    return f"Account {account_id}"


nti = NTICallbackHandler(agent_id="safe_agent", strict=True)
nti.grant_capability("execute_transfer")
nti.grant_capability("read_account")


agent = AgentExecutor(
    agent=ChatOpenAI(model="gpt-4"),
    tools=[execute_transfer, read_account],
    callbacks=[nti],
)


# Audit trail
audit_log = []
def log_event(msg):
    audit_log.append(msg)


# Persistence
def save_state():
    return "state_saved"


def verify_history():
    return True
