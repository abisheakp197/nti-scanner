"""Partial safety: some tools governed, others not."""
from langchain.agents import AgentExecutor
from langchain_core.tools import tool
from langchain_nti import NTICallbackHandler


@tool
def execute_transfer(amount: float) -> str:
    return f"Transferred {amount}"


@tool
def delete_database(db_name: str) -> str:
    return f"Deleted {db_name}"


nti = NTICallbackHandler(agent_id="mixed_agent")
nti.grant_capability("execute_transfer")
# NOTE: delete_database is NOT granted


agent = AgentExecutor(agent=None, tools=[execute_transfer, delete_database], callbacks=[nti])


audit = True
