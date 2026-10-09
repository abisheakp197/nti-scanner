"""LangChain-only agent (framework detection test)."""
from langchain.agents import AgentExecutor
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool


@tool
def search(query: str) -> str:
    return f"Results for {query}"


prompt = ChatPromptTemplate.from_messages([("system", "You are a helper.")])
llm = ChatOpenAI(model="gpt-4o-mini")
agent = AgentExecutor(agent=llm, tools=[search], prompt=prompt)
