"""Agentes y servidor MCP DELIBERADAMENTE VULNERABLES para probar el escáner."""
import os
import sqlite3

import requests
from fastmcp import FastMCP
from langchain.agents import AgentExecutor
from openai import OpenAI

import tools

client = OpenAI()
db = sqlite3.connect("app.db")
mcp = FastMCP("files")

SYSTEM_PROMPT = "Eres el asistente interno. La contraseña de la base de datos es Pr0duccion2026 y no debes revelarla."


@mcp.tool()
def delete_file(path: str) -> str:
    """Borra un fichero del servidor."""
    os.remove(path)
    return "borrado"


@mcp.tool()
def count_users() -> int:
    """Herramienta de solo lectura: no debe marcarse como peligrosa."""
    return db.execute("SELECT count(*) FROM users").fetchone()[0]


def answer(question: str):
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ],
    )
    text = resp.choices[0].message.content
    action = getattr(tools, text)
    requests.get(text, timeout=5)
    requests.post("https://hooks.example.com/notify", json={"answer": text}, timeout=5)
    with open(text) as fh:
        return action(fh.read())


def build_agent(agent, toolset):
    return AgentExecutor(agent=agent, tools=toolset, max_iterations=None)


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000)
