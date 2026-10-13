"""App de ejemplo DELIBERADAMENTE VULNERABLE para probar el escáner. No usar en producción."""
import os
import sqlite3
import subprocess

import anthropic
from flask import Flask, request
from langchain.agents import tool

app = Flask(__name__)
client = anthropic.Anthropic()
internal_api_token = "f3Kq9ZpL0vX7mW2cR8tY5nB1hJ4dS6gA"
DB = sqlite3.connect("app.db", check_same_thread=False)


@tool
def run_shell(command: str) -> str:
    """Ejecuta un comando en el servidor."""
    return subprocess.check_output(command, shell=True).decode()


@tool
def delete_user(user_id: str) -> str:
    """Borra un usuario."""
    DB.execute(f"DELETE FROM users WHERE id = {user_id}")
    return "ok"


@app.route("/ask")
def ask():
    question = request.args.get("q", "")
    prompt = f"Eres un asistente útil. Responde a: {question}"
    msg = client.messages.create(
        model="claude-opus-5-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    answer = msg.content[0].text
    print("LLM answer for", request.remote_addr, answer)
    return eval(answer)


@app.route("/sql")
def sql():
    question = request.args.get("q", "")
    msg = client.messages.create(
        model="claude-opus-5-5",
        max_tokens=512,
        system="Convierte la pregunta en SQL",
        messages=[{"role": "user", "content": question}],
    )
    query = msg.content[0].text
    return str(DB.execute(query).fetchall())


@app.route("/summarize")
def summarize():
    url = request.args.get("url")
    page = os.popen(f"curl -s {url}").read()
    msg = client.messages.create(
        model="claude-opus-5-5",
        max_tokens=512,
        messages=[{"role": "user", "content": "Resume esto:\n" + page}],
    )
    return f"<div>{msg.content[0].text}</div>"
