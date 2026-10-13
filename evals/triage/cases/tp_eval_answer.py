"""Calculadora con LLM: evalúa directamente lo que devuelve el modelo."""
import anthropic
from flask import Flask, request

app = Flask(__name__)
client = anthropic.Anthropic()


@app.route("/calc")
def calc():
    question = request.args.get("q", "")
    msg = client.messages.create(
        model="claude-opus-5-5",
        max_tokens=256,
        system="Convierte la pregunta en una expresión de Python.",
        messages=[{"role": "user", "content": question}],
    )
    expression = msg.content[0].text
    return str(eval(expression))
