"""Clasificador de intenciones: la salida del modelo solo elige entre funciones fijas."""
import anthropic
from flask import Flask, abort, request

app = Flask(__name__)
client = anthropic.Anthropic()

HANDLERS = {"saldo": "show_balance", "ayuda": "show_help"}


def show_balance():
    return "Tu saldo es 0"


def show_help():
    return "¿En qué te ayudo?"


@app.route("/intent")
def intent():
    question = request.args.get("q", "")
    msg = client.messages.create(
        model="claude-opus-5-5",
        max_tokens=8,
        system="Responde solo con una palabra: saldo o ayuda.",
        messages=[{"role": "user", "content": question}],
    )
    label = msg.content[0].text.strip().lower()
    if label not in HANDLERS:
        abort(400)
    return eval(HANDLERS[label])()
