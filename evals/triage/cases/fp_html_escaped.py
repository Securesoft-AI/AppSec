"""Igual que el resumen, pero la salida del modelo se escapa antes de insertarla en HTML."""
from html import escape

import anthropic
from flask import Flask, request

app = Flask(__name__)
client = anthropic.Anthropic()


@app.route("/greeting")
def greeting():
    name = request.args.get("name", "")[:40]
    msg = client.messages.create(
        model="claude-opus-5-5",
        max_tokens=64,
        messages=[{"role": "user", "content": f"Escribe un saludo corto para {name}"}],
    )
    return f"<p>{escape(msg.content[0].text)}</p>"
