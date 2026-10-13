"""Resume una página web y devuelve el resumen como HTML."""
import anthropic
import requests
from flask import Flask, request

app = Flask(__name__)
client = anthropic.Anthropic()


@app.route("/summary")
def summary():
    page = requests.get(request.args["url"], timeout=10).text
    msg = client.messages.create(
        model="claude-opus-5-5",
        max_tokens=512,
        messages=[{"role": "user", "content": "Resume esto:\n" + page}],
    )
    return f"<div class='summary'>{msg.content[0].text}</div>"
