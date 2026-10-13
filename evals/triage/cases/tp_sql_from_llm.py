"""Pregunta a la base de datos en lenguaje natural (conexión con permisos de escritura)."""
import sqlite3

import anthropic
from flask import Flask, request

app = Flask(__name__)
client = anthropic.Anthropic()
DB = sqlite3.connect("customers.db", check_same_thread=False)


@app.route("/report")
def report():
    question = request.args.get("q", "")
    msg = client.messages.create(
        model="claude-opus-5-5",
        max_tokens=512,
        system="Convierte la pregunta en una consulta SQL para la tabla customers.",
        messages=[{"role": "user", "content": question}],
    )
    query = msg.content[0].text
    rows = DB.execute(query).fetchall()
    DB.commit()
    return {"rows": rows}
