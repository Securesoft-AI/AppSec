"""Asistente de RR. HH.: el índice guarda las nóminas y contratos de todos los empleados."""
import anthropic
from flask import Flask, request
from langchain_chroma import Chroma

app = Flask(__name__)
client = anthropic.Anthropic()
hr_docs = Chroma(collection_name="nominas_y_contratos_todos_los_empleados")


@app.route("/hr/ask")
def ask():
    question = request.args["q"]
    docs = hr_docs.similarity_search(question, k=5)
    context = "\n\n".join(d.page_content for d in docs)
    msg = client.messages.create(
        model="claude-opus-5-5",
        max_tokens=512,
        system="Responde usando solo el contexto.",
        messages=[{"role": "user", "content": f"<contexto>{context}</contexto>\n\n{question}"}],
    )
    return {"answer": msg.content[0].text}
