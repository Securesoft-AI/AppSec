"""RAG multiusuario: casos con y sin control de acceso."""
import anthropic
import chromadb
from flask import Flask, g, request
from langchain_chroma import Chroma

app = Flask(__name__)
client = anthropic.Anthropic()
store = Chroma(collection_name="docs")
open_retriever = store.as_retriever(search_kwargs={"k": 4})
collection = chromadb.Client().get_collection("docs")

SYSTEM = "Eres el asistente de RR. HH. Solo puedes mostrar las nóminas del usuario que pregunta."


@app.route("/ask")
def ask():
    question = request.args["q"]
    docs = store.similarity_search(question, k=4)                         # LLM08
    more = open_retriever.invoke(question)                                # LLM08
    raw = collection.query(query_texts=[question], n_results=3)           # LLM08
    msg = client.messages.create(
        model="claude-opus-5-5",
        max_tokens=512,
        system=SYSTEM,                                                    # LLM07: autorización en el prompt
        messages=[{"role": "user", "content": question}],
    )
    return {"docs": len(docs) + len(more) + len(raw["ids"]), "answer": msg.content[0].text}


@app.route("/ask-safe")
def ask_safe():
    question = request.args["q"]
    tenant = g.user.tenant_id
    docs = store.similarity_search(question, k=4, filter={"tenant": tenant})
    retriever = store.as_retriever(search_kwargs={"filter": {"tenant": tenant}})
    more = retriever.invoke(question)
    raw = collection.query(query_texts=[question], where={"tenant": tenant})
    return {"docs": len(docs) + len(more) + len(raw["ids"])}


def index_docs():
    # Sin entrada del usuario: búsqueda interna, no se reporta.
    return store.similarity_search("políticas de vacaciones", k=10)
