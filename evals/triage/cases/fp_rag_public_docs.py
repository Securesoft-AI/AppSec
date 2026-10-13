"""Buscador del manual público del producto: todos los documentos son públicos y del mismo nivel."""
from flask import Flask, request
from langchain_chroma import Chroma

app = Flask(__name__)
# Se indexa solo la documentación pública de docs.example.com (ver scripts/index_public_docs.py).
public_manual = Chroma(collection_name="manual_publico_producto")


@app.route("/docs/search")
def search():
    question = request.args["q"][:200]
    docs = public_manual.similarity_search(question, k=5)
    return {"results": [d.metadata.get("url") for d in docs]}
