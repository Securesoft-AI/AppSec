"""Agente que abre documentación, pero solo de una lista cerrada de URLs."""
import requests
from openai import OpenAI

client = OpenAI()

ALLOWED_URLS = {
    "https://docs.example.com/precios",
    "https://docs.example.com/envios",
}


def browse(task: str) -> str:
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=200,
        messages=[{"role": "system", "content": "Devuelve la URL de la documentación que hay que abrir."},
                  {"role": "user", "content": task}],
    )
    url = resp.choices[0].message.content.strip()
    if url not in ALLOWED_URLS:
        raise ValueError("URL no permitida")
    return requests.get(url, timeout=10).text
