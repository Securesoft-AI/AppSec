"""Agente que sigue los enlaces que el modelo decide abrir."""
import requests
from openai import OpenAI

client = OpenAI()


def browse(task: str) -> str:
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=200,
        messages=[{"role": "system", "content": "Devuelve la URL que hay que abrir."},
                  {"role": "user", "content": task}],
    )
    url = resp.choices[0].message.content
    return requests.get(url, timeout=10).text
