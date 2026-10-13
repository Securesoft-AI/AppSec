"""Herramienta de diagnóstico: ejecuta un único comando fijo, sin argumentos del modelo."""
import subprocess

from langchain.agents import tool


@tool
def disk_usage() -> str:
    """Devuelve el uso de disco del servidor (solo lectura)."""
    return subprocess.run(["df", "-h", "/"], capture_output=True, text=True, check=True).stdout
