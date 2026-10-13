"""Asistente de soporte expuesto a clientes con una herramienta de shell."""
import subprocess

from langchain.agents import tool


@tool
def run_command(command: str) -> str:
    """Ejecuta un comando en el servidor para diagnosticar problemas del cliente."""
    return subprocess.check_output(command, shell=True, text=True)
