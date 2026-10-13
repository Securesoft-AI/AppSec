"""Definiciones compartidas por los analizadores de seguridad de IA (Python y JS/TS)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from appsec_ai.models import AIComponent, Category, Finding, Severity

OWASP = {
    "LLM01": "OWASP-LLM01:2025 Prompt Injection",
    "LLM02": "OWASP-LLM02:2025 Sensitive Information Disclosure",
    "LLM05": "OWASP-LLM05:2025 Improper Output Handling",
    "LLM06": "OWASP-LLM06:2025 Excessive Agency",
    "LLM07": "OWASP-LLM07:2025 System Prompt Leakage",
    "LLM10": "OWASP-LLM10:2025 Unbounded Consumption",
}

# CWE-1427: Improper Neutralization of Input Used for LLM Prompting.
CWE_PROMPT = "CWE-1427"


@dataclass(frozen=True)
class Rule:
    id: str
    owasp: str
    severity: Severity
    title: str
    message: str
    cwe: str


RULES = {r.id: r for r in [
    Rule("llm01-untrusted-input-in-system-prompt", "LLM01", Severity.HIGH,
         "Entrada no confiable dentro del prompt de sistema",
         "Datos controlados por el usuario o externos se insertan en las instrucciones de sistema, lo que "
         "permite sobrescribir el comportamiento del modelo. Mantén el prompt de sistema constante y pasa "
         "la entrada como mensaje de usuario.", CWE_PROMPT),
    Rule("llm01-prompt-concatenation", "LLM01", Severity.MEDIUM,
         "Entrada del usuario concatenada con las instrucciones del prompt",
         "La entrada del usuario se mezcla con las instrucciones en el mismo texto, sin separación. Mantén "
         "las instrucciones en el prompt de sistema y pasa la entrada como mensaje de usuario independiente, "
         "delimitada (p. ej. entre etiquetas XML).", CWE_PROMPT),
    Rule("llm01-indirect-prompt-injection", "LLM01", Severity.MEDIUM,
         "Contenido externo no confiable enviado al LLM (prompt injection indirecta)",
         "Contenido obtenido de la red, de ficheros o de un vector store llega al modelo junto a las "
         "instrucciones. Quien controle ese contenido puede dar órdenes al modelo. Delimita el contenido, "
         "indica al modelo que es solo información y limita lo que el modelo puede hacer después.", CWE_PROMPT),
    Rule("llm02-llm-io-logged", "LLM02", Severity.LOW,
         "Entrada/salida del LLM escrita en logs",
         "Los prompts y respuestas pueden contener datos personales o secretos; revisa la retención y el "
         "enmascarado de los logs.", "CWE-532"),
    Rule("llm05-llm-output-to-code-exec", "LLM05", Severity.CRITICAL,
         "Salida del LLM ejecutada como código o comando",
         "La respuesta del modelo se ejecuta directamente. Con prompt injection esto es ejecución remota de "
         "código. Nunca ejecutes salida del modelo; si es imprescindible, usa un sandbox aislado.", "CWE-94"),
    Rule("llm05-llm-output-to-sql", "LLM05", Severity.HIGH,
         "Salida del LLM ejecutada como SQL",
         "La consulta generada por el modelo se ejecuta sin validación: un atacante puede leer o borrar datos. "
         "Usa consultas parametrizadas, una lista blanca de operaciones y un usuario de BD de solo lectura.",
         "CWE-89"),
    Rule("llm05-llm-output-to-request", "LLM05", Severity.HIGH,
         "Salida del LLM usada como destino de una petición HTTP (SSRF)",
         "El modelo decide a qué URL se conecta el servidor: puede alcanzar servicios internos o exfiltrar "
         "datos. Valida el destino contra una lista blanca.", "CWE-918"),
    Rule("llm05-llm-output-to-filesystem", "LLM05", Severity.HIGH,
         "Salida del LLM usada como ruta de fichero",
         "El modelo controla rutas de ficheros (path traversal, lectura o borrado de ficheros).", "CWE-22"),
    Rule("llm05-llm-output-to-html", "LLM05", Severity.MEDIUM,
         "Salida del LLM insertada en HTML sin escapar (XSS)",
         "La respuesta del modelo se inserta como HTML. Un atacante puede hacer que el modelo devuelva "
         "JavaScript. Escápala, renderízala como texto o sanéala (DOMPurify).", "CWE-79"),
    Rule("llm05-llm-output-selects-function", "LLM05", Severity.HIGH,
         "La salida del LLM decide qué función se ejecuta",
         "Se usa la respuesta del modelo para elegir dinámicamente una función o atributo (getattr, "
         "globals, objeto[clave]). Restringe las opciones a una lista blanca explícita.", "CWE-470"),
    Rule("llm06-excessive-agency-tool", "LLM06", Severity.HIGH,
         "Herramienta de agente con acciones peligrosas",
         "El LLM puede invocar esta herramienta con argumentos controlados por un atacante (vía prompt "
         "injection). Requiere confirmación humana, mínimo privilegio y validación estricta de argumentos.",
         "CWE-250"),
    Rule("llm06-mcp-http-without-auth", "LLM06", Severity.MEDIUM,
         "Servidor MCP expuesto por HTTP sin autenticación",
         "El servidor MCP se publica por HTTP/SSE y no se ha encontrado ninguna autenticación: cualquiera que "
         "alcance el puerto puede invocar sus herramientas. Añade autenticación (OAuth/token) o exponlo solo "
         "por stdio o en una red privada.", "CWE-306"),
    Rule("llm07-secret-in-system-prompt", "LLM07", Severity.HIGH,
         "Secreto incluido en el prompt de sistema",
         "El prompt de sistema contiene lo que parece una credencial. Los prompts de sistema se pueden "
         "extraer con prompt injection: nunca incluyas secretos en ellos.", "CWE-200"),
    Rule("llm10-no-output-limit", "LLM10", Severity.LOW,
         "Llamada al LLM sin límite de tokens de salida",
         "Sin un límite explícito de tokens, un atacante puede provocar respuestas largas y costes elevados. "
         "Fija max_tokens y limita también la frecuencia de peticiones por usuario.", "CWE-770"),
    Rule("llm10-unbounded-agent-loop", "LLM10", Severity.MEDIUM,
         "Agente sin límite de iteraciones",
         "El agente puede encadenar llamadas a herramientas sin límite, con coste y riesgo ilimitados. "
         "Fija un número máximo de iteraciones y un tiempo máximo de ejecución.", "CWE-770"),
]}

# Patrones de secretos dentro de prompts (LLM07).
SECRET_IN_TEXT = re.compile(
    r"(?i)(?:api[_ -]?key|password|passwd|contraseña|clave|secret|token|credential|credencial)\w*"
    r"[^\n.:=]{0,40}?(?:\bis|\bes|:|=)\s*[\"']?(?=[A-Za-z0-9_\-+/]*\d)[A-Za-z0-9_\-+/]{8,}"
    r"|\bsk-[A-Za-z0-9_\-]{16,}|\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|\bAKIA[0-9A-Z]{16}\b"
    r"|\bgh[pousr]_[A-Za-z0-9]{30,}"
)

# Operaciones peligrosas dentro de herramientas de agentes (LLM06), por nombre de llamada.
DANGEROUS_CALL = re.compile(
    r"^(eval|exec|execSync|spawn|spawnSync|execFile|os\.system|os\.popen|subprocess\.\w+|shutil\.rmtree"
    r"|os\.remove|os\.unlink|child_process\.\w+|fs\.(promises\.)?(unlink|unlinkSync|rm|rmSync|rmdir|writeFile"
    r"|writeFileSync)|requests\.(post|put|delete|patch)|smtplib\.\w+|.*\.(sendmail|send_mail|send_email|sendMail"
    r"|delete|deleteMany|deleteOne|destroy|drop_table|transfer|charge|refund))$"
)
# Llamadas que ejecutan SQL: peligrosas en una herramienta si el SQL es dinámico o de escritura.
SQL_EXEC_CALL = re.compile(r"\.(execute|executemany|executescript|query|raw|\$queryRawUnsafe|\$executeRawUnsafe)$")
DESTRUCTIVE_SQL = re.compile(r"\b(DELETE\s+FROM|DROP\s+(TABLE|DATABASE)|UPDATE\s+\w+\s+SET|INSERT\s+INTO|TRUNCATE|ALTER\s+TABLE|GRANT)\b", re.I)

# Sufijos de llamadas que invocan un LLM.
LLM_CALL_SUFFIXES = (
    "messages.create", "messages.stream", "messages.parse", "chat.completions.create",
    "chat.completions.parse", "completions.create", "responses.create", "responses.parse",
    "generate_content", "generate_content_async", "generateContent", "generateContentStream",
    "invoke_model", "converse", "chat.complete", "chat", "invoke", "ainvoke", "predict",
    "completion", "acompletion", "generateText", "streamText", "generateObject", "streamObject",
)
# Sufijos ambiguos: solo cuentan si el objeto parece un LLM.
AMBIGUOUS_SUFFIXES = {"chat", "invoke", "ainvoke", "predict", "completion", "acompletion"}
BARE_LLM_FUNCTIONS = {"completion", "acompletion", "generateText", "streamText", "generateObject", "streamObject"}
LLM_OBJ_HINT = re.compile(r"(llm|chain|agent|model|client|anthropic|openai|bedrock|gemini|litellm|chat)", re.I)
# Llamadas OpenAI-compatibles donde el límite de tokens es opcional (en Anthropic es obligatorio).
OPTIONAL_LIMIT_SUFFIXES = ("chat.completions.create", "responses.create", "generateText", "streamText")
TOKEN_LIMIT_KEYS = {"max_tokens", "max_completion_tokens", "max_output_tokens", "maxTokens", "maxOutputTokens",
                    "max_new_tokens"}


def is_llm_call_name(name: str) -> bool:
    name = re.sub(r"\s+", "", name)
    if name in BARE_LLM_FUNCTIONS:
        return True
    for suffix in LLM_CALL_SUFFIXES:
        if name == suffix or name.endswith("." + suffix):
            if suffix.split(".")[-1] in AMBIGUOUS_SUFFIXES:
                obj = name[: -len(suffix)].rstrip(".")
                return bool(LLM_OBJ_HINT.search(obj))
            return True
    return False


def needs_token_limit(name: str) -> bool:
    name = re.sub(r"\s+", "", name)
    return any(name == s or name.endswith("." + s) for s in OPTIONAL_LIMIT_SUFFIXES)


@dataclass
class FuncState:
    """Estado del análisis de flujo dentro de una función."""

    tainted: dict[str, str] = field(default_factory=dict)  # variable -> "user" | "external"
    llm_output: set[str] = field(default_factory=set)
    prompt_vars: set[str] = field(default_factory=set)

    def child(self) -> "FuncState":
        # Las funciones anidadas (callbacks, closures) ven las variables de la función que las contiene.
        return FuncState(dict(self.tainted), set(self.llm_output), set(self.prompt_vars))


class FindingSink:
    """Acumula hallazgos e inventario de un fichero, sin duplicados."""

    def __init__(self, engine: str, rel: str, lines: list[str]):
        self.engine = engine
        self.rel = rel
        self.lines = lines
        self.findings: list[Finding] = []
        self.inventory: list[AIComponent] = []
        self._seen: set[tuple[str, int]] = set()

    def snippet(self, start: int, end: int) -> str:
        return "\n".join(self.lines[max(0, start - 1): min(len(self.lines), end)])

    def add(self, rule_id: str, start: int, end: int | None = None, title: str | None = None, extra: str = ""):
        if (rule_id, start) in self._seen:
            return
        self._seen.add((rule_id, start))
        r = RULES[rule_id]
        end = end or start
        self.findings.append(Finding(
            engine=self.engine, rule_id=rule_id, category=Category.AI, severity=r.severity,
            title=title or r.title, message=(r.message + (" " + extra if extra else "")).strip(),
            file=self.rel, line=start, end_line=end, snippet=self.snippet(start, min(end, start + 15)),
            frameworks=[OWASP[r.owasp], r.cwe],
        ))

    def component(self, kind: str, name: str, line: int, detail: str = ""):
        self.inventory.append(AIComponent(kind=kind, name=name, file=self.rel, line=line, detail=detail[:300]))
