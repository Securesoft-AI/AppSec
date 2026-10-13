"""Motor propio de seguridad de IA: inventario de uso de LLMs y riesgos del OWASP Top 10 para LLM.

Python se analiza con el AST (flujo de datos simple dentro de cada función).
JavaScript/TypeScript se analiza con heurísticas por línea. Ambos producen candidatos
que después el triage con Claude confirma o descarta.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from appsec_ai.engines.base import IGNORED_DIRS, Engine
from appsec_ai.models import AIComponent, Category, Finding, Severity

OWASP = {
    "LLM01": "OWASP-LLM01:2025 Prompt Injection",
    "LLM02": "OWASP-LLM02:2025 Sensitive Information Disclosure",
    "LLM05": "OWASP-LLM05:2025 Improper Output Handling",
    "LLM06": "OWASP-LLM06:2025 Excessive Agency",
    "LLM07": "OWASP-LLM07:2025 System Prompt Leakage",
}

# --- Inventario -----------------------------------------------------------------

PY_SDKS = {
    "anthropic": ("llm_sdk", "Anthropic"),
    "openai": ("llm_sdk", "OpenAI"),
    "google.generativeai": ("llm_sdk", "Google Gemini"),
    "google.genai": ("llm_sdk", "Google Gen AI"),
    "vertexai": ("llm_sdk", "Vertex AI"),
    "mistralai": ("llm_sdk", "Mistral"),
    "cohere": ("llm_sdk", "Cohere"),
    "ollama": ("llm_sdk", "Ollama"),
    "litellm": ("llm_sdk", "LiteLLM"),
    "transformers": ("llm_sdk", "Hugging Face Transformers"),
    "langchain": ("framework", "LangChain"),
    "langchain_core": ("framework", "LangChain"),
    "langchain_community": ("framework", "LangChain"),
    "langgraph": ("framework", "LangGraph"),
    "llama_index": ("framework", "LlamaIndex"),
    "crewai": ("framework", "CrewAI"),
    "autogen": ("framework", "AutoGen"),
    "agents": ("framework", "OpenAI Agents SDK"),
    "claude_agent_sdk": ("framework", "Claude Agent SDK"),
    "semantic_kernel": ("framework", "Semantic Kernel"),
    "mcp": ("mcp_server", "Model Context Protocol"),
    "fastmcp": ("mcp_server", "FastMCP"),
    "chromadb": ("vector_store", "Chroma"),
    "pinecone": ("vector_store", "Pinecone"),
    "weaviate": ("vector_store", "Weaviate"),
    "qdrant_client": ("vector_store", "Qdrant"),
    "faiss": ("vector_store", "FAISS"),
    "pgvector": ("vector_store", "pgvector"),
}

JS_SDKS = {
    "@anthropic-ai/sdk": ("llm_sdk", "Anthropic"),
    "openai": ("llm_sdk", "OpenAI"),
    "@google/generative-ai": ("llm_sdk", "Google Gemini"),
    "@google/genai": ("llm_sdk", "Google Gen AI"),
    "@aws-sdk/client-bedrock-runtime": ("llm_sdk", "AWS Bedrock"),
    "ai": ("framework", "Vercel AI SDK"),
    "langchain": ("framework", "LangChain.js"),
    "@langchain/core": ("framework", "LangChain.js"),
    "@langchain/langgraph": ("framework", "LangGraph.js"),
    "llamaindex": ("framework", "LlamaIndex.ts"),
    "@modelcontextprotocol/sdk": ("mcp_server", "Model Context Protocol"),
    "@pinecone-database/pinecone": ("vector_store", "Pinecone"),
    "chromadb": ("vector_store", "Chroma"),
}

MODEL_RE = re.compile(
    r"""["']((?:claude|gpt|o[134]|gemini|mistral|mixtral|llama|command|anthropic\.claude)[\w.:\-/]*)["']"""
)

# --- Fuentes, llamadas a LLM y sumideros (Python) ----------------------------------

LLM_CALL_SUFFIXES = (
    "messages.create", "messages.stream", "messages.parse", "chat.completions.create",
    "completions.create", "responses.create", "generate_content", "generate_content_async",
    "invoke_model", "converse", "chat.complete", "chat", "invoke", "ainvoke", "predict",
    "completion", "acompletion", "query", "run",
)
# Sufijos ambiguos ("run", "query", "invoke"...) solo cuentan si el objeto parece un LLM.
AMBIGUOUS_SUFFIXES = {"chat", "invoke", "ainvoke", "predict", "query", "run", "completion", "acompletion"}
LLM_OBJ_HINT = re.compile(r"(llm|chain|agent|model|client|anthropic|openai|bedrock|gemini|litellm)", re.I)

UNTRUSTED_SOURCES = re.compile(
    r"^(request\.(args|form|values|json|data|get_json|files|headers|cookies|body|query_params|path_params)"
    r"|flask\.request\.|input$|sys\.argv)"
)
EXTERNAL_CONTENT = re.compile(
    r"^(requests\.(get|post|request)|httpx\.(get|post)|urllib\.request\.urlopen|urlopen|os\.popen"
    r"|.*\.(read|read_text|load|page_content|get_text|similarity_search|retrieve|search))$"
)

CODE_EXEC_SINKS = {"eval", "exec", "compile", "os.system", "os.popen", "pickle.loads",
                   "subprocess.run", "subprocess.call", "subprocess.check_output",
                   "subprocess.Popen", "subprocess.check_call", "yaml.load",
                   "yaml.unsafe_load", "marshal.loads", "__import__", "importlib.import_module"}
SQL_SINKS = re.compile(r"\.(execute|executemany|executescript|raw|text)$")
SSRF_SINKS = re.compile(r"^(requests\.(get|post|put|delete|request)|httpx\.\w+|urlopen|urllib\.request\.urlopen)$")
FILE_SINKS = re.compile(r"^(open|os\.remove|os\.unlink|shutil\.rmtree|shutil\.move|os\.rename|Path)$")
LOG_SINKS = re.compile(r"^(print|logging\.\w+|logger\.\w+|log\.\w+)$")

DANGEROUS_TOOL_CALLS = re.compile(
    r"^(eval|exec|os\.system|os\.popen|subprocess\.\w+|shutil\.rmtree|os\.remove|os\.unlink"
    r"|requests\.(post|put|delete|patch)|smtplib\.\w+|.*\.sendmail|.*\.execute|.*\.executescript"
    r"|.*\.delete|.*\.drop|.*\.transfer|.*\.charge|.*\.refund|.*\.send_email)$"
)
DESTRUCTIVE_SQL = re.compile(r"\b(DELETE|DROP|UPDATE|INSERT|TRUNCATE|ALTER|GRANT)\b", re.I)

TOOL_DECORATORS = re.compile(r"(^|\.)(tool|function_tool|kernel_function|beta_tool)$")


def dotted(node: ast.AST) -> str:
    """Nombre con puntos de una expresión: `client.messages.create`, `request.args.get`..."""
    parts = []
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Subscript):
            node = node.value
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            break
        else:
            break
    return ".".join(reversed(parts))


def names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def has_interpolation(node: ast.AST) -> bool:
    """¿La expresión construye texto mezclando constantes con variables? (f-string, +, format, %)."""
    for n in ast.walk(node):
        if isinstance(n, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in n.values):
            return True
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
            if any(isinstance(s, ast.Constant) and isinstance(s.value, str) for s in ast.walk(n)):
                return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("format", "join"):
            return True
    return False


def is_llm_call(call: ast.Call) -> bool:
    name = dotted(call.func)
    for suffix in LLM_CALL_SUFFIXES:
        if name == suffix or name.endswith("." + suffix):
            if suffix.split(".")[-1] in AMBIGUOUS_SUFFIXES:
                obj = name[: -len(suffix)].rstrip(".")
                return bool(LLM_OBJ_HINT.search(obj)) or name in ("completion", "acompletion")
            return True
    return False


@dataclass
class _FuncState:
    tainted: dict[str, str] = field(default_factory=dict)      # var -> "user" | "external"
    llm_output: set[str] = field(default_factory=set)
    prompt_vars: dict[str, ast.AST] = field(default_factory=dict)


class _PyAnalyzer(ast.NodeVisitor):
    def __init__(self, rel: str, source: str):
        self.rel = rel
        self.lines = source.splitlines()
        self.findings: list[Finding] = []
        self.inventory: list[AIComponent] = []
        self.state = _FuncState()
        self._seen: set[tuple[str, int]] = set()

    # -- utilidades
    def snippet(self, node: ast.AST, ctx: int = 0) -> str:
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start)
        lo, hi = max(0, start - 1 - ctx), min(len(self.lines), end + ctx)
        return "\n".join(self.lines[lo:hi])

    def add(self, rule: str, owasp: str, sev: Severity, title: str, msg: str, node: ast.AST, cwe: str = ""):
        key = (rule, node.lineno)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(
            engine="ai-security", rule_id=rule, category=Category.AI, severity=sev,
            title=title, message=msg, file=self.rel, line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno), snippet=self.snippet(node),
            frameworks=[OWASP[owasp]] + ([cwe] if cwe else []),
        ))

    def taint_of(self, node: ast.AST) -> str | None:
        """'user' si depende de entrada del usuario, 'external' si de contenido externo."""
        # El resultado de leer contenido externo es externo aunque el destino lo elija el usuario.
        if isinstance(node, ast.Call) and EXTERNAL_CONTENT.match(dotted(node)):
            return "external"
        kinds = set()
        for n in ast.walk(node):
            if isinstance(n, (ast.Attribute, ast.Call, ast.Name)):
                d = dotted(n)
                if UNTRUSTED_SOURCES.match(d):
                    kinds.add("user")
                elif isinstance(n, ast.Call) and EXTERNAL_CONTENT.match(d):
                    kinds.add("external")
            if isinstance(n, ast.Name) and n.id in self.state.tainted:
                kinds.add(self.state.tainted[n.id])
        if "user" in kinds:
            return "user"
        return "external" if kinds else None

    def depends_on_llm(self, node: ast.AST) -> bool:
        if names_in(node) & self.state.llm_output:
            return True
        return any(isinstance(n, ast.Call) and is_llm_call(n) for n in ast.walk(node))

    # -- inventario
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._inventory_module(alias.name, node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self._inventory_module(node.module, node)

    def _inventory_module(self, module: str, node: ast.AST):
        for prefix, (kind, label) in PY_SDKS.items():
            if module == prefix or module.startswith(prefix + "."):
                self.inventory.append(AIComponent(kind=kind, name=label, file=self.rel,
                                                  line=node.lineno, detail=module))
                return

    # -- funciones
    def visit_FunctionDef(self, node):  # también AsyncFunctionDef
        outer = self.state
        self.state = _FuncState()
        if any(TOOL_DECORATORS.search(dotted(d)) for d in node.decorator_list):
            self._check_agent_tool(node)
        self.generic_visit(node)
        self.state = outer

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_agent_tool(self, node: ast.FunctionDef):
        self.inventory.append(AIComponent(kind="agent_tool", name=node.name, file=self.rel,
                                          line=node.lineno, detail=ast.get_docstring(node) or ""))
        risky = []
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                name = dotted(n.func)
                if DANGEROUS_TOOL_CALLS.match(name):
                    risky.append(name)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and DESTRUCTIVE_SQL.search(n.value):
                risky.append("SQL de escritura")
            if isinstance(n, ast.JoinedStr):
                text = "".join(v.value for v in n.values if isinstance(v, ast.Constant))
                if DESTRUCTIVE_SQL.search(text):
                    risky.append("SQL de escritura")
        if risky:
            self.add(
                "llm06-excessive-agency-tool", "LLM06", Severity.HIGH,
                f"Herramienta de agente '{node.name}' con acciones peligrosas",
                "El LLM puede invocar esta herramienta con argumentos controlados por un atacante "
                f"(vía prompt injection). Operaciones sensibles detectadas: {', '.join(sorted(set(risky)))}. "
                "Requiere confirmación humana, mínimo privilegio y validación estricta de argumentos.",
                node, "CWE-250",
            )

    # -- asignaciones: propagación de contaminación y salidas del LLM
    def visit_Assign(self, node: ast.Assign):
        self._track(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is not None:
            self._track([node.target], node.value)
        self.generic_visit(node)

    def _track(self, targets: list[ast.AST], value: ast.AST):
        names = [n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)]
        taint = self.taint_of(value)
        from_llm = self.depends_on_llm(value)
        for name in names:
            if from_llm:
                self.state.llm_output.add(name)
                self.state.tainted.pop(name, None)
            elif taint:
                self.state.tainted[name] = taint
            if has_interpolation(value) and taint:
                self.state.prompt_vars[name] = value

    # -- llamadas: llamadas al LLM y sumideros
    def visit_Call(self, node: ast.Call):
        name = dotted(node.func)
        if is_llm_call(node):
            self._check_llm_call(node)
        else:
            self._check_sink(node, name)
        self.generic_visit(node)

    def _check_llm_call(self, call: ast.Call):
        for kw in call.keywords:
            if kw.arg == "model":
                for n in ast.walk(kw.value):
                    if isinstance(n, ast.Constant) and isinstance(n.value, str):
                        self.inventory.append(AIComponent(kind="model", name=n.value, file=self.rel, line=call.lineno))
        system_args = [kw.value for kw in call.keywords if kw.arg in ("system", "instructions", "system_instruction")]
        system_args += [
            d.values[i] for d in ast.walk(call) if isinstance(d, ast.Dict)
            for i, k in enumerate(d.keys)
            if isinstance(k, ast.Constant) and k.value == "content"
            and any(isinstance(kk, ast.Constant) and kk.value == "role" and isinstance(vv, ast.Constant)
                    and vv.value in ("system", "developer") for kk, vv in zip(d.keys, d.values))
        ]
        for arg in system_args:
            if self.taint_of(arg):
                self.add(
                    "llm01-untrusted-input-in-system-prompt", "LLM01", Severity.HIGH,
                    "Entrada no confiable dentro del prompt de sistema",
                    "Datos controlados por el usuario o externos se insertan en las instrucciones de sistema, "
                    "lo que permite sobrescribir el comportamiento del modelo.", call, "CWE-77",
                )
        for arg in list(call.args) + [kw.value for kw in call.keywords if kw.arg not in ("model",)]:
            taint = self.taint_of(arg)
            if not taint:
                continue
            mixed = has_interpolation(arg) or bool(names_in(arg) & set(self.state.prompt_vars))
            if taint == "external":
                self.add(
                    "llm01-indirect-prompt-injection", "LLM01", Severity.MEDIUM,
                    "Contenido externo no confiable enviado al LLM (prompt injection indirecta)",
                    "Contenido obtenido de la red, ficheros o un vector store se mezcla con las instrucciones. "
                    "Un atacante que controle ese contenido puede dar órdenes al modelo.", call, "CWE-77",
                )
            elif mixed:
                self.add(
                    "llm01-prompt-concatenation", "LLM01", Severity.MEDIUM,
                    "Entrada del usuario concatenada con las instrucciones del prompt",
                    "La entrada del usuario se mezcla con las instrucciones en el mismo texto, sin separación "
                    "ni delimitadores. Mantén las instrucciones en el prompt de sistema y pasa la entrada como "
                    "mensaje de usuario independiente.", call, "CWE-77",
                )

    def _check_sink(self, call: ast.Call, name: str):
        args = list(call.args) + [kw.value for kw in call.keywords]
        if not any(self.depends_on_llm(a) for a in args):
            return
        shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value for kw in call.keywords)
        if name in CODE_EXEC_SINKS and (not name.startswith("subprocess") or shell or name == "subprocess.Popen"):
            self.add("llm05-llm-output-to-code-exec", "LLM05", Severity.CRITICAL,
                     f"Salida del LLM ejecutada como código/comando ({name})",
                     "La respuesta del modelo se ejecuta directamente. Con prompt injection esto es ejecución "
                     "remota de código.", call, "CWE-94")
        elif SQL_SINKS.search(name):
            self.add("llm05-llm-output-to-sql", "LLM05", Severity.HIGH,
                     "Salida del LLM ejecutada como SQL",
                     "La consulta generada por el modelo se ejecuta sin validación: un atacante puede leer o "
                     "borrar datos. Usa consultas parametrizadas, lista blanca de operaciones y un usuario de BD "
                     "de solo lectura.", call, "CWE-89")
        elif SSRF_SINKS.match(name):
            self.add("llm05-llm-output-to-request", "LLM05", Severity.HIGH,
                     "Salida del LLM usada como destino de una petición HTTP (SSRF)",
                     "El modelo decide a qué URL se conecta el servidor.", call, "CWE-918")
        elif FILE_SINKS.match(name):
            self.add("llm05-llm-output-to-filesystem", "LLM05", Severity.HIGH,
                     "Salida del LLM usada en operaciones de sistema de ficheros",
                     "El modelo controla rutas de ficheros (path traversal / borrado).", call, "CWE-22")
        elif LOG_SINKS.match(name):
            self.add("llm02-llm-io-logged", "LLM02", Severity.LOW,
                     "Entrada/salida del LLM escrita en logs",
                     "Los prompts y respuestas pueden contener datos personales o secretos; revisa la "
                     "retención y el enmascarado de logs.", call, "CWE-532")

    def visit_Return(self, node: ast.Return):
        if node.value is not None and self.depends_on_llm(node.value):
            text = "".join(
                n.value for n in ast.walk(node.value) if isinstance(n, ast.Constant) and isinstance(n.value, str)
            )
            if re.search(r"<\w+", text):
                self.add("llm05-llm-output-to-html", "LLM05", Severity.MEDIUM,
                         "Salida del LLM insertada en HTML sin escapar (XSS)",
                         "La respuesta del modelo se devuelve dentro de HTML. Escápala o renderízala como texto.",
                         node, "CWE-79")
        self.generic_visit(node)


# --- JavaScript / TypeScript (heurístico) -------------------------------------------

JS_IMPORT_RE = re.compile(r"""(?:from\s+|require\(\s*)["']([^"']+)["']""")
JS_USER_INPUT_RE = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*.*\breq(?:uest)?\.(?:body|query|params)\b")
JS_LLM_OUTPUT_RE = re.compile(
    r"\b(?:const|let|var)\s+(\w+)\s*=\s*.*(?:choices\[0\]\.message\.content|content\[0\]\.text"
    r"|\.output_text|response\.text\(\)|\.generateText\(|\.text\b)"
)
JS_SINKS = [
    (re.compile(r"\b(?:eval|exec|execSync|spawn|new Function)\s*\("), "llm05-llm-output-to-code-exec",
     Severity.CRITICAL, "Salida del LLM ejecutada como código/comando", "CWE-94"),
    (re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML|\.send\(\s*`<|document\.write\("),
     "llm05-llm-output-to-html", Severity.MEDIUM, "Salida del LLM insertada en HTML sin escapar (XSS)", "CWE-79"),
    (re.compile(r"\.(?:query|execute|raw)\s*\("), "llm05-llm-output-to-sql", Severity.HIGH,
     "Salida del LLM ejecutada como SQL", "CWE-89"),
    (re.compile(r"\bfetch\s*\(|axios\.\w+\s*\("), "llm05-llm-output-to-request", Severity.HIGH,
     "Salida del LLM usada como destino de una petición HTTP (SSRF)", "CWE-918"),
]


def analyze_js(rel: str, source: str) -> tuple[list[Finding], list[AIComponent]]:
    findings: list[Finding] = []
    inventory: list[AIComponent] = []
    user_vars: set[str] = set()
    llm_vars: set[str] = set()
    for i, line in enumerate(source.splitlines(), start=1):
        for mod in JS_IMPORT_RE.findall(line):
            if mod in JS_SDKS:
                kind, label = JS_SDKS[mod]
                inventory.append(AIComponent(kind=kind, name=label, file=rel, line=i, detail=mod))
        for m in MODEL_RE.findall(line):
            if "model" in line:
                inventory.append(AIComponent(kind="model", name=m, file=rel, line=i))
        if m := JS_USER_INPUT_RE.search(line):
            user_vars.add(m.group(1))
        if m := JS_LLM_OUTPUT_RE.search(line):
            llm_vars.add(m.group(1))
            continue
        used = {v for v in user_vars if re.search(rf"\b{v}\b", line)}
        if used and re.search(r"role\s*:\s*[\"'](system|developer)[\"']", line):
            findings.append(Finding(
                engine="ai-security", rule_id="llm01-untrusted-input-in-system-prompt", category=Category.AI,
                severity=Severity.HIGH, title="Entrada no confiable dentro del prompt de sistema",
                message="La entrada del usuario se inserta en las instrucciones de sistema.",
                file=rel, line=i, end_line=i, snippet=line.strip(), frameworks=[OWASP["LLM01"], "CWE-77"],
            ))
        llm_used = {v for v in llm_vars if re.search(rf"\b{v}\b", line)}
        if llm_used:
            for rx, rule, sev, title, cwe in JS_SINKS:
                if rx.search(line):
                    findings.append(Finding(
                        engine="ai-security", rule_id=rule, category=Category.AI, severity=sev, title=title,
                        message=f"La variable '{', '.join(sorted(llm_used))}' contiene la respuesta del modelo.",
                        file=rel, line=i, end_line=i, snippet=line.strip(),
                        frameworks=[OWASP["LLM05"], cwe],
                    ))
                    break
    return findings, inventory


# --- Motor -----------------------------------------------------------------------

PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
MAX_FILE_BYTES = 1_000_000


def iter_source_files(target: Path, exts: set[str]):
    for path in sorted(target.rglob("*")):
        if path.suffix in exts and path.is_file() and not (set(path.relative_to(target).parts) & IGNORED_DIRS):
            if path.stat().st_size <= MAX_FILE_BYTES:
                yield path


class AISecurityEngine(Engine):
    name = "ai-security"

    def __init__(self):
        self.inventory: list[AIComponent] = []

    def run(self, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        self.inventory = []
        for path in iter_source_files(target, PY_EXT | JS_EXT):
            rel = str(path.relative_to(target))
            source = path.read_text(errors="replace")
            if path.suffix in PY_EXT:
                try:
                    tree = ast.parse(source)
                except SyntaxError:
                    continue
                analyzer = _PyAnalyzer(rel, source)
                analyzer.visit(tree)
                findings += analyzer.findings
                self.inventory += analyzer.inventory
            else:
                f, inv = analyze_js(rel, source)
                findings += f
                self.inventory += inv
        self.inventory = _dedupe_inventory(self.inventory)
        return findings


def _dedupe_inventory(items: list[AIComponent]) -> list[AIComponent]:
    seen, out = set(), []
    for c in items:
        key = (c.kind, c.name, c.file)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out
