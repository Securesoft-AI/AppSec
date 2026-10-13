"""Analizador de seguridad de IA para Python, basado en el AST (flujo de datos dentro de cada función)."""

from __future__ import annotations

import ast
import re

from appsec_ai.engines.ai_common import (
    ACCESS_FILTER_KEYS, AUTHZ_IN_PROMPT, DANGEROUS_CALL, DESTRUCTIVE_SQL, RETRIEVAL_CALL, RETRIEVER_INVOKE,
    SECRET_IN_TEXT, SQL_EXEC_CALL, TOKEN_LIMIT_KEYS, VECTOR_QUERY_KEYS, FindingSink, FuncState, is_llm_call_name,
    needs_token_limit,
)

SDKS = {
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
    "langchain_openai": ("framework", "LangChain"),
    "langchain_anthropic": ("framework", "LangChain"),
    "langgraph": ("framework", "LangGraph"),
    "llama_index": ("framework", "LlamaIndex"),
    "crewai": ("framework", "CrewAI"),
    "autogen": ("framework", "AutoGen"),
    "agents": ("framework", "OpenAI Agents SDK"),
    "claude_agent_sdk": ("framework", "Claude Agent SDK"),
    "semantic_kernel": ("framework", "Semantic Kernel"),
    "pydantic_ai": ("framework", "Pydantic AI"),
    "mcp": ("mcp_server", "Model Context Protocol"),
    "fastmcp": ("mcp_server", "FastMCP"),
    "chromadb": ("vector_store", "Chroma"),
    "pinecone": ("vector_store", "Pinecone"),
    "weaviate": ("vector_store", "Weaviate"),
    "qdrant_client": ("vector_store", "Qdrant"),
    "faiss": ("vector_store", "FAISS"),
    "pgvector": ("vector_store", "pgvector"),
}

UNTRUSTED_SOURCES = re.compile(
    r"^(request\.(args|form|values|json|data|get_json|files|headers|cookies|body|query_params|path_params|GET|POST)"
    r"|flask\.request\.|input$|sys\.argv)"
)
EXTERNAL_CONTENT = re.compile(
    r"^(requests\.(get|post|request)|httpx\.(get|post)|urllib\.request\.urlopen|urlopen|os\.popen"
    r"|.*\.(read|read_text|load|load_and_split|page_content|get_text|similarity_search\w*|retrieve|get_relevant_documents))$"
)
CODE_EXEC_SINKS = {"eval", "exec", "compile", "os.system", "os.popen", "pickle.loads", "subprocess.run",
                   "subprocess.call", "subprocess.check_output", "subprocess.Popen", "subprocess.check_call",
                   "yaml.load", "yaml.unsafe_load", "marshal.loads", "__import__", "importlib.import_module"}
SQL_SINKS = re.compile(r"\.(execute|executemany|executescript|raw)$|^(sqlalchemy\.)?text$")
SSRF_SINKS = re.compile(r"^(requests\.(get|post|put|delete|patch|request)|httpx\.\w+|urlopen|urllib\.request\.urlopen)$")
FILE_SINKS = re.compile(r"^(open|os\.remove|os\.unlink|shutil\.rmtree|shutil\.move|os\.rename|Path|pathlib\.Path|send_file)$")
# Los logs de nivel debug suelen estar desactivados en producción: no se reportan.
LOG_SINKS = re.compile(r"^(print|(logging|logger|log)\.(info|warning|warn|error|exception|critical|log))$")
TOOL_DECORATORS = re.compile(r"(^|\.)(tool|function_tool|kernel_function|beta_tool)$")
SYSTEM_KWARGS = {"system", "instructions", "system_instruction", "system_prompt"}


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


def target_names(target: ast.AST) -> list[str]:
    """Variables que recibe una asignación. En `d[k] = v` solo cambia `d`, no `k`."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for e in target.elts for n in target_names(e)]
    if isinstance(target, ast.Starred):
        return target_names(target.value)
    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
        return [target.value.id]
    return []


def names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def string_parts(node: ast.AST) -> str:
    return "".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))


def has_interpolation(node: ast.AST) -> bool:
    """¿La expresión construye texto mezclando constantes con variables? (f-string, +, %, format)."""
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
    return is_llm_call_name(dotted(call.func))


class PythonAIAnalyzer(ast.NodeVisitor):
    def __init__(self, rel: str, source: str):
        self.out = FindingSink("ai-security", rel, source.splitlines())
        self.state = FuncState()
        self.constants: dict[str, ast.AST] = {}       # constantes de módulo (posibles prompts)
        self.mcp_servers: dict[str, bool] = {}        # variable -> tiene autenticación
        self.unfiltered_retrievers: set[str] = set()  # variables con as_retriever() sin filtro

    @property
    def findings(self):
        return self.out.findings

    @property
    def inventory(self):
        return self.out.inventory

    def add(self, rule: str, node: ast.AST, **kw):
        self.out.add(rule, node.lineno, getattr(node, "end_lineno", node.lineno), **kw)

    # -- flujo de datos -------------------------------------------------------------

    def taint_of(self, node: ast.AST) -> str | None:
        """'user' si depende de entrada del usuario, 'external' si de contenido externo."""
        # Leer contenido externo produce contenido externo aunque el destino lo elija el usuario:
        # la entrada del usuario dentro de esas llamadas no cuenta como 'user'.
        external = [n for n in ast.walk(node) if isinstance(n, ast.Call) and EXTERNAL_CONTENT.match(dotted(n))]
        inside_external = {id(x) for e in external for x in ast.walk(e)}
        kinds = {"external"} if external else set()
        for n in ast.walk(node):
            if id(n) in inside_external:
                continue
            if isinstance(n, (ast.Attribute, ast.Call, ast.Name)) and UNTRUSTED_SOURCES.match(dotted(n)):
                kinds.add("user")
            if isinstance(n, ast.Name) and n.id in self.state.tainted:
                kinds.add(self.state.tainted[n.id])
        if "user" in kinds:
            return "user"
        return "external" if kinds else None

    def depends_on_llm(self, node: ast.AST) -> bool:
        if names_in(node) & self.state.llm_output:
            return True
        return any(isinstance(n, ast.Call) and is_llm_call(n) for n in ast.walk(node))

    def resolve_text(self, node: ast.AST) -> str:
        """Texto literal de un prompt, resolviendo constantes de módulo."""
        if isinstance(node, ast.Name) and node.id in self.constants:
            node = self.constants[node.id]
        return string_parts(node)

    # -- inventario -----------------------------------------------------------------

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._inventory_module(alias.name, node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self._inventory_module(node.module, node)

    def _inventory_module(self, module: str, node: ast.AST):
        for prefix, (kind, label) in SDKS.items():
            if module == prefix or module.startswith(prefix + "."):
                self.out.component(kind, label, node.lineno, module)
                return

    # -- funciones y herramientas de agentes -------------------------------------------

    def visit_FunctionDef(self, node):
        outer = self.state
        self.state = outer.child() if outer is not self._module_state else FuncState()
        tool_decorators = [dotted(d) for d in node.decorator_list if TOOL_DECORATORS.search(dotted(d))]
        if tool_decorators:
            self._check_agent_tool(node, tool_decorators[0])
        self.generic_visit(node)
        self.state = outer

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Module(self, node: ast.Module):
        self._module_state = self.state
        self.generic_visit(node)

    def _check_agent_tool(self, node: ast.FunctionDef, decorator: str):
        is_mcp = bool(re.search(r"(mcp|server)", decorator, re.I))
        self.out.component("mcp_tool" if is_mcp else "agent_tool", node.name, node.lineno,
                           ast.get_docstring(node) or "")
        risky = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                name = dotted(n.func)
                if DANGEROUS_CALL.match(name):
                    risky.add(name)
                elif SQL_EXEC_CALL.search(name) and n.args:
                    q = n.args[0]
                    literal = isinstance(q, ast.Constant) and isinstance(q.value, str)
                    if not literal and not (isinstance(q, ast.JoinedStr) and not has_interpolation(q)):
                        if not DESTRUCTIVE_SQL.search(string_parts(q)):
                            risky.add("SQL dinámico")
            if isinstance(n, (ast.Constant, ast.JoinedStr)) and DESTRUCTIVE_SQL.search(string_parts(n)):
                risky.add("SQL de escritura")
        if risky:
            kind = "servidor MCP" if is_mcp else "agente"
            self.add("llm06-excessive-agency-tool", node,
                     title=f"Herramienta de {kind} '{node.name}' con acciones peligrosas",
                     extra=f"Operaciones sensibles detectadas: {', '.join(sorted(risky))}.")

    # -- asignaciones -------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign):
        self._track(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is not None:
            self._track([node.target], node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        # for fila in salida_llm: ... -> cada elemento hereda el origen de la colección.
        self._track([node.target], node.iter)
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def _track(self, targets: list[ast.AST], value: ast.AST):
        names = [n for t in targets for n in target_names(t)]
        if self.state is self._module_state and isinstance(value, (ast.Constant, ast.JoinedStr, ast.BinOp)):
            for name in names:
                self.constants[name] = value
        if isinstance(value, ast.Call) and dotted(value.func).split(".")[-1] == "FastMCP":
            for name in names:
                self.mcp_servers[name] = any(kw.arg == "auth" for kw in value.keywords)
                self.out.component("mcp_server", name, value.lineno, "FastMCP")
        if isinstance(value, ast.Call) and dotted(value.func).endswith(".as_retriever"):
            for name in names:
                if has_access_filter(value):
                    self.unfiltered_retrievers.discard(name)
                else:
                    self.unfiltered_retrievers.add(name)
        taint = self.taint_of(value)
        from_llm = self.depends_on_llm(value)
        for name in names:
            if from_llm:
                self.state.llm_output.add(name)
                self.state.tainted.pop(name, None)
            elif taint:
                self.state.tainted[name] = taint
            else:
                self.state.tainted.pop(name, None)
            if has_interpolation(value) and taint:
                self.state.prompt_vars.add(name)

    # -- llamadas -------------------------------------------------------------------------

    def visit_Call(self, node: ast.Call):
        name = dotted(node.func)
        if is_llm_call(node):
            self._check_llm_call(node, name)
        else:
            self._check_sink(node, name)
            self._check_agent_config(node, name)
            self._check_retrieval(node, name)
        self.generic_visit(node)

    def _check_llm_call(self, call: ast.Call, name: str):
        for kw in call.keywords:
            if kw.arg in ("model", "model_id", "modelId"):
                for n in ast.walk(kw.value):
                    if isinstance(n, ast.Constant) and isinstance(n.value, str):
                        self.out.component("model", n.value, call.lineno)

        if needs_token_limit(name) and not any(kw.arg in TOKEN_LIMIT_KEYS or kw.arg is None for kw in call.keywords):
            self.add("llm10-no-output-limit", call)

        system_args = [kw.value for kw in call.keywords if kw.arg in SYSTEM_KWARGS]
        for d in ast.walk(call):
            if isinstance(d, ast.Dict):
                pairs = {k.value: v for k, v in zip(d.keys, d.values) if isinstance(k, ast.Constant)}
                role = pairs.get("role")
                if isinstance(role, ast.Constant) and role.value in ("system", "developer") and "content" in pairs:
                    system_args.append(pairs["content"])
        for arg in system_args:
            if self.taint_of(arg):
                self.add("llm01-untrusted-input-in-system-prompt", call)
            if self.taint_of(arg) == "user":
                self.out.component("llm_entrypoint", name, call.lineno)
            prompt_text = self.resolve_text(arg)
            if SECRET_IN_TEXT.search(prompt_text):
                self.add("llm07-secret-in-system-prompt", call)
            if AUTHZ_IN_PROMPT.search(prompt_text):
                self.add("llm07-authorization-in-prompt", call)

        for arg in list(call.args) + [kw.value for kw in call.keywords if kw.arg not in ("model",)]:
            taint = self.taint_of(arg)
            if not taint:
                continue
            if taint == "user":
                # El usuario puede disparar esta llamada: lo usa la regla de rate limiting.
                self.out.component("llm_entrypoint", name, call.lineno)
            if taint == "external":
                self.add("llm01-indirect-prompt-injection", call)
            elif has_interpolation(arg) or names_in(arg) & self.state.prompt_vars:
                self.add("llm01-prompt-concatenation", call)

    def _check_sink(self, call: ast.Call, name: str):
        args = list(call.args) + [kw.value for kw in call.keywords]
        # Para SSRF, ficheros y SQL lo relevante es el primer argumento (URL, ruta o consulta).
        first = call.args[:1] + [kw.value for kw in call.keywords if kw.arg in ("url", "path", "file", "sql", "query")]
        shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value for kw in call.keywords)

        # getattr(obj, salida_llm) o tabla[salida_llm](...): el modelo elige qué se ejecuta.
        if isinstance(call.func, ast.Name) and call.func.id == "getattr" and len(call.args) >= 2:
            if self.depends_on_llm(call.args[1]):
                self.add("llm05-llm-output-selects-function", call)
            return
        if isinstance(call.func, ast.Subscript) and self.depends_on_llm(call.func.slice):
            self.add("llm05-llm-output-selects-function", call)
            return
        if name in CODE_EXEC_SINKS:
            if any(self.depends_on_llm(a) for a in args) and (not name.startswith("subprocess") or shell or name == "subprocess.Popen"):
                self.add("llm05-llm-output-to-code-exec", call, title=f"Salida del LLM ejecutada como código o comando ({name})")
        elif SQL_SINKS.search(name):
            if any(self.depends_on_llm(a) for a in first):
                self.add("llm05-llm-output-to-sql", call)
        elif SSRF_SINKS.match(name):
            if any(self.depends_on_llm(a) for a in first):
                self.add("llm05-llm-output-to-request", call)
        elif FILE_SINKS.match(name):
            if any(self.depends_on_llm(a) for a in first):
                self.add("llm05-llm-output-to-filesystem", call)
        elif LOG_SINKS.match(name):
            if any(self.depends_on_llm(a) for a in args):
                self.add("llm02-llm-io-logged", call)

    def _check_retrieval(self, call: ast.Call, name: str):
        """LLM08: búsqueda en un vector store con la pregunta del usuario y sin filtro de acceso."""
        obj = name.rsplit(".", 1)[0]
        kwargs = {kw.arg for kw in call.keywords}
        is_search = RETRIEVAL_CALL.search(name) or (
            name.endswith(".query") and kwargs & VECTOR_QUERY_KEYS)  # Chroma / Pinecone
        is_retriever = RETRIEVER_INVOKE.search(name) and obj in self.unfiltered_retrievers
        if not (is_search or is_retriever) or (is_search and has_access_filter(call)):
            return
        query = call.args[:1] + [kw.value for kw in call.keywords if kw.arg in (
            "query", "input", "query_texts", "query_embeddings", "vector")]
        if any(self.taint_of(a) == "user" for a in query):
            self.add("llm08-rag-without-access-filter", call)

    def _check_agent_config(self, call: ast.Call, name: str):
        last = name.split(".")[-1]
        if last in ("AgentExecutor", "initialize_agent", "create_react_agent", "AgentExecutor.from_agent_and_tools"):
            for kw in call.keywords:
                if kw.arg == "max_iterations" and isinstance(kw.value, ast.Constant) and kw.value.value is None:
                    self.add("llm10-unbounded-agent-loop", call)
        if last in ("run", "run_async", "http_app", "sse_app", "streamable_http_app"):
            obj = name.rsplit(".", 1)[0]
            if obj in self.mcp_servers and not self.mcp_servers[obj]:
                transport = next((kw.value for kw in call.keywords if kw.arg == "transport"), None)
                over_http = last != "run" and last != "run_async" or (
                    isinstance(transport, ast.Constant) and transport.value in ("sse", "http", "streamable-http")
                )
                if over_http:
                    self.add("llm06-mcp-http-without-auth", call)

    # -- returns: HTML ----------------------------------------------------------------------

    def visit_Return(self, node: ast.Return):
        if node.value is not None and self.depends_on_llm(node.value):
            if re.search(r"<[a-zA-Z]", string_parts(node.value)):
                self.add("llm05-llm-output-to-html", node)
        self.generic_visit(node)


def has_access_filter(call: ast.Call) -> bool:
    """¿La llamada restringe los documentos? (filter=..., where=..., search_kwargs={"filter": ...})."""
    for kw in call.keywords:
        if kw.arg in ACCESS_FILTER_KEYS:
            return True
        if kw.arg == "search_kwargs" and isinstance(kw.value, ast.Dict):
            if any(isinstance(k, ast.Constant) and k.value in ACCESS_FILTER_KEYS for k in kw.value.keys):
                return True
        if kw.arg is None:  # **kwargs: no se puede saber
            return True
    return False


def analyze_python(rel: str, source: str):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], []
    analyzer = PythonAIAnalyzer(rel, source)
    analyzer.visit(tree)
    return analyzer.findings, analyzer.inventory
