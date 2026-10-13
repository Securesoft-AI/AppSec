"""Analizador de seguridad de IA para JavaScript/TypeScript basado en tree-sitter.

Aplica el mismo análisis de flujo que el de Python: fuentes no confiables (req.body, req.query...),
salidas del LLM y sumideros peligrosos, dentro de cada función y de sus callbacks anidados.
"""

from __future__ import annotations

import re
from functools import lru_cache

from tree_sitter import Language, Node, Parser

from appsec_ai.engines.ai_common import (
    ACCESS_FILTER_KEYS, AUTHZ_IN_PROMPT, DANGEROUS_CALL, DESTRUCTIVE_SQL, RETRIEVAL_CALL, RETRIEVER_INVOKE,
    SECRET_IN_TEXT, SQL_EXEC_CALL, TOKEN_LIMIT_KEYS, VECTOR_QUERY_KEYS, FindingSink, FuncState, is_llm_call_name,
    needs_token_limit,
)

SDKS = {
    "@anthropic-ai/sdk": ("llm_sdk", "Anthropic"),
    "@anthropic-ai/claude-agent-sdk": ("framework", "Claude Agent SDK"),
    "openai": ("llm_sdk", "OpenAI"),
    "@google/generative-ai": ("llm_sdk", "Google Gemini"),
    "@google/genai": ("llm_sdk", "Google Gen AI"),
    "@aws-sdk/client-bedrock-runtime": ("llm_sdk", "AWS Bedrock"),
    "@mistralai/mistralai": ("llm_sdk", "Mistral"),
    "ollama": ("llm_sdk", "Ollama"),
    "ai": ("framework", "Vercel AI SDK"),
    "@ai-sdk/openai": ("framework", "Vercel AI SDK"),
    "@ai-sdk/anthropic": ("framework", "Vercel AI SDK"),
    "langchain": ("framework", "LangChain.js"),
    "@langchain/core": ("framework", "LangChain.js"),
    "@langchain/openai": ("framework", "LangChain.js"),
    "@langchain/anthropic": ("framework", "LangChain.js"),
    "@langchain/langgraph": ("framework", "LangGraph.js"),
    "llamaindex": ("framework", "LlamaIndex.ts"),
    "@openai/agents": ("framework", "OpenAI Agents SDK"),
    "@mastra/core": ("framework", "Mastra"),
    "@modelcontextprotocol/sdk": ("mcp_server", "Model Context Protocol"),
    "@pinecone-database/pinecone": ("vector_store", "Pinecone"),
    "chromadb": ("vector_store", "Chroma"),
    "@qdrant/js-client-rest": ("vector_store", "Qdrant"),
}

FUNCTION_TYPES = {"function_declaration", "function_expression", "function", "arrow_function",
                  "method_definition", "generator_function_declaration", "generator_function"}
USER_INPUT = re.compile(
    r"^(req|request|ctx\.request|event)\.(body|query|params|headers|cookies|queryStringParameters)\b"
    r"|^(await\s+)?(req|request)\.(json|formData|text)\(\)"
    r"|searchParams\.get\(|formData\.get\("
)
EXTERNAL_CONTENT = re.compile(
    r"^(fetch|axios(\.\w+)?|got|fs\.(promises\.)?readFile(Sync)?|readFile(Sync)?)$"
    r"|\.(text|json|similaritySearch\w*|getRelevantDocuments|retrieve|load|loadAndSplit)$"
)
CODE_EXEC = re.compile(r"^(eval|Function|exec|execSync|spawn|spawnSync|execFile|execFileSync"
                       r"|(child_process|cp|childProcess)\.\w+|vm\.run\w+)$")
SQL_SINK = re.compile(r"^(\w*(db|pool|client|conn|connection|knex|prisma|sequelize|sql|database|pg|mysql)\w*)"
                      r"\.(query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)$", re.I)
SSRF_SINK = re.compile(r"^(fetch|got|axios(\.(get|post|put|delete|patch|request))?|https?\.(get|request)|request)$")
FILE_SINK = re.compile(r"^fs\.(promises\.)?(writeFile|writeFileSync|appendFile\w*|unlink\w*|rm\w*|readFile\w*"
                       r"|createReadStream|createWriteStream)$|^\w+\.(sendFile|download)$")
# Los logs de nivel debug suelen estar desactivados en producción: no se reportan.
LOG_SINK = re.compile(r"^(console\.(log|info|warn|error)|(logger|log)\.(info|warn|warning|error|fatal|log))$")
HTML_SINK = re.compile(r"^(\w+\.(send|write|end)|document\.write(ln)?)$")
TOOL_FACTORY = re.compile(r"(^|\.)(tool|registerTool|addTool|createTool)$")
TOOL_CLASSES = re.compile(r"^(DynamicStructuredTool|DynamicTool|StructuredTool|FunctionTool|Tool)$")
PROMPT_KEYS = {"content", "prompt", "input", "text", "query", "question", "messages", "contents"}
SYSTEM_KEYS = {"system", "instructions", "systemInstruction", "system_prompt", "systemPrompt"}


@lru_cache(maxsize=None)
def _parser(kind: str) -> Parser:
    if kind == "js":
        import tree_sitter_javascript as tsjs

        return Parser(Language(tsjs.language()))
    import tree_sitter_typescript as tsts

    return Parser(Language(tsts.language_tsx() if kind == "tsx" else tsts.language_typescript()))


def parser_for(suffix: str) -> Parser:
    if suffix == ".ts":
        return _parser("ts")
    if suffix == ".tsx":
        return _parser("tsx")
    return _parser("js")


def text(node: Node | None) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def call_name(node: Node) -> str:
    """Nombre normalizado de la función llamada: `openai.chat.completions.create`."""
    fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
    name = re.sub(r"\s+", "", text(fn)).replace("?.", ".").replace("!", "")
    return re.sub(r"<[^()]*>$", "", name)


def walk(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


IDENTIFIER_TYPES = ("identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern")


def identifiers(node: Node) -> set[str]:
    return {text(n) for n in walk(node) if n.type in IDENTIFIER_TYPES}


def string_value(node: Node) -> str:
    return "".join(text(n) for n in walk(node) if n.type in ("string_fragment", "template_string"))


def has_interpolation(node: Node) -> bool:
    for n in walk(node):
        if n.type == "template_substitution":
            return True
        if n.type == "binary_expression" and text(n.child_by_field_name("operator")) == "+":
            if any(c.type in ("string", "template_string") for c in walk(n)):
                return True
        if n.type == "call_expression" and call_name(n).endswith((".join", ".concat", ".replace")):
            return True
    return False


def pairs_of(node: Node) -> dict[str, Node]:
    out = {}
    for c in node.named_children:
        if c.type == "pair":
            key = c.child_by_field_name("key")
            k = string_value(key) if key is not None and key.type == "string" else text(key)
            out[k] = c.child_by_field_name("value")
        elif c.type == "shorthand_property_identifier":
            out[text(c)] = c
    return out


class JSAIAnalyzer:
    def __init__(self, rel: str, source: bytes, parser: Parser):
        self.source = source
        self.out = FindingSink("ai-security", rel, source.decode("utf-8", errors="replace").splitlines())
        self.tree = parser.parse(source)
        self.constants: dict[str, Node] = {}
        self.unfiltered_retrievers: set[str] = set()  # variables con asRetriever() sin filtro

    def line(self, node: Node) -> int:
        return node.start_point[0] + 1

    def add(self, rule: str, node: Node, **kw):
        self.out.add(rule, self.line(node), node.end_point[0] + 1, **kw)

    def run(self):
        self.visit(self.tree.root_node, FuncState())
        self._check_mcp_transport()
        return self.out.findings, self.out.inventory

    # -- flujo de datos -----------------------------------------------------------------

    def taint_of(self, node: Node, state: FuncState) -> str | None:
        """'user' si depende de entrada del usuario, 'external' si de contenido descargado o leído.

        El resultado de descargar o leer algo es contenido externo aunque la URL o la ruta las
        elija el usuario, así que la entrada del usuario dentro de esas llamadas no cuenta como 'user'.
        """
        external = [n for n in walk(node) if n.type == "call_expression" and EXTERNAL_CONTENT.search(call_name(n))
                    and not USER_INPUT.search(text(n))]

        def inside_external(n: Node) -> bool:
            return any(e.start_byte <= n.start_byte and n.end_byte <= e.end_byte for e in external)

        kinds = {"external"} if external else set()
        for n in walk(node):
            if inside_external(n):
                continue
            if n.type in ("member_expression", "call_expression", "await_expression") and USER_INPUT.search(text(n)):
                kinds.add("user")
            elif n.type in IDENTIFIER_TYPES and text(n) in state.tainted:
                kinds.add(state.tainted[text(n)])
        if "user" in kinds:
            return "user"
        return "external" if kinds else None

    def depends_on_llm(self, node: Node, state: FuncState) -> bool:
        if identifiers(node) & state.llm_output:
            return True
        return any(n.type == "call_expression" and is_llm_call_name(call_name(n)) for n in walk(node))

    # -- recorrido ------------------------------------------------------------------------

    def visit(self, node: Node, state: FuncState):
        t = node.type
        if t in FUNCTION_TYPES:
            state = state.child()
        elif t == "import_statement":
            self._inventory_module(string_value(node.child_by_field_name("source")), node)
        elif t == "variable_declarator":
            name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if value is not None:
                self._track(name, value, state)
        elif t == "assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is not None and left.type == "member_expression":
                prop = text(left.child_by_field_name("property"))
                if prop in ("innerHTML", "outerHTML") and self.depends_on_llm(right, state):
                    self.add("llm05-llm-output-to-html", node)
            elif left is not None and left.type == "subscript_expression":
                # En obj[clave] = valor solo cambia obj, no clave.
                self._track(left.child_by_field_name("object"), right, state)
            elif left is not None:
                self._track(left, right, state)
        elif t == "for_in_statement":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is not None and right is not None:
                self._track(left, right, state)
        elif t == "jsx_attribute" and text(node.named_children[0]) == "dangerouslySetInnerHTML":
            if self.depends_on_llm(node, state):
                self.add("llm05-llm-output-to-html", node)
        elif t in ("call_expression", "new_expression"):
            self._check_call(node, state)
        for child in node.children:
            self.visit(child, state)

    def _inventory_module(self, module: str, node: Node):
        if module in SDKS:
            kind, label = SDKS[module]
            self.out.component(kind, label, self.line(node), module)

    def _track(self, target: Node, value: Node, state: FuncState):
        names = identifiers(target) if target.type != "identifier" else {text(target)}
        if value.type in ("string", "template_string") or (value.type == "binary_expression" and has_interpolation(value)):
            for n in names:
                self.constants[n] = value
        call = value.named_children[0] if value.type == "await_expression" and value.named_children else value
        if call.type == "call_expression" and call_name(call).endswith(".asRetriever"):
            args = call.child_by_field_name("arguments")
            filtered = any(set(pairs_of(a)) & ACCESS_FILTER_KEYS for a in (args.named_children if args else [])
                           if a.type == "object")
            for n in names:
                (self.unfiltered_retrievers.discard if filtered else self.unfiltered_retrievers.add)(n)
        taint = self.taint_of(value, state)
        from_llm = self.depends_on_llm(value, state)
        for n in names:
            if from_llm:
                state.llm_output.add(n)
                state.tainted.pop(n, None)
            elif taint:
                state.tainted[n] = taint
            else:
                state.tainted.pop(n, None)
            if taint and has_interpolation(value):
                state.prompt_vars.add(n)

    # -- llamadas ---------------------------------------------------------------------------

    def _check_call(self, node: Node, state: FuncState):
        name = call_name(node)
        args = node.child_by_field_name("arguments")
        arg_nodes = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]

        if node.type == "call_expression" and name == "require" and arg_nodes:
            self._inventory_module(string_value(arg_nodes[0]), node)
        if TOOL_FACTORY.search(name) and node.type == "call_expression" or \
                node.type == "new_expression" and TOOL_CLASSES.match(name):
            self._check_tool(node, name, arg_nodes)
        if is_llm_call_name(name):
            self._check_llm_call(node, name, arg_nodes, state)
            return

        self._check_retrieval(node, name, arg_nodes, state)
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "subscript_expression":
            if self.depends_on_llm(fn.child_by_field_name("index"), state):
                self.add("llm05-llm-output-selects-function", node)
            return
        first = arg_nodes[:1]
        if CODE_EXEC.match(name):
            if any(self.depends_on_llm(a, state) for a in arg_nodes):
                self.add("llm05-llm-output-to-code-exec", node,
                         title=f"Salida del LLM ejecutada como código o comando ({name})")
        elif SQL_SINK.match(name):
            if any(self.depends_on_llm(a, state) for a in first):
                self.add("llm05-llm-output-to-sql", node)
        elif SSRF_SINK.match(name):
            if any(self.depends_on_llm(a, state) for a in first):
                self.add("llm05-llm-output-to-request", node)
        elif FILE_SINK.search(name):
            if any(self.depends_on_llm(a, state) for a in first):
                self.add("llm05-llm-output-to-filesystem", node)
        elif LOG_SINK.match(name):
            if any(self.depends_on_llm(a, state) for a in arg_nodes):
                self.add("llm02-llm-io-logged", node)
        elif HTML_SINK.match(name):
            if any(self.depends_on_llm(a, state) and re.search(r"<[a-zA-Z]", string_value(a)) for a in arg_nodes):
                self.add("llm05-llm-output-to-html", node)

    def _check_retrieval(self, node: Node, name: str, arg_nodes: list[Node], state: FuncState):
        """LLM08: búsqueda en un vector store con la pregunta del usuario y sin filtro de acceso."""
        objects = [a for a in arg_nodes if a.type == "object"]
        keys = {k for o in objects for k in pairs_of(o)}
        if RETRIEVAL_CALL.search(name):
            # LangChain JS: similaritySearch(query, k, filter).
            filtered = len(arg_nodes) >= 3 or bool(keys & ACCESS_FILTER_KEYS)
            query = arg_nodes[:1]
        elif name.endswith(".query") and keys & VECTOR_QUERY_KEYS:  # Pinecone / Chroma
            filtered = bool(keys & ACCESS_FILTER_KEYS) or ".namespace(" in name
            query = [v for o in objects for k, v in pairs_of(o).items()
                     if k in ("vector", "queryTexts", "queryEmbeddings") and v is not None]
        elif RETRIEVER_INVOKE.search(name) and name.rsplit(".", 1)[0] in self.unfiltered_retrievers:
            filtered, query = False, arg_nodes[:1]
        else:
            return
        if not filtered and any(self.taint_of(a, state) == "user" for a in query):
            self.add("llm08-rag-without-access-filter", node)

    def _check_llm_call(self, node: Node, name: str, arg_nodes: list[Node], state: FuncState):
        objects = [n for a in arg_nodes for n in walk(a) if n.type == "object"]
        top_keys: set[str] = set()
        for a in arg_nodes:
            if a.type == "object":
                top_keys |= set(pairs_of(a))
        for obj in objects:
            p = pairs_of(obj)
            model = p.get("model") or p.get("modelId")
            if model is not None and model.type == "string":
                self.out.component("model", string_value(model), self.line(model))

        if needs_token_limit(name) and not (top_keys & TOKEN_LIMIT_KEYS) and \
                not any(a.type == "spread_element" or (a.type == "object" and any(c.type == "spread_element" for c in a.named_children)) for a in arg_nodes):
            self.add("llm10-no-output-limit", node)

        system_values, prompt_values = [], []
        for obj in objects:
            p = pairs_of(obj)
            role = p.get("role")
            if role is not None and string_value(role) in ("system", "developer") and "content" in p:
                system_values.append(p["content"])
                continue
            system_values += [v for k, v in p.items() if k in SYSTEM_KEYS and v is not None]
            prompt_values += [v for k, v in p.items() if k in PROMPT_KEYS and v is not None and v.type != "array"]
        prompt_values += [a for a in arg_nodes if a.type != "object"]

        for v in system_values:
            if self.taint_of(v, state):
                self.add("llm01-untrusted-input-in-system-prompt", node)
            literal = self.constants.get(text(v), v) if v.type == "identifier" else v
            if SECRET_IN_TEXT.search(string_value(literal)):
                self.add("llm07-secret-in-system-prompt", node)
            if AUTHZ_IN_PROMPT.search(string_value(literal)):
                self.add("llm07-authorization-in-prompt", node)
        for v in prompt_values:
            taint = self.taint_of(v, state)
            if taint == "external":
                self.add("llm01-indirect-prompt-injection", node)
            elif taint == "user" and (has_interpolation(v) or identifiers(v) & state.prompt_vars):
                self.add("llm01-prompt-concatenation", node)

    def _check_tool(self, node: Node, name: str, arg_nodes: list[Node]):
        tool_name = ""
        for a in arg_nodes:
            if a.type == "string" and not tool_name:
                tool_name = string_value(a)
            if a.type == "object":
                n = pairs_of(a).get("name")
                if n is not None and n.type == "string":
                    tool_name = tool_name or string_value(n)
        is_mcp = bool(re.search(r"(server|mcp)", name, re.I))
        parent = node.parent
        if not tool_name and parent is not None and parent.type == "variable_declarator":
            tool_name = text(parent.child_by_field_name("name"))
        elif not tool_name and parent is not None and parent.type == "pair":
            tool_name = text(parent.child_by_field_name("key"))
        tool_name = tool_name or "(anónima)"
        self.out.component("mcp_tool" if is_mcp else "agent_tool", tool_name, self.line(node))

        risky = set()
        for n in walk(node):
            if n.type in ("call_expression", "new_expression"):
                cn = call_name(n)
                if DANGEROUS_CALL.match(cn) or CODE_EXEC.match(cn):
                    risky.add(cn)
                elif SQL_EXEC_CALL.search(cn):
                    a = n.child_by_field_name("arguments")
                    q = a.named_children[0] if a is not None and a.named_children else None
                    if q is not None and not (q.type == "string" or (q.type == "template_string" and not has_interpolation(q))):
                        risky.add("SQL dinámico")
            if n.type in ("string", "template_string") and DESTRUCTIVE_SQL.search(string_value(n)):
                risky.add("SQL de escritura")
            if n.type == "pair" and text(n.child_by_field_name("key")) == "method" and \
                    re.search(r"(?i)^(post|put|delete|patch)$", string_value(n.child_by_field_name("value"))):
                risky.add(f"HTTP {string_value(n.child_by_field_name('value')).upper()}")
        if risky:
            kind = "servidor MCP" if is_mcp else "agente"
            self.add("llm06-excessive-agency-tool", node,
                     title=f"Herramienta de {kind} '{tool_name}' con acciones peligrosas",
                     extra=f"Operaciones sensibles detectadas: {', '.join(sorted(risky))}.")

    def _check_mcp_transport(self):
        src = self.source.decode("utf-8", errors="replace")
        if "McpServer" not in src and "@modelcontextprotocol/sdk/server" not in src:
            return
        m = re.search(r"new\s+(StreamableHTTPServerTransport|SSEServerTransport)\b", src)
        if m and not re.search(r"(?i)(requireBearerAuth|authorization|bearer|authMiddleware|verifyToken|\bauth\b)", src):
            line = src[: m.start()].count("\n") + 1
            self.out.add("llm06-mcp-http-without-auth", line)


def analyze_js(rel: str, source: bytes, suffix: str):
    return JSAIAnalyzer(rel, source, parser_for(suffix)).run()
