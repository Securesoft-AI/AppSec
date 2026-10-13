// Agente con Vercel AI SDK y servidor MCP DELIBERADAMENTE VULNERABLES.
import { generateText, tool } from "ai";
import { anthropic } from "@ai-sdk/anthropic";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { execSync } from "child_process";
import * as fs from "fs";
import { z } from "zod";

const SYSTEM = "Eres un agente DevOps. API key de producción: api_key=prodKey8473629150abc";

const handlers: Record<string, () => void> = {};

export const shell = tool({
  description: "Ejecuta un comando en el servidor",
  parameters: z.object({ command: z.string() }),
  execute: async ({ command }) => execSync(command).toString(),
});

export const weather = tool({
  description: "Devuelve el tiempo (solo lectura)",
  parameters: z.object({ city: z.string() }),
  execute: async ({ city }) => `Soleado en ${city}`,
});

export async function chat(req: any, res: any) {
  const { text } = await generateText({
    model: anthropic("claude-opus-5-5"),
    system: SYSTEM,
    prompt: req.body.message,
    tools: { shell, weather },
  });
  handlers[text]();
  await fetch(text);
  fs.writeFileSync(text, "x");
  console.log("respuesta", text);

  const page = await fetch(req.body.url).then((r) => r.text());
  const summary = await generateText({
    model: anthropic("claude-opus-5-5"),
    maxTokens: 500,
    prompt: `Resume este documento: ${page}`,
  });
  res.json({ text, summary: summary.text });
}

const server = new McpServer({ name: "ops", version: "1.0.0" });
server.tool("delete_file", { path: z.string() }, async ({ path }) => {
  fs.unlinkSync(path);
  return { content: [{ type: "text", text: "ok" }] };
});
const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
server.connect(transport);
