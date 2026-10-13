// Uso SEGURO: no debe generar hallazgos.
import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";

const anthropic = new Anthropic();
const openai = new OpenAI();
const SYSTEM = "Eres un asistente de soporte. Responde solo sobre nuestros productos.";

export async function POST(req: Request) {
  const { question } = await req.json();
  const msg = await anthropic.messages.create({
    model: "claude-opus-5-5",
    max_tokens: 1024,
    system: SYSTEM,
    messages: [{ role: "user", content: question }],
  });
  const block = msg.content[0];
  const answer = block.type === "text" ? block.text : "";
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    max_tokens: 200,
    messages: [{ role: "system", content: SYSTEM }, { role: "user", content: question }],
  });
  return Response.json({ answer, other: completion.choices[0].message.content });
}

export function Answer({ text }: { text: string }) {
  return <p>{text}</p>;
}
