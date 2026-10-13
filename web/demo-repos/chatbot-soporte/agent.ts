// Ejemplo DELIBERADAMENTE VULNERABLE.
import OpenAI from "openai";
import { exec } from "child_process";

const openai = new OpenAI();

export async function handler(req: any, res: any) {
  const userInput = req.body.message;
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "system", content: "Ayuda al usuario: " + userInput }],
  });
  const out = completion.choices[0].message.content ?? "";
  exec(out);
  res.send(`<p>${out}</p>`);
  document.getElementById("x")!.innerHTML = out;
}
