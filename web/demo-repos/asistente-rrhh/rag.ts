// RAG multiusuario en TypeScript: casos con y sin control de acceso.
import Anthropic from "@anthropic-ai/sdk";
import { Pinecone } from "@pinecone-database/pinecone";
import { MemoryVectorStore } from "langchain/vectorstores/memory";

const anthropic = new Anthropic();
const store = new MemoryVectorStore();
const index = new Pinecone().index("docs");
const SYSTEM = "You are the billing assistant. You must only show invoices that belong to the current user.";

export async function POST(req: Request) {
  const { question, userId } = await req.json();
  const docs = await store.similaritySearch(question, 4);
  const hits = await index.query({ vector: question, topK: 3 });
  const safeDocs = await store.similaritySearch(question, 4, { userId });
  const safeHits = await index.query({ vector: question, topK: 3, filter: { userId } });
  const openRetriever = store.asRetriever({ k: 4 });
  const viaRetriever = await openRetriever.invoke(question);
  const userRetriever = store.asRetriever({ k: 4, filter: { userId } });
  const safeViaRetriever = await userRetriever.invoke(question);
  const msg = await anthropic.messages.create({
    model: "claude-opus-5-5",
    max_tokens: 512,
    system: SYSTEM,
    messages: [{ role: "user", content: question }],
  });
  return Response.json({ n: docs.length + hits.matches.length + safeDocs.length + safeHits.matches.length + viaRetriever.length + safeViaRetriever.length, msg });
}
