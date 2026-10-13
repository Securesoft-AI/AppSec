import { exec, execFile } from "child_process";
import * as fs from "fs";
import * as path from "path";
import axios from "axios";
import jwt from "jsonwebtoken";
import DOMPurify from "dompurify";

export function routes(app: any, db: any, User: any) {
  app.get("/user", (req: any, res: any) => {
    const id = req.query.id;
    // ruleid: js-sql-injection
    db.query(`SELECT * FROM users WHERE id = ${id}`);
    // ok: js-sql-injection
    db.query("SELECT * FROM users WHERE id = $1", [id]);
    // ok: js-sql-injection
    db.query(`SELECT * FROM users WHERE id = ${parseInt(id, 10)}`);
  });

  app.get("/ping", (req: any, res: any) => {
    // ruleid: js-command-injection
    exec("ping -c 1 " + req.query.host);
    // ok: js-command-injection
    execFile("ping", ["-c", "1", req.query.host]);
  });

  app.post("/calc", (req: any, res: any) => {
    // ruleid: js-code-injection
    const r = eval(req.body.expr);
    // ok: js-reflected-xss
    res.json({ r });
  });

  app.get("/proxy", async (req: any, res: any) => {
    // ruleid: js-ssrf
    const r = await fetch(req.query.url);
    // ok: js-ssrf
    await axios.get("https://api.example.com/items", { params: { q: req.query.q } });
    // ruleid: js-ssrf
    await axios.get(req.query.target);
  });

  app.get("/file", (req: any, res: any) => {
    // ruleid: js-path-traversal
    res.sendFile("/srv/files/" + req.params.name);
    // ok: js-path-traversal
    fs.readFileSync(path.join("/srv/files", path.basename(req.params.name)));
  });

  app.get("/hello", (req: any, res: any) => {
    // ruleid: js-reflected-xss
    res.send("<h1>Hola " + req.query.name + "</h1>");
  });

  app.get("/go", (req: any, res: any) => {
    // ruleid: js-open-redirect
    res.redirect(req.query.next);
    // ok: js-open-redirect
    res.redirect("/home");
  });

  app.post("/login", async (req: any, res: any) => {
    // ruleid: js-nosql-injection
    const u = await User.findOne({ user: req.body.user, pass: req.body.pass });
    // ok: js-nosql-injection
    await User.findOne({ user: String(req.body.user) });
    // ruleid: js-insecure-cookie
    res.cookie("session", "x", { httpOnly: false });
    // ok: js-insecure-cookie
    res.cookie("session", "x", { httpOnly: true, secure: true });
  });
}

export function render(el: HTMLElement, html: string) {
  // ruleid: js-dom-xss
  el.innerHTML = html;
  // ok: js-dom-xss
  el.innerHTML = DOMPurify.sanitize(html);
  // ok: js-dom-xss
  el.textContent = html;
}

export function tls() {
  // ruleid: js-tls-verification-disabled
  const agent = { rejectUnauthorized: false };
  // ruleid: js-tls-verification-disabled
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  return agent;
}

export function auth(token: string, key: string) {
  // ruleid: js-jwt-insecure
  jwt.verify(token, key, { algorithms: ["HS256", "none"] });
  // ok: js-jwt-insecure
  return jwt.verify(token, key, { algorithms: ["HS256"] });
}

export function tokens() {
  // ruleid: js-weak-random-token
  const resetToken = Math.random().toString(36).slice(2);
  // ok: js-weak-random-token
  const jitter = Math.random() * 100;
  return [resetToken, jitter];
}
