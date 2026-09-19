#!/usr/bin/env node
// Streamable HTTP entry point for single-user hosted deployments (Railway,
// Fly, a VPS). The stdio server in index.js stays the default; this file
// reuses its createYnabServer factory and serves it at POST/GET/DELETE /mcp.
//
// Required environment:
//   YNAB_API_TOKEN   YNAB personal access token
//   MCP_AUTH_TOKEN   shared secret; callers send "Authorization: Bearer <it>"
// Optional:
//   YNAB_ALLOW_WRITES=1, YNAB_BUDGET_ID, PORT (default 3000)
//
// The server refuses to start without MCP_AUTH_TOKEN: an open endpoint would
// hand the YNAB budget to anyone who finds the URL.

import { createServer } from "node:http";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

process.env.YNAB_MCP_NO_AUTOSTART = "1";
const { createYnabServer, createFsJournal, undoJournalPath } = await import("./index.js");

const PORT = Number(process.env.PORT) || 3000;
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || "";
const YNAB_TOKEN = process.env.YNAB_API_TOKEN || "";
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const SESSION_IDLE_MS = 60 * 60 * 1000;

if (AUTH_TOKEN.length < 32) {
  console.error("MCP_AUTH_TOKEN is required and must be at least 32 characters. Generate one with: openssl rand -hex 32");
  process.exit(1);
}
if (!YNAB_TOKEN) {
  console.error("YNAB_API_TOKEN is required.");
  process.exit(1);
}

const journal = createFsJournal(undoJournalPath());
const sessions = new Map(); // sessionId -> { transport, lastSeen }

function sha256(value) {
  return createHash("sha256").update(value).digest();
}

// Hash both sides so timingSafeEqual gets equal-length buffers.
function isAuthorized(req) {
  const header = req.headers.authorization || "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (!match) return false;
  return timingSafeEqual(sha256(match[1].trim()), sha256(AUTH_TOKEN));
}

function sendJson(res, status, body, headers = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

function rpcError(res, status, message, headers) {
  sendJson(res, status, { jsonrpc: "2.0", error: { code: -32000, message }, id: null }, headers);
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error("body too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function newSession() {
  const { server } = createYnabServer({
    getAccessToken: async () => YNAB_TOKEN,
    hasCredentials: true,
    defaultBudgetId: process.env.YNAB_BUDGET_ID || undefined,
    writesEnabled: process.env.YNAB_ALLOW_WRITES === "1",
    journal,
    runtime: { tokenSource: "env", detected_agent: "hosted-http", values: {}, sources_checked: [] },
    serverInfo: { name: "YNAB Hosted", version: "5.4.0" },
  });
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    onsessioninitialized: (id) => sessions.set(id, { transport, lastSeen: Date.now() }),
  });
  transport.onclose = () => {
    if (transport.sessionId) sessions.delete(transport.sessionId);
  };
  await server.connect(transport);
  return transport;
}

async function handleMcp(req, res) {
  if (!isAuthorized(req)) {
    return rpcError(res, 401, "Unauthorized", { "www-authenticate": "Bearer" });
  }

  const sessionId = req.headers["mcp-session-id"];
  const session = sessionId ? sessions.get(sessionId) : undefined;

  if (req.method === "POST") {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      return rpcError(res, 400, "Invalid JSON body");
    }
    if (session) {
      session.lastSeen = Date.now();
      return session.transport.handleRequest(req, res, body);
    }
    if (!sessionId && isInitializeRequest(body)) {
      const transport = await newSession();
      return transport.handleRequest(req, res, body);
    }
    // 404 tells a client holding a stale session id (e.g. after a redeploy) to re-initialize.
    return rpcError(res, sessionId ? 404 : 400, sessionId ? "Session not found" : "Missing session id");
  }

  if (req.method === "GET" || req.method === "DELETE") {
    if (!session) return rpcError(res, sessionId ? 404 : 400, sessionId ? "Session not found" : "Missing session id");
    session.lastSeen = Date.now();
    return session.transport.handleRequest(req, res);
  }

  res.writeHead(405, { allow: "GET, POST, DELETE" }).end();
}

const httpServer = createServer((req, res) => {
  const { pathname } = new URL(req.url, "http://localhost");
  if (pathname === "/healthz") return sendJson(res, 200, { ok: true });
  if (pathname === "/mcp") {
    return handleMcp(req, res).catch((err) => {
      console.error("MCP request failed:", err?.message || err);
      if (!res.headersSent) rpcError(res, 500, "Internal server error");
      else res.end();
    });
  }
  sendJson(res, 404, { error: "not found" });
});

setInterval(() => {
  const cutoff = Date.now() - SESSION_IDLE_MS;
  for (const [id, session] of sessions) {
    if (session.lastSeen < cutoff) {
      sessions.delete(id);
      session.transport.close().catch(() => {});
    }
  }
}, 5 * 60 * 1000).unref();

httpServer.listen(PORT, "0.0.0.0", () => {
  console.error(`YNAB MCP (streamable HTTP) listening on :${PORT}/mcp, writes ${process.env.YNAB_ALLOW_WRITES === "1" ? "enabled" : "disabled"}`);
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => httpServer.close(() => process.exit(0)));
}
