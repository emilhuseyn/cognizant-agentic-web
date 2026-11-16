#!/usr/bin/env node
// Local static server for one site, sending the same headers as the site's _headers file in
// production: CORS on the public agent files and the OSV feed, the CSP on the sandbox worker.
// The skill's serve_site.mjs sends CORS only on the agent files, and a desk's OSV feed needs it too.
//
//   node scripts/serve.mjs <site folder> --port 8081 [--host 127.0.0.1] [--log requests.jsonl]
//
// The log has one JSON line per request: path, status, Origin, whether an Authorization header
// came, and cookie names. It never records header values other than Origin.

import { appendFileSync } from "node:fs";
import { readFile, realpath, stat } from "node:fs/promises";
import http from "node:http";
import path from "node:path";

const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8", ".hocon": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png", ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
  ".zip": "application/zip",
};
const WORKER_CSP = "default-src 'none'; script-src blob:; connect-src 'none'; worker-src 'none'";
const PUBLIC = [/^\/agent-manifest\.json$/, /^\/[a-z0-9_]+\.network\.json$/, /^\/[a-z0-9_]+\.hocon$/, /^\/links\.json$/, /^\/agent-mcp\.json$/,
  /^\/\.well-known\/[a-z0-9-]+\.json$/, /^\/osv\/[A-Za-z0-9._-]+\.json$/, /^\/desks\.json$/, /^\/desk-data\.json$/];

function args(argv) {
  const o = { host: "127.0.0.1", port: 8080, log: null, folder: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--port") o.port = Number(argv[++i]);
    else if (argv[i] === "--host") o.host = argv[++i];
    else if (argv[i] === "--log") o.log = argv[++i];
    else o.folder = argv[i];
  }
  if (!o.folder) throw new Error("Usage: node scripts/serve.mjs <site folder> --port 8081 [--host 127.0.0.1] [--log file]");
  return o;
}

const opts = args(process.argv.slice(2));
const root = await realpath(opts.folder);

function log(req, urlPath, status) {
  if (!opts.log) return;
  const cookies = (req.headers.cookie || "").split(";").map(c => c.split("=")[0].trim()).filter(Boolean);
  appendFileSync(opts.log, JSON.stringify({ time: Date.now(), method: req.method, path: urlPath, status, origin: req.headers.origin || null, authorization: req.headers.authorization !== undefined, cookies }) + "\n");
}

const server = http.createServer(async (req, res) => {
  let urlPath = "/";
  try {
    urlPath = decodeURIComponent(new URL(req.url, "http://x").pathname);
  } catch {
    res.writeHead(400).end();
    return;
  }
  const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" };
  if (PUBLIC.some(re => re.test(urlPath))) headers["Access-Control-Allow-Origin"] = "*";
  if (urlPath === "/runtime/sandbox-worker.js") headers["Content-Security-Policy"] = WORKER_CSP;
  if (req.method === "OPTIONS") {
    log(req, urlPath, 204);
    res.writeHead(204, { ...headers, "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS" }).end();
    return;
  }
  if (req.method !== "GET" && req.method !== "HEAD") {
    log(req, urlPath, 405);
    res.writeHead(405, headers).end();
    return;
  }
  let file = path.join(root, urlPath.endsWith("/") ? urlPath + "index.html" : urlPath);
  try {
    file = await realpath(file);
    if (file !== root && !file.startsWith(root + path.sep)) throw new Error("outside");
    if ((await stat(file)).isDirectory()) file = path.join(file, "index.html");
    const body = await readFile(file);
    headers["Content-Type"] = TYPES[path.extname(file).toLowerCase()] || "application/octet-stream";
    log(req, urlPath, 200);
    res.writeHead(200, headers).end(req.method === "HEAD" ? undefined : body);
  } catch {
    log(req, urlPath, 404);
    res.writeHead(404, { ...headers, "Content-Type": "text/plain" }).end("Not found");
  }
});

server.listen(opts.port, opts.host, () => console.log(`Serving ${root} on http://${opts.host}:${opts.port}/`));
