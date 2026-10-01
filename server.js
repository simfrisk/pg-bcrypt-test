// pg-bcrypt-test: sign in against bcrypt hashes migrated from Supabase, stored in OSC PostgreSQL.
// No auth server. The app verifies the hash itself with bcryptjs.
// All credentials come from environment variables (OSC parameter store), never from code.

const http = require("http");
const crypto = require("crypto");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("DATABASE_URL is not set");
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL, max: 5 });

// Used for unknown emails so the response time does not reveal whether an account exists.
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString("hex"), 10);

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY,
      email text NOT NULL UNIQUE,
      password_hash text NOT NULL,
      email_verified boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL DEFAULT now()
    )`);
}

// Basic in-memory sign-in throttle: per client IP and per email.
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 10;
const attempts = new Map();
function throttled(key) {
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry || now - entry.start > WINDOW_MS) {
    attempts.set(key, { start: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_ATTEMPTS;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of attempts) if (now - v.start > WINDOW_MS) attempts.delete(k);
}, 60 * 1000).unref();

function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  return (typeof fwd === "string" && fwd.split(",")[0].trim()) || req.socket.remoteAddress || "unknown";
}

function send(res, status, body, type = "text/html; charset=utf-8") {
  res.writeHead(status, {
    "Content-Type": type,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
  });
  res.end(body);
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error("too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function page(message) {
  const msg = message ? `<p style="font-weight:bold">${message}</p>` : "";
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PG bcrypt test</title></head><body style="font-family:sans-serif;max-width:24rem;margin:3rem auto;padding:0 1rem">
<h1>Sign in</h1>${msg}
<form method="POST" action="/signin" autocomplete="off">
<p><label>Email<br><input name="email" type="email" required style="width:100%"></label></p>
<p><label>Password<br><input name="password" type="password" required style="width:100%"></label></p>
<p><button type="submit">Sign in</button></p>
</form></body></html>`;
}

async function handleSignin(req, res) {
  let form;
  try {
    form = new URLSearchParams(await readBody(req, 8 * 1024));
  } catch {
    return send(res, 413, page("WRONG CREDENTIALS"));
  }
  const email = (form.get("email") || "").trim().toLowerCase();
  const password = form.get("password") || "";

  if (throttled("ip:" + clientIp(req)) || throttled("email:" + email)) {
    return send(res, 429, page("TOO MANY ATTEMPTS, TRY AGAIN LATER"));
  }

  let hash = DUMMY_HASH;
  let found = false;
  try {
    const r = await pool.query("SELECT password_hash FROM users WHERE email = $1", [email]);
    if (r.rows.length === 1) {
      hash = r.rows[0].password_hash;
      found = true;
    }
  } catch (e) {
    console.error("signin db error:", e.code || e.message);
    return send(res, 500, page("SERVER ERROR"));
  }
  const ok = (await bcrypt.compare(password, hash)) && found && password.length > 0;
  return send(res, ok ? 200 : 401, page(ok ? "SIGN-IN OK" : "WRONG CREDENTIALS"));
}

const server = http.createServer(async (req, res) => {
  const path = (req.url || "/").split("?")[0];
  try {
    if (req.method === "GET" && path === "/") return send(res, 200, page(""));
    if (req.method === "POST" && path === "/signin") return await handleSignin(req, res);
    return send(res, 404, "Not found", "text/plain");
  } catch (e) {
    console.error("request error:", e.code || e.message);
    if (!res.headersSent) send(res, 500, "Server error", "text/plain");
  }
});

initDb()
  .then(() => server.listen(PORT, () => console.log(`listening on ${PORT}`)))
  .catch((e) => {
    console.error("db init failed:", e.code || e.message);
    process.exit(1);
  });
