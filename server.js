// pg-bcrypt-test: sign in against bcrypt hashes migrated from Supabase, stored in OSC PostgreSQL.
// No auth server. The app verifies the hash itself with bcryptjs.
// All credentials come from environment variables (OSC parameter store), never from code.

const http = require("http");
const crypto = require("crypto");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
// Admin routes exist only while ADMIN_ENABLED is exactly "true" and a long token is set.
const ADMIN_ENABLED = process.env.ADMIN_ENABLED === "true" && ADMIN_TOKEN.length >= 32;

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

function adminAuthorized(req) {
  const h = req.headers["authorization"] || "";
  const given = Buffer.from(h.startsWith("Bearer ") ? h.slice(7) : "");
  const expected = Buffer.from(ADMIN_TOKEN);
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

// One-off import. Body: JSON array of {id, email, encrypted_password, email_confirmed_at, created_at}.
// Returns per-user status only, never hashes.
async function handleImport(req, res) {
  let users;
  try {
    users = JSON.parse(await readBody(req));
    if (!Array.isArray(users)) throw new Error("not array");
  } catch {
    return send(res, 400, JSON.stringify({ error: "bad body" }), "application/json");
  }
  const results = [];
  for (const u of users) {
    const email = String(u.email || "").trim().toLowerCase();
    const hash = String(u.encrypted_password || "");
    if (!/^\$2[aby]\$\d{2}\$.{53}$/.test(hash)) {
      results.push({ email, status: "skipped: not a bcrypt hash" });
      continue;
    }
    try {
      await pool.query(
        `INSERT INTO users (id, email, password_hash, email_verified, created_at)
         VALUES ($1, $2, $3, $4, COALESCE($5::timestamptz, now()))
         ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash,
           email_verified = EXCLUDED.email_verified`,
        [u.id, email, hash, Boolean(u.email_confirmed_at), u.created_at || null]
      );
      results.push({ email, status: "imported" });
    } catch (e) {
      results.push({ email, status: "error: " + (e.code || "db") });
    }
  }
  return send(res, 200, JSON.stringify({ results }), "application/json");
}

// Temporary security probe: tries the DB with a wrong password and with no password.
async function handleDbCheck(req, res) {
  const u = new URL(DATABASE_URL);
  async function attempt(password) {
    const { Client } = require("pg");
    const c = new Client({
      host: u.hostname, port: Number(u.port || 5432), user: decodeURIComponent(u.username),
      database: u.pathname.slice(1), password, connectionTimeoutMillis: 5000,
    });
    try {
      await c.connect();
      await c.end();
      return "CONNECTED (this would be a security failure)";
    } catch (e) {
      return `REFUSED: code=${e.code || "none"} message=${e.message}`;
    }
  }
  // Raw protocol probe with no password at all: send a StartupMessage and report what the
  // server asks for. Auth code 0 means it let us in without a password (a failure).
  function noPasswordProbe() {
    return new Promise((resolve) => {
      const net = require("net");
      const params = Buffer.from(`user\0${decodeURIComponent(u.username)}\0database\0${u.pathname.slice(1)}\0\0`);
      const msg = Buffer.alloc(8 + params.length);
      msg.writeInt32BE(8 + params.length, 0);
      msg.writeInt32BE(196608, 4);
      params.copy(msg, 8);
      const s = net.connect(Number(u.port || 5432), u.hostname);
      const done = (r) => { s.destroy(); resolve(r); };
      s.setTimeout(5000, () => done("TIMEOUT"));
      s.on("error", (e) => done("ERROR " + e.code));
      s.on("connect", () => s.write(msg));
      s.once("data", (d) => {
        if (d[0] === 0x52) {
          const code = d.readInt32BE(5);
          const names = { 0: "AuthenticationOk (NO PASSWORD NEEDED, security failure)", 3: "cleartext password required", 5: "MD5 password required", 10: "SASL/SCRAM password required" };
          done(`server replied auth code ${code}: ${names[code] || "other"}`);
        } else if (d[0] === 0x45) {
          done("server error: " + d.toString("utf8", 5).replace(/\0/g, " ").trim());
        } else done("unexpected reply byte " + d[0]);
      });
    });
  }
  const out = {
    host: u.hostname,
    wrongPassword: await attempt("definitely-not-the-password"),
    noPassword: await noPasswordProbe(),
    appToDbTls: await pool.query("SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()").then((r) => JSON.stringify(r.rows[0]), (e) => "ERR " + e.code),
    serverSslSetting: await pool.query("SHOW ssl").then((r) => r.rows[0].ssl, (e) => "ERR " + e.code),
    correctPasswordViaPool: await pool.query("SELECT count(*)::int AS n FROM users").then((r) => `OK, users=${r.rows[0].n}`, (e) => "ERR " + e.code),
  };
  return send(res, 200, JSON.stringify(out), "application/json");
}

const server = http.createServer(async (req, res) => {
  const path = (req.url || "/").split("?")[0];
  try {
    if (req.method === "GET" && path === "/") return send(res, 200, page(""));
    if (req.method === "POST" && path === "/signin") return await handleSignin(req, res);
    if (ADMIN_ENABLED && req.method === "POST" && (path === "/admin/import" || path === "/admin/dbcheck")) {
      if (!adminAuthorized(req)) return send(res, 404, "Not found", "text/plain");
      return path === "/admin/import" ? await handleImport(req, res) : await handleDbCheck(req, res);
    }
    return send(res, 404, "Not found", "text/plain");
  } catch (e) {
    console.error("request error:", e.code || e.message);
    if (!res.headersSent) send(res, 500, "Server error", "text/plain");
  }
});

initDb()
  .then(() => server.listen(PORT, () => console.log(`listening on ${PORT}, admin routes ${ADMIN_ENABLED ? "ENABLED" : "disabled"}`)))
  .catch((e) => {
    console.error("db init failed:", e.code || e.message);
    process.exit(1);
  });
