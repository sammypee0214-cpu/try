// Portfolio server. No packages needed: just run  node server.js
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const scrypt = require("util").promisify(crypto.scrypt);

const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "data.json");
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const SESSION_DAYS = 30;

// ---------- tiny JSON database (a single file) ----------
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = {
  users: [], sessions: {},
  site: { phone: "", email: "hello@adalindqvist.example", services: [
    { t: "Product design", d: "End-to-end design for web and mobile apps, from research to handoff." },
    { t: "Design systems", d: "Component libraries, tokens and documentation your team can extend." },
    { t: "Brand identity", d: "Logos, type and color systems that hold up across every touchpoint." },
    { t: "UX research", d: "Interviews and usability tests that turn guesses into decisions." } ] },
};
try { db = { ...db, ...JSON.parse(fs.readFileSync(DATA_FILE, "utf8")) }; }
catch (e) { if (e.code !== "ENOENT") throw e; }
function save() { fs.writeFileSync(DATA_FILE + ".tmp", JSON.stringify(db)); fs.renameSync(DATA_FILE + ".tmp", DATA_FILE); }
function pruneSessions() { const now = Date.now(); for (const k in db.sessions) if (db.sessions[k].exp < now) delete db.sessions[k]; }
pruneSessions();

// ---------- helpers ----------
const page = n => fs.readFileSync(path.join(__dirname, "public", n + ".html"));
const PAGES = { login: page("login"), app: page("app") };
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const SEC = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
};
function send(res, status, body, extra = {}) {
  const isPage = Buffer.isBuffer(body);
  res.writeHead(status, { "Content-Type": isPage ? "text/html; charset=utf-8" : "application/json; charset=utf-8", ...SEC, ...extra });
  res.end(isPage ? body : JSON.stringify(body));
}
const fail = (res, status, error) => send(res, status, { error });
const cookiesOf = req => Object.fromEntries((req.headers.cookie || "").split(";").map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(p => p[0]));
function currentUser(req) {
  const t = cookiesOf(req).sid; if (!t) return null;
  const s = db.sessions[sha(t)]; if (!s || s.exp < Date.now()) return null;
  return db.users.find(u => u.id === s.uid) || null;
}
function readJson(req) {
  return new Promise((ok, bad) => {
    let n = 0; const chunks = [];
    req.on("data", c => { n += c.length; if (n > 100000) { bad(new Error("Request too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { ok(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch { bad(new Error("Bad request")); } });
  });
}
const hits = new Map(); // simple brute-force protection: 20 sign-in/sign-up tries per 15 min per IP
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.reset < now) hits.delete(k); }, 60000).unref();
function limited(req) {
  const ip = (TRUST_PROXY && (req.headers["x-forwarded-for"] || "").split(",")[0].trim()) || req.socket.remoteAddress;
  const now = Date.now(); let h = hits.get(ip);
  if (!h || h.reset < now) { h = { n: 0, reset: now + 15 * 60000 }; hits.set(ip, h); }
  return ++h.n > 20;
}
async function hashPw(pw, salt = crypto.randomBytes(16).toString("hex")) { return { salt, hash: (await scrypt(pw, salt, 64)).toString("hex") }; }
async function checkPw(pw, u) { const { hash } = await hashPw(pw, u.salt); return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(u.hash, "hex")); }
function startSession(req, u) {
  const token = crypto.randomBytes(32).toString("hex");
  db.sessions[sha(token)] = { uid: u.id, exp: Date.now() + SESSION_DAYS * 864e5 }; save();
  const secure = process.env.COOKIE_SECURE === "1" || (TRUST_PROXY && req.headers["x-forwarded-proto"] === "https");
  return { "Set-Cookie": `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}${secure ? "; Secure" : ""}` };
}
const clients = new Set(); // live connections {res, uid}
const broadcast = (event, data) => { for (const c of clients) c.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); };
setInterval(() => { for (const c of clients) c.res.write(": ping\n\n"); }, 25000).unref();
function cleanSite(b) {
  const s = x => (typeof x === "string" ? x.trim() : "");
  if (!Array.isArray(b.services) || b.services.length > 12) throw new Error("Add up to 12 services.");
  return { phone: s(b.phone).slice(0, 30), email: s(b.email).slice(0, 120) || db.site.email,
    services: b.services.map(v => ({ t: s(v && v.t).slice(0, 60), d: s(v && v.d).slice(0, 200) })).filter(v => v.t) };
}
const publicUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });

// ---------- routes ----------
http.createServer(async (req, res) => {
  try {
    const url = req.url.split("?")[0], method = req.method, user = currentUser(req);
    if (method !== "GET" && method !== "HEAD") { // block cross-site requests
      const o = req.headers.origin;
      if (o) { let host; try { host = new URL(o).host; } catch {} if (host !== req.headers.host) return fail(res, 403, "Forbidden"); }
    }
    if (url === "/" && method === "GET") return send(res, 200, user ? PAGES.app : PAGES.login); // nothing is visible before sign-in

    if (url === "/api/signup" && method === "POST") {
      if (limited(req)) return fail(res, 429, "Too many attempts. Try again in a few minutes.");
      const b = await readJson(req), name = String(b.name || "").trim().slice(0, 60), email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || "");
      if (!name) return fail(res, 400, "Please enter your name.");
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 120) return fail(res, 400, "Please enter a valid email.");
      if (pw.length < 8 || pw.length > 200) return fail(res, 400, "Use a password of at least 8 characters.");
      const { salt, hash } = await hashPw(pw);
      if (db.users.some(u => u.email === email)) return fail(res, 409, "An account with that email already exists.");
      const isAdmin = ADMIN_EMAIL ? email === ADMIN_EMAIL : db.users.length === 0; // first account is admin unless ADMIN_EMAIL is set
      const u = { id: crypto.randomUUID(), name, email, role: isAdmin ? "admin" : "member", salt, hash, created: Date.now() };
      db.users.push(u);
      return send(res, 200, { ok: true }, startSession(req, u));
    }
    if (url === "/api/login" && method === "POST") {
      if (limited(req)) return fail(res, 429, "Too many attempts. Try again in a few minutes.");
      const b = await readJson(req), email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || "").slice(0, 200);
      const u = db.users.find(x => x.email === email);
      const ok = u ? await checkPw(pw, u) : (await hashPw(pw, "0".repeat(32)), false);
      if (!ok) return fail(res, 401, "Incorrect email or password.");
      return send(res, 200, { ok: true }, startSession(req, u));
    }
    if (url === "/api/logout" && method === "POST") {
      const t = cookiesOf(req).sid; if (t) { delete db.sessions[sha(t)]; save(); }
      return send(res, 200, { ok: true }, { "Set-Cookie": "sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0" });
    }

    if (!url.startsWith("/api/")) return fail(res, 404, "Not found");
    if (!user) return fail(res, 401, "Please sign in.");
    const admin = user.role === "admin";

    if (url === "/api/me" && method === "GET") return send(res, 200, { user: publicUser(user), site: db.site });
    if (url === "/api/events" && method === "GET") {
      res.writeHead(200, { "Content-Type": "text/event-stream", Connection: "keep-alive", ...SEC });
      res.write(": connected\n\n");
      const c = { res, uid: user.id }; clients.add(c); req.on("close", () => clients.delete(c)); return;
    }
    if (url === "/api/site" && method === "PUT") {
      if (!admin) return fail(res, 403, "Only the admin can do that.");
      db.site = cleanSite(await readJson(req)); save(); broadcast("site", db.site);
      return send(res, 200, { site: db.site });
    }
    if (url === "/api/users" && method === "GET") {
      if (!admin) return fail(res, 403, "Only the admin can do that.");
      return send(res, 200, { users: db.users.map(publicUser) });
    }
    const del = url.match(/^\/api\/users\/([\w-]+)$/);
    if (del && method === "DELETE") {
      if (!admin) return fail(res, 403, "Only the admin can do that.");
      if (del[1] === user.id) return fail(res, 400, "You can’t remove your own account.");
      db.users = db.users.filter(u => u.id !== del[1]);
      for (const k in db.sessions) if (db.sessions[k].uid === del[1]) delete db.sessions[k];
      for (const c of clients) if (c.uid === del[1]) { c.res.end(); clients.delete(c); }
      save(); return send(res, 200, { ok: true });
    }
    return fail(res, 404, "Not found");
  } catch (e) {
    console.error(e);
    if (!res.headersSent) fail(res, e.message === "Request too large" ? 413 : 400, e.message === "Request too large" ? e.message : "Something went wrong.");
  }
}).listen(PORT, () => console.log(`Portfolio running on http://localhost:${PORT}`));
