require("dotenv").config();
const express = require("express");
const cookieSession = require("cookie-session");
const crypto = require("crypto");
const path = require("path");

const {
  ROBLOX_CLIENT_ID, ROBLOX_CLIENT_SECRET, ROBLOX_REDIRECT_URI, SESSION_SECRET,
  PORT = 3000, NODE_ENV,
} = process.env;
const PROD = NODE_ENV === "production";

for (const [k, v] of Object.entries({ ROBLOX_CLIENT_ID, ROBLOX_CLIENT_SECRET, ROBLOX_REDIRECT_URI, SESSION_SECRET })) {
  if (!v) { console.error(`Falta a variável ${k} no arquivo .env`); process.exit(1); }
}

const RBX = {
  authorize: "https://apis.roblox.com/oauth/v1/authorize",
  token: "https://apis.roblox.com/oauth/v1/token",
  revoke: "https://apis.roblox.com/oauth/v1/token/revoke",
  userinfo: "https://apis.roblox.com/oauth/v1/userinfo",
};

const app = express();
if (PROD) app.set("trust proxy", 1);
app.disable("x-powered-by");

/* Cabeçalhos de segurança */
app.use((req, res, next) => {
  res.set({
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: https://*.rbxcdn.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
  });
  next();
});

/* Sessão: cookie assinado, httpOnly. Guarda SÓ o User ID (nenhum token, nenhuma senha). */
app.use(cookieSession({
  name: "ml_sess",
  keys: [SESSION_SECRET],
  maxAge: 30 * 24 * 3600 * 1000,
  httpOnly: true,
  sameSite: "lax",
  secure: PROD,
}));

/* Limitador simples de requisições por IP */
const hits = new Map();
const limit = (max, windowMs) => (req, res, next) => {
  const k = req.ip + req.path, now = Date.now();
  const h = (hits.get(k) || []).filter(t => now - t < windowMs);
  if (h.length >= max) return res.status(429).json({ error: "Muitas tentativas. Aguarde um instante." });
  h.push(now); hits.set(k, h); next();
};
setInterval(() => hits.clear(), 10 * 60 * 1000).unref();

/* Transações OAuth pendentes (state -> code_verifier), expiram em 10 min */
const pending = new Map();
setInterval(() => { const n = Date.now(); for (const [k, v] of pending) if (n - v.t > 600000) pending.delete(k); }, 60000).unref();
const b64u = b => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/* 1) Início do login → página OFICIAL de autorização do Roblox */
app.get("/auth/roblox/login", limit(20, 60000), (req, res) => {
  const state = b64u(crypto.randomBytes(24));
  const verifier = b64u(crypto.randomBytes(48));
  const challenge = b64u(crypto.createHash("sha256").update(verifier).digest());
  pending.set(state, { verifier, t: Date.now() });
  const url = new URL(RBX.authorize);
  url.search = new URLSearchParams({
    client_id: ROBLOX_CLIENT_ID,
    redirect_uri: ROBLOX_REDIRECT_URI,
    scope: "openid profile",
    response_type: "code",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  }).toString();
  res.redirect(url.toString());
});

/* 2) Retorno do Roblox */
app.get("/auth/roblox/callback", limit(30, 60000), async (req, res) => {
  const back = (status, reason) => res.redirect("/?roblox=" + status + (reason ? "&reason=" + reason : ""));
  const { code, state, error } = req.query;
  const tx = typeof state === "string" ? pending.get(state) : null;
  if (tx) pending.delete(state);

  if (error) return back(error === "access_denied" ? "cancelled" : "error", "denied");
  if (!tx || typeof code !== "string") return back("error", "state");

  try {
    const tr = await fetch(RBX.token, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        code_verifier: tx.verifier,
        client_id: ROBLOX_CLIENT_ID,
        client_secret: ROBLOX_CLIENT_SECRET,
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (!tr.ok) throw new Error("token " + tr.status);
    const tok = await tr.json();

    const ur = await fetch(RBX.userinfo, {
      headers: { Authorization: "Bearer " + tok.access_token },
      signal: AbortSignal.timeout(10000),
    });
    if (!ur.ok) throw new Error("userinfo " + ur.status);
    const info = await ur.json();

    /* Não guardamos tokens: revogamos assim que lemos a identidade. */
    fetch(RBX.revoke, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: tok.refresh_token || tok.access_token, client_id: ROBLOX_CLIENT_ID, client_secret: ROBLOX_CLIENT_SECRET }),
    }).catch(() => {});

    if (!/^\d+$/.test(String(info.sub))) throw new Error("sub inválido");
    req.session = { rid: String(info.sub) };
    return back("ok");
  } catch (e) {
    console.error("Falha no login Roblox:", e.message);
    return back("error", "server");
  }
});

/* Perfil público via APIs oficiais do Roblox (cache de 5 min) */
const cache = new Map();
const getJson = async url => {
  const r = await fetch(url, { signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error(url + " " + r.status);
  return r.json();
};
async function profile(id) {
  const c = cache.get(id);
  if (c && Date.now() - c.t < 300000) return c.d;
  const [u, av, fr, fo, fg] = await Promise.allSettled([
    getJson(`https://users.roblox.com/v1/users/${id}`),
    getJson(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${id}&size=150x150&format=Png&isCircular=false`),
    getJson(`https://friends.roblox.com/v1/users/${id}/friends/count`),
    getJson(`https://friends.roblox.com/v1/users/${id}/followers/count`),
    getJson(`https://friends.roblox.com/v1/users/${id}/followings/count`),
  ]);
  if (u.status !== "fulfilled") throw new Error("perfil indisponível");
  const p = u.value;
  const d = {
    userId: String(p.id),
    username: p.name,
    displayName: p.displayName,
    description: (p.description || "").slice(0, 300),
    created: p.created,
    verified: !!p.hasVerifiedBadge,
    avatar: av.status === "fulfilled" ? av.value?.data?.[0]?.imageUrl || null : null,
    friends: fr.status === "fulfilled" ? fr.value.count : null,
    followers: fo.status === "fulfilled" ? fo.value.count : null,
    following: fg.status === "fulfilled" ? fg.value.count : null,
    profileUrl: `https://www.roblox.com/users/${p.id}/profile`,
  };
  cache.set(id, { t: Date.now(), d });
  return d;
}

app.get("/api/me", limit(60, 60000), async (req, res) => {
  res.set("Cache-Control", "no-store");
  const id = req.session && req.session.rid;
  if (!id) return res.json({ user: null });
  try { res.json({ user: await profile(id) }); }
  catch { res.status(502).json({ error: "Não foi possível consultar o Roblox agora." }); }
});

/* Desconectar (exige cabeçalho customizado: proteção contra CSRF) */
app.post("/api/logout", (req, res) => {
  if (req.get("X-Requested-With") !== "fetch") return res.status(403).json({ error: "Requisição inválida." });
  req.session = null;
  res.json({ ok: true });
});

app.get(["/", "/index.html"], (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.listen(PORT, () => console.log(`Mar Limpo rodando em http://localhost:${PORT}`));
