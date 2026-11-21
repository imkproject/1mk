const enc = new TextEncoder();

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function hashPassword(password, saltB64, iterations = 100000) {
  const salt = saltB64 ? unb64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256
  );
  return `pbkdf2$${iterations}$${b64(salt)}$${b64(bits)}`;
}

async function verifyPassword(password, stored) {
  const [scheme, iter, salt] = String(stored || "").split("$");
  if (scheme !== "pbkdf2") return false;
  return (await hashPassword(password, salt, Number(iter))) === stored;
}

async function sha256hex(s) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyCaptcha(token, ip, secret) {
  if (!token) return { success: false };
  const body = new URLSearchParams({ secret, response: token });
  if (ip) body.set("remoteip", ip);
  const res = await fetch("https://api.hcaptcha.com/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  return res.json();
}

const SESSION_COOKIE = "imk_sid";
const SESSION_TTL = 60 * 60 * 24 * 30;
const cookieHeader = (token, maxAge) =>
  `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

async function createSession(env, userId) {
  const token = b64(crypto.getRandomValues(new Uint8Array(32))).replace(/[^A-Za-z0-9]/g, "");
  const hash = await sha256hex(token);
  const expires = Math.floor(Date.now() / 1000) + SESSION_TTL;
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
    .bind(hash, userId, expires).run();
  return token;
}

async function currentUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const hash = await sha256hex(token);
  const row = await env.DB.prepare(
    `SELECT u.id, u.username, u.email FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?`
  ).bind(hash, Math.floor(Date.now() / 1000)).first();
  return row || null;
}

async function handleApi(request, env, url) {
  const path = url.pathname;
  const ip = request.headers.get("CF-Connecting-IP");

  if (path === "/api/me" && request.method === "GET") {
    return json({ user: await currentUser(request, env) });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const token = getCookie(request, SESSION_COOKIE);
    if (token) {
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?")
        .bind(await sha256hex(token)).run();
    }
    return json({ ok: true }, 200, { "Set-Cookie": cookieHeader("", 0) });
  }

  if (path !== "/api/login" && path !== "/api/register") {
    return json({ error: "Не найдено" }, 404);
  }
  if (request.method !== "POST") return json({ error: "Метод не поддерживается" }, 405);

  let body;
  try { body = await request.json(); } catch { return json({ error: "Некорректный запрос" }, 400); }

  const captcha = await verifyCaptcha(body.captcha, ip, env.HCAPTCHA_SECRET);
  if (!captcha.success) return json({ error: "Капча не пройдена" }, 400);

  const password = String(body.password || "");
  if (password.length < 8) return json({ error: "Пароль должен быть не короче 8 символов" }, 400);

  if (path === "/api/register") {
    const username = String(body.username || "").trim();
    const email = String(body.email || "").trim().toLowerCase();

    if (!/^[A-Za-z0-9_]{3,24}$/.test(username))
      return json({ error: "Логин: 3–24 символа, латиница, цифры и _" }, 400);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
      return json({ error: "Некорректная электронная почта" }, 400);

    const exists = await env.DB.prepare(
      "SELECT 1 AS x FROM users WHERE lower(username) = lower(?) OR lower(email) = ?"
    ).bind(username, email).first();
    if (exists) return json({ error: "Логин или почта уже заняты" }, 409);

    const hash = await hashPassword(password);
    const res = await env.DB.prepare(
      "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"
    ).bind(username, email, hash).run();

    const userId = res.meta.last_row_id;
    const token = await createSession(env, userId);
    return json({ user: { id: userId, username, email } }, 200, {
      "Set-Cookie": cookieHeader(token, SESSION_TTL),
    });
  }

  const identity = String(body.identity || "").trim();
  const user = await env.DB.prepare(
    `SELECT id, username, email, password_hash FROM users
      WHERE lower(username) = lower(?) OR lower(email) = lower(?)`
  ).bind(identity, identity).first();

  if (!user || !(await verifyPassword(password, user.password_hash)))
    return json({ error: "Неверный логин или пароль" }, 401);

  const token = await createSession(env, user.id);
  return json({ user: { id: user.id, username: user.username, email: user.email } }, 200, {
    "Set-Cookie": cookieHeader(token, SESSION_TTL),
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (e) {
        return json({ error: "Внутренняя ошибка сервера" }, 500);
      }
    }
    return env.ASSETS.fetch(request);
  },
};
