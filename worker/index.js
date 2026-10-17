
const COOKIE_NAME = "__Host-ms_session";
const SESSION_TTL = 7 * 24 * 60 * 60;
const FIREBASE_LOOKUP_TIMEOUT = 10000;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";

  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;

    if (part.slice(0, separator).trim() !== name) continue;

    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return null;
    }
  }

  return null;
}

function cookieHeader(value, maxAge) {
  return [
    `${COOKIE_NAME}=${value ? encodeURIComponent(value) : ""}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
  ].join("; ");
}

function clearSessionCookie() {
  return cookieHeader("", 0) +
    "; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
}

function generateSessionKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  return Array.from(bytes, byte =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(digest), byte =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function isConfigured(env) {
  return Boolean(
    env.DB &&
    typeof env.DB.prepare === "function" &&
    typeof env.FIREBASE_API_KEY === "string" &&
    env.FIREBASE_API_KEY.trim()
  );
}

function isSameOrigin(request) {
  const origin = request.headers.get("Origin");

  if (!origin) return false;

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

async function readJson(request) {
  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    return {
      ok: false,
      response: json({
        error: "Content-Type must be application/json.",
      }, 415),
    };
  }

  const contentLength = Number(
    request.headers.get("Content-Length") || 0
  );

  if (contentLength > 12000) {
    return {
      ok: false,
      response: json({
        error: "Request body is too large.",
      }, 413),
    };
  }

  let data;

  try {
    data = await request.json();
  } catch {
    return {
      ok: false,
      response: json({ error: "Invalid JSON body." }, 400),
    };
  }

  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return {
      ok: false,
      response: json({ error: "Invalid request body." }, 400),
    };
  }

  return { ok: true, data };
}

/*
 * Convert Firebase account creation time to Unix seconds.
 *
 * Supported inputs:
 * - Unix timestamp in milliseconds
 * - Unix timestamp in seconds
 * - Numeric strings
 * - ISO date strings
 *
 * Invalid or absent values return null.
 */
function normalizeAccountCreatedAt(value) {
  if (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value > 0
  ) {
    const seconds = value > 1e12
      ? Math.floor(value / 1000)
      : Math.floor(value);

    return seconds > 0 ? seconds : null;
  }

  if (typeof value !== "string" || !value.trim()) {
    return null;
  }

  const input = value.trim();

  if (/^\d+$/.test(input)) {
    const number = Number(input);

    if (!Number.isSafeInteger(number) || number <= 0) {
      return null;
    }

    const seconds = number > 1e12
      ? Math.floor(number / 1000)
      : number;

    return seconds > 0 ? seconds : null;
  }

  const milliseconds = Date.parse(input);

  if (!Number.isFinite(milliseconds) || milliseconds <= 0) {
    return null;
  }

  return Math.floor(milliseconds / 1000);
}

function getProviderIds(user) {
  const providerInfo = Array.isArray(user?.providerUserInfo)
    ? user.providerUserInfo
    : [];

  return [
    ...new Set(
      providerInfo
        .map(item => item?.providerId)
        .filter(value =>
          typeof value === "string" && value.length > 0
        )
    ),
  ];
}

/*
 * This identifies linked-provider information only.
 * It cannot prove which provider was used for this exact login.
 */
function inferSingleLinkedProvider(providerIds) {
  if (!Array.isArray(providerIds) || providerIds.length !== 1) {
    return null;
  }

  const provider = providerIds[0];

  const allowedProviders = new Set([
    "password",
    "google.com",
    "facebook.com",
    "github.com",
    "apple.com",
    "microsoft.com",
    "twitter.com",
    "yahoo.com",
    "phone",
  ]);

  return allowedProviders.has(provider) ? provider : null;
}

async function verifyFirebaseIdToken(idToken, env) {
  if (
    typeof idToken !== "string" ||
    idToken.length < 100 ||
    idToken.length > 10000
  ) {
    return { ok: false, reason: "invalid-token" };
  }

  const controller = new AbortController();

  const timeout = setTimeout(
    () => controller.abort(),
    FIREBASE_LOOKUP_TIMEOUT
  );

  try {
    const endpoint =
      "https://identitytoolkit.googleapis.com/v1/accounts:lookup" +
      `?key=${encodeURIComponent(env.FIREBASE_API_KEY)}`;

    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ idToken }),
      signal: controller.signal,
    });

    let result;

    try {
      result = await response.json();
    } catch {
      return { ok: false, reason: "firebase-unavailable" };
    }

    if (!response.ok) {
      if (response.status === 400 || response.status === 401) {
        return { ok: false, reason: "invalid-token" };
      }

      console.error(
        "Firebase token lookup failed:",
        response.status
      );

      return { ok: false, reason: "firebase-unavailable" };
    }

    const user = result?.users?.[0];

    if (
      !user ||
      typeof user.localId !== "string" ||
      !user.localId
    ) {
      return { ok: false, reason: "invalid-token" };
    }

    if (user.disabled === true) {
      return { ok: false, reason: "account-disabled" };
    }

    if (user.emailVerified !== true) {
      return { ok: false, reason: "email-not-verified" };
    }

    const providerIds = getProviderIds(user);

    const accountCreatedAt =
      normalizeAccountCreatedAt(user.createdAt);

    /*
     * Diagnostic logs intentionally omit tokens, email addresses,
     * API keys and other account identifiers.
     */
    console.log("Firebase metadata diagnostic:", {
      hasCreatedAt: user.createdAt !== undefined &&
        user.createdAt !== null,
      createdAtType: typeof user.createdAt,
      createdAtParsed: accountCreatedAt !== null,
      providerCount: providerIds.length,
    });

    return {
      ok: true,
      user: {
        uid: user.localId,
        email:
          typeof user.email === "string" ? user.email : null,
        displayName:
          typeof user.displayName === "string"
            ? user.displayName
            : null,
        photoURL:
          typeof user.photoUrl === "string"
            ? user.photoUrl
            : null,
      },
      accountCreatedAt,
      providerIds,
      loginMethod: inferSingleLinkedProvider(providerIds),
    };
  } catch (error) {
    console.error(
      "Firebase verification request failed:",
      error?.name || "UnknownError"
    );

    return { ok: false, reason: "firebase-unavailable" };
  } finally {
    clearTimeout(timeout);
  }
}

function firebaseErrorResponse(reason) {
  switch (reason) {
    case "email-not-verified":
      return json({
        authenticated: false,
        error: "Please verify your email address before signing in.",
        code: "EMAIL_NOT_VERIFIED",
      }, 403);

    case "account-disabled":
      return json({
        authenticated: false,
        error: "This account has been disabled.",
        code: "ACCOUNT_DISABLED",
      }, 403);

    case "firebase-unavailable":
      return json({
        authenticated: false,
        error:
          "Authentication service is temporarily unavailable. Please try again.",
        code: "AUTH_SERVICE_UNAVAILABLE",
      }, 503);

    default:
      return json({
        authenticated: false,
        error:
          "Your sign-in session is invalid or has expired. Please sign in again.",
        code: "INVALID_ID_TOKEN",
      }, 401);
  }
}

async function handleHealth(env) {
  const configured = isConfigured(env);

  return json({
    ok: true,
    service: "Moon Studio Forms",
    sessionSystem: configured
      ? "configured"
      : "needs-configuration",
  }, configured ? 200 : 503);
}

async function saveAccountMetadata(env, verification, now) {
  await env.DB.prepare(
    `INSERT INTO account_metadata
       (user_id, account_created_at, provider_ids, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       account_created_at = COALESCE(
         excluded.account_created_at,
         account_metadata.account_created_at
       ),
       provider_ids = excluded.provider_ids,
       updated_at = excluded.updated_at`
  ).bind(
    verification.user.uid,
    verification.accountCreatedAt,
    JSON.stringify(verification.providerIds),
    now
  ).run();
}

async function handleLogin(request, env) {
  if (!isSameOrigin(request)) {
    return json({
      error: "Cross-origin request rejected.",
    }, 403);
  }

  if (!isConfigured(env)) {
    return json({
      error: "Session service is not configured.",
    }, 503);
  }

  const parsed = await readJson(request);

  if (!parsed.ok) return parsed.response;

  const idToken = parsed.data.idToken;

  if (typeof idToken !== "string" || !idToken) {
    return json({
      error: "Firebase ID token is required.",
    }, 400);
  }

  const verification = await verifyFirebaseIdToken(idToken, env);

  if (!verification.ok) {
    return firebaseErrorResponse(verification.reason);
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_TTL;

  const sessionKey = generateSessionKey();
  const sessionHash = await sha256(sessionKey);

  try {
    await env.DB.prepare(
      `INSERT INTO sessions
         (id, user_id, created_at, expires_at, revoked_at, login_method)
       VALUES (?, ?, ?, ?, NULL, ?)`
    ).bind(
      sessionHash,
      verification.user.uid,
      now,
      expiresAt,
      verification.loginMethod
    ).run();
  } catch (error) {
    console.error(
      "Could not create D1 session:",
      error?.message || error
    );

    return json({
      error: "Could not create your sign-in session. Please try again.",
    }, 503);
  }

  try {
    await saveAccountMetadata(env, verification, now);
  } catch (error) {
    console.error(
      "Could not save account metadata:",
      error?.message || error
    );
  }

  try {
    await env.DB.prepare(
      `DELETE FROM sessions
       WHERE expires_at <= ? OR revoked_at IS NOT NULL`
    ).bind(now).run();
  } catch (error) {
    console.error(
      "Session cleanup failed:",
      error?.message || error
    );
  }

  return json({
    authenticated: true,
    user: verification.user,
    accountCreatedAt: verification.accountCreatedAt,
    loginMethod: verification.loginMethod,
    expiresAt,
  }, 200, {
    "Set-Cookie": cookieHeader(sessionKey, SESSION_TTL),
  });
}

async function handleMe(request, env) {
  if (!isConfigured(env)) {
    return json({
      error: "Session service is not configured.",
    }, 503);
  }

  const sessionKey = getCookie(request, COOKIE_NAME);

  if (!sessionKey || !/^[a-f0-9]{64}$/.test(sessionKey)) {
    return json({
      authenticated: false,
      error: "Not signed in.",
    }, 401);
  }

  const sessionHash = await sha256(sessionKey);
  const now = Math.floor(Date.now() / 1000);

  let session;

  try {
    session = await env.DB.prepare(
      `SELECT user_id, created_at, expires_at, login_method
       FROM sessions
       WHERE id = ?
         AND revoked_at IS NULL
         AND expires_at > ?
       LIMIT 1`
    ).bind(sessionHash, now).first();
  } catch (error) {
    console.error(
      "Could not read D1 session:",
      error?.message || error
    );

    return json({
      error: "Could not verify your session.",
    }, 503);
  }

  if (!session) {
    return json({
      authenticated: false,
      error: "Your session is invalid or has expired.",
    }, 401, {
      "Set-Cookie": clearSessionCookie(),
    });
  }

  let metadata = null;

  try {
    metadata = await env.DB.prepare(
      `SELECT account_created_at, provider_ids
       FROM account_metadata
       WHERE user_id = ?
       LIMIT 1`
    ).bind(session.user_id).first();
  } catch (error) {
    console.error(
      "Could not read account metadata:",
      error?.message || error
    );
  }

  const accountCreatedAt =
    Number.isSafeInteger(metadata?.account_created_at) &&
    metadata.account_created_at > 0
      ? metadata.account_created_at
      : null;

  let linkedProviders = [];

  try {
    const parsedProviders = JSON.parse(
      metadata?.provider_ids || "[]"
    );

    if (Array.isArray(parsedProviders)) {
      linkedProviders = parsedProviders;
    }
  } catch {
    linkedProviders = [];
  }

  return json({
    authenticated: true,
    user: {
      uid: session.user_id,
    },
    accountCreatedAt,
    loginMethod: session.login_method || null,
    linkedProviders,
    createdAt: session.created_at,
    expiresAt: session.expires_at,
  });
}

async function handleLogout(request, env) {
  if (!isSameOrigin(request)) {
    return json({
      error: "Cross-origin request rejected.",
    }, 403);
  }

  const sessionKey = getCookie(request, COOKIE_NAME);

  if (sessionKey && /^[a-f0-9]{64}$/.test(sessionKey)) {
    if (!isConfigured(env)) {
      return json({
        error:
          "Session service is not configured; sign-out could not be confirmed.",
      }, 503);
    }

    const sessionHash = await sha256(sessionKey);
    const now = Math.floor(Date.now() / 1000);

    try {
      await env.DB.prepare(
        `UPDATE sessions
         SET revoked_at = ?
         WHERE id = ?
           AND revoked_at IS NULL`
      ).bind(now, sessionHash).run();
    } catch (error) {
      console.error(
        "Could not revoke D1 session:",
        error?.message || error
      );

      return json({
        error: "Could not revoke your session. Please try again.",
      }, 503);
    }
  }

  return json({ ok: true }, 200, {
    "Set-Cookie": clearSessionCookie(),
  });
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (path === "/api/health" && method === "GET") {
    return handleHealth(env);
  }

  if (path === "/api/session/login" && method === "POST") {
    return handleLogin(request, env);
  }

  if (path === "/api/session/me" && method === "GET") {
    return handleMe(request, env);
  }

  if (path === "/api/session/logout" && method === "POST") {
    return handleLogout(request, env);
  }

  if (path.startsWith("/api/")) {
    return json({ error: "Not found" }, 404);
  }

  if (env.ASSETS) {
    return env.ASSETS.fetch(request);
  }

  return json({
    error: "Static assets are not configured.",
  }, 500);
}

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error(
        "Moon Studio Forms request failed:",
        error?.message || error
      );

      return json({
        error: "Internal server error.",
      }, 500);
    }
  },
};
