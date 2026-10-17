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

function normalizeAccountCreatedAt(value) {
  if (typeof value !== "string" || !value.trim()) {
    return null;
  }

  const milliseconds = Date.parse(value);

  if (!Number.isFinite(milliseconds) || milliseconds <= 0) {
    return null;
  }

  return Math.floor(milliseconds / 1000);
}

/*
 * The Firebase accounts:lookup endpoint validates the ID token.
 * Account creation time and provider information are taken from
 * Firebase's response, never from client-supplied profile fields.
 */
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

    const providerIds = Array.isArray(user.providerUserInfo)
      ? [
          ...new Set(
            user.providerUserInfo
              .map(item => item?.providerId)
              .filter(value =>
                typeof value === "string" && value.length > 0
              )
          ),
        ]
      : [];

    return {
      ok: true,
      user: {
        uid: user.localId,
        email: typeof user.email === "string"
          ? user.email
          : null,
        displayName: typeof user.displayName === "string"
          ? user.displayName
          : null,
        photoURL: typeof user.photoUrl === "string"
          ? user.photoUrl
          : null,
      },
      accountCreatedAt: normalizeAccountCreatedAt(user.createdAt),
      providerIds,
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
    sessionSystem: configured ? "configured" : "needs-configuration",
  }, configured ? 200 : 503);
}

async function saveAccountMetadata(env, verification, now) {
  /*
   * Do not overwrite a previously saved creation date with NULL.
   * This keeps existing valid metadata when Firebase omits a field.
   */
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
    return json({ error: "Cross-origin request rejected." }, 403);
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

  /*
   * Firebase's accounts:lookup response provides linked providers,
   * not necessarily the provider used for this particular sign-in.
   * Therefore login_method remains NULL until the actual sign-in
   * provider can be established by a trusted mechanism.
   */
  const sessionKey = generateSessionKey();
  const sessionHash = await sha256(sessionKey);

  try {
    await env.DB.prepare(
      `INSERT INTO sessions
         (id, user_id, created_at, expires_at, revoked_at, login_method)
       VALUES (?, ?, ?, ?, NULL, NULL)`
    ).bind(
      sessionHash,
      verification.user.uid,
      now,
      expiresAt
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

  /*
   * Metadata is supplementary. If this write fails, the verified
   * session remains usable; the API will report missing metadata.
   */
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
      "DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL"
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
      `SELECT account_created_at
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

  const loginMethod =
    typeof session.login_method === "string" &&
    session.login_method.length > 0
      ? session.login_method
      : null;

  return json({
    authenticated: true,
    user: {
      uid: session.user_id,
    },
    accountCreatedAt,
    loginMethod,
    createdAt: session.created_at,
    expiresAt: session.expires_at,
  });
}

async function handleLogout(request, env) {
  if (!isSameOrigin(request)) {
    return json({ error: "Cross-origin request rejected." }, 403);
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
