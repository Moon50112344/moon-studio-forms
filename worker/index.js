const COOKIE_NAME = "__Host-ms_session";
const SESSION_TTL = 7 * 24 * 60 * 60;
const FIREBASE_LOOKUP_TIMEOUT = 10000;

const SURVEY_ADMIN_COOKIE_NAME = "__Host-ms_survey_admin";
const SURVEY_ADMIN_SESSION_TTL = 24 * 60 * 60;
const MAX_SURVEY_TITLE_LENGTH = 200;
const MAX_SURVEY_DESCRIPTION_LENGTH = 3000;

/* =========================================================
   GENERAL HELPERS
========================================================= */

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
      return decodeURIComponent(
        part.slice(separator + 1).trim()
      );
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
  return (
    cookieHeader("", 0) +
    "; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
  );
}

function surveyAdminCookieHeader(value, maxAge) {
  return [
    `${SURVEY_ADMIN_COOKIE_NAME}=${
      value ? encodeURIComponent(value) : ""
    }`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
  ].join("; ");
}

function clearSurveyAdminCookie() {
  return (
    surveyAdminCookieHeader("", 0) +
    "; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
  );
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

function isSurveyDbConfigured(env) {
  return Boolean(
    env.SURVEYS_DB &&
    typeof env.SURVEYS_DB.prepare === "function"
  );
}

function isSurveyAdminConfigured(env) {
  return (
    isSurveyDbConfigured(env) &&
    typeof env.SURVEY_ADMIN_PASSWORD === "string" &&
    env.SURVEY_ADMIN_PASSWORD.length > 0
  );
}

function isSameOrigin(request) {
  const origin = request.headers.get("Origin");

  if (!origin) return false;

  try {
    return (
      new URL(origin).origin ===
      new URL(request.url).origin
    );
  } catch {
    return false;
  }
}

async function readJson(request) {
  const contentType =
    request.headers.get("Content-Type") || "";

  if (
    !contentType
      .toLowerCase()
      .includes("application/json")
  ) {
    return {
      ok: false,
      response: json(
        {
          error: "Content-Type must be application/json.",
        },
        415
      ),
    };
  }

  const contentLength = Number(
    request.headers.get("Content-Length") || 0
  );

  if (contentLength > 12000) {
    return {
      ok: false,
      response: json(
        {
          error: "Request body is too large.",
        },
        413
      ),
    };
  }

  let data;

  try {
    data = await request.json();
  } catch {
    return {
      ok: false,
      response: json(
        { error: "Invalid JSON body." },
        400
      ),
    };
  }

  if (
    !data ||
    typeof data !== "object" ||
    Array.isArray(data)
  ) {
    return {
      ok: false,
      response: json(
        { error: "Invalid request body." },
        400
      ),
    };
  }

  return { ok: true, data };
}

/* =========================================================
   FIREBASE ACCOUNT METADATA
========================================================= */

/*
 * Convert Firebase account creation time to Unix seconds.
 *
 * Supported:
 * - Unix timestamp in milliseconds
 * - Unix timestamp in seconds
 * - Numeric strings
 * - ISO date strings
 */
function normalizeAccountCreatedAt(value) {
  if (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value > 0
  ) {
    const seconds =
      value > 1e12
        ? Math.floor(value / 1000)
        : Math.floor(value);

    return seconds > 0 ? seconds : null;
  }

  if (
    typeof value !== "string" ||
    !value.trim()
  ) {
    return null;
  }

  const input = value.trim();

  if (/^\d+$/.test(input)) {
    const number = Number(input);

    if (
      !Number.isSafeInteger(number) ||
      number <= 0
    ) {
      return null;
    }

    const seconds =
      number > 1e12
        ? Math.floor(number / 1000)
        : number;

    return seconds > 0 ? seconds : null;
  }

  const milliseconds = Date.parse(input);

  if (
    !Number.isFinite(milliseconds) ||
    milliseconds <= 0
  ) {
    return null;
  }

  return Math.floor(milliseconds / 1000);
}

function getProviderIds(user) {
  const providerInfo = Array.isArray(
    user?.providerUserInfo
  )
    ? user.providerUserInfo
    : [];

  return [
    ...new Set(
      providerInfo
        .map(item => item?.providerId)
        .filter(
          value =>
            typeof value === "string" &&
            value.length > 0
        )
    ),
  ];
}

/*
 * This identifies linked-provider information only.
 * It cannot prove which provider was used for this exact login.
 */
function inferSingleLinkedProvider(providerIds) {
  if (
    !Array.isArray(providerIds) ||
    providerIds.length !== 1
  ) {
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

  return allowedProviders.has(provider)
    ? provider
    : null;
}

async function verifyFirebaseIdToken(idToken, env) {
  if (
    typeof idToken !== "string" ||
    idToken.length < 100 ||
    idToken.length > 10000
  ) {
    return {
      ok: false,
      reason: "invalid-token",
    };
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
      return {
        ok: false,
        reason: "firebase-unavailable",
      };
    }

    if (!response.ok) {
      if (
        response.status === 400 ||
        response.status === 401
      ) {
        return {
          ok: false,
          reason: "invalid-token",
        };
      }

      console.error(
        "Firebase token lookup failed:",
        response.status
      );

      return {
        ok: false,
        reason: "firebase-unavailable",
      };
    }

    const user = result?.users?.[0];

    if (
      !user ||
      typeof user.localId !== "string" ||
      !user.localId
    ) {
      return {
        ok: false,
        reason: "invalid-token",
      };
    }

    if (user.disabled === true) {
      return {
        ok: false,
        reason: "account-disabled",
      };
    }

    if (user.emailVerified !== true) {
      return {
        ok: false,
        reason: "email-not-verified",
      };
    }

    const providerIds = getProviderIds(user);

    const accountCreatedAt =
      normalizeAccountCreatedAt(user.createdAt);

    console.log(
      "Firebase metadata diagnostic:",
      {
        hasCreatedAt:
          user.createdAt !== undefined &&
          user.createdAt !== null,
        createdAtType: typeof user.createdAt,
        createdAtParsed:
          accountCreatedAt !== null,
        providerCount: providerIds.length,
      }
    );

    return {
      ok: true,
      user: {
        uid: user.localId,
        email:
          typeof user.email === "string"
            ? user.email
            : null,
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
      loginMethod:
        inferSingleLinkedProvider(providerIds),
    };
  } catch (error) {
    console.error(
      "Firebase verification request failed:",
      error?.name || "UnknownError"
    );

    return {
      ok: false,
      reason: "firebase-unavailable",
    };
  } finally {
    clearTimeout(timeout);
  }
}

function firebaseErrorResponse(reason) {
  switch (reason) {
    case "email-not-verified":
      return json(
        {
          authenticated: false,
          error:
            "Please verify your email address before signing in.",
          code: "EMAIL_NOT_VERIFIED",
        },
        403
      );

    case "account-disabled":
      return json(
        {
          authenticated: false,
          error: "This account has been disabled.",
          code: "ACCOUNT_DISABLED",
        },
        403
      );

    case "firebase-unavailable":
      return json(
        {
          authenticated: false,
          error:
            "Authentication service is temporarily unavailable. Please try again.",
          code: "AUTH_SERVICE_UNAVAILABLE",
        },
        503
      );

    default:
      return json(
        {
          authenticated: false,
          error:
            "Your sign-in session is invalid or has expired. Please sign in again.",
          code: "INVALID_ID_TOKEN",
        },
        401
      );
  }
}

/* =========================================================
   EXISTING FIREBASE SESSION SYSTEM
========================================================= */

async function handleHealth(env) {
  const configured = isConfigured(env);

  return json(
    {
      ok: true,
      service: "Moon Studio Forms",
      sessionSystem: configured
        ? "configured"
        : "needs-configuration",
      surveySystem: isSurveyAdminConfigured(env)
        ? "configured"
        : "needs-configuration",
    },
    configured ? 200 : 503
  );
}

async function saveAccountMetadata(
  env,
  verification,
  now
) {
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
  )
    .bind(
      verification.user.uid,
      verification.accountCreatedAt,
      JSON.stringify(verification.providerIds),
      now
    )
    .run();
}

async function handleLogin(request, env) {
  if (!isSameOrigin(request)) {
    return json(
      {
        error: "Cross-origin request rejected.",
      },
      403
    );
  }

  if (!isConfigured(env)) {
    return json(
      {
        error: "Session service is not configured.",
      },
      503
    );
  }

  const parsed = await readJson(request);

  if (!parsed.ok) return parsed.response;

  const idToken = parsed.data.idToken;

  if (
    typeof idToken !== "string" ||
    !idToken
  ) {
    return json(
      {
        error: "Firebase ID token is required.",
      },
      400
    );
  }

  const verification =
    await verifyFirebaseIdToken(idToken, env);

  if (!verification.ok) {
    return firebaseErrorResponse(
      verification.reason
    );
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
    )
      .bind(
        sessionHash,
        verification.user.uid,
        now,
        expiresAt,
        verification.loginMethod
      )
      .run();
  } catch (error) {
    console.error(
      "Could not create D1 session:",
      error?.message || error
    );

    return json(
      {
        error:
          "Could not create your sign-in session. Please try again.",
      },
      503
    );
  }

  try {
    await saveAccountMetadata(
      env,
      verification,
      now
    );
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
    )
      .bind(now)
      .run();
  } catch (error) {
    console.error(
      "Session cleanup failed:",
      error?.message || error
    );
  }

  return json(
    {
      authenticated: true,
      user: verification.user,
      accountCreatedAt:
        verification.accountCreatedAt,
      loginMethod: verification.loginMethod,
      expiresAt,
    },
    200,
    {
      "Set-Cookie": cookieHeader(
        sessionKey,
        SESSION_TTL
      ),
    }
  );
}

async function handleMe(request, env) {
  if (!isConfigured(env)) {
    return json(
      {
        error: "Session service is not configured.",
      },
      503
    );
  }

  const sessionKey = getCookie(
    request,
    COOKIE_NAME
  );

  if (
    !sessionKey ||
    !/^[a-f0-9]{64}$/.test(sessionKey)
  ) {
    return json(
      {
        authenticated: false,
        error: "Not signed in.",
      },
      401
    );
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
    )
      .bind(sessionHash, now)
      .first();
  } catch (error) {
    console.error(
      "Could not read D1 session:",
      error?.message || error
    );

    return json(
      {
        error: "Could not verify your session.",
      },
      503
    );
  }

  if (!session) {
    return json(
      {
        authenticated: false,
        error:
          "Your session is invalid or has expired.",
      },
      401,
      {
        "Set-Cookie": clearSessionCookie(),
      }
    );
  }

  let metadata = null;

  try {
    metadata = await env.DB.prepare(
      `SELECT account_created_at, provider_ids
       FROM account_metadata
       WHERE user_id = ?
       LIMIT 1`
    )
      .bind(session.user_id)
      .first();
  } catch (error) {
    console.error(
      "Could not read account metadata:",
      error?.message || error
    );
  }

  const accountCreatedAt =
    Number.isSafeInteger(
      metadata?.account_created_at
    ) && metadata.account_created_at > 0
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
    return json(
      {
        error: "Cross-origin request rejected.",
      },
      403
    );
  }

  const sessionKey = getCookie(
    request,
    COOKIE_NAME
  );

  if (
    sessionKey &&
    /^[a-f0-9]{64}$/.test(sessionKey)
  ) {
    if (!isConfigured(env)) {
      return json(
        {
          error:
            "Session service is not configured; sign-out could not be confirmed.",
        },
        503
      );
    }

    const sessionHash = await sha256(sessionKey);
    const now = Math.floor(Date.now() / 1000);

    try {
      await env.DB.prepare(
        `UPDATE sessions
         SET revoked_at = ?
         WHERE id = ?
           AND revoked_at IS NULL`
      )
        .bind(now, sessionHash)
        .run();
    } catch (error) {
      console.error(
        "Could not revoke D1 session:",
        error?.message || error
      );

      return json(
        {
          error:
            "Could not revoke your session. Please try again.",
        },
        503
      );
    }
  }

  return json(
    { ok: true },
    200,
    {
      "Set-Cookie": clearSessionCookie(),
    }
  );
}

/* =========================================================
   SURVEY HELPERS
========================================================= */

/*
 * Convert a date or timestamp to Unix seconds.
 *
 * Accepts:
 * - Unix seconds
 * - Unix milliseconds
 * - Numeric strings
 * - ISO date strings
 * - datetime-local values
 */
function parseSurveyTimestamp(value) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return {
      ok: true,
      value: null,
    };
  }

  if (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value > 0
  ) {
    const seconds =
      value > 1e12
        ? Math.floor(value / 1000)
        : Math.floor(value);

    if (
      !Number.isSafeInteger(seconds) ||
      seconds <= 0
    ) {
      return {
        ok: false,
        value: null,
      };
    }

    return {
      ok: true,
      value: seconds,
    };
  }

  if (typeof value !== "string") {
    return {
      ok: false,
      value: null,
    };
  }

  const input = value.trim();

  if (!input) {
    return {
      ok: true,
      value: null,
    };
  }

  if (/^\d+$/.test(input)) {
    const number = Number(input);

    if (
      !Number.isSafeInteger(number) ||
      number <= 0
    ) {
      return {
        ok: false,
        value: null,
      };
    }

    const seconds =
      number > 1e12
        ? Math.floor(number / 1000)
        : number;

    return {
      ok: true,
      value: seconds,
    };
  }

  const milliseconds = Date.parse(input);

  if (
    !Number.isFinite(milliseconds) ||
    milliseconds <= 0
  ) {
    return {
      ok: false,
      value: null,
    };
  }

  const seconds = Math.floor(
    milliseconds / 1000
  );

  if (!Number.isSafeInteger(seconds)) {
    return {
      ok: false,
      value: null,
    };
  }

  return {
    ok: true,
    value: seconds,
  };
}

function validateSurveyDestination(value) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > 2048
  ) {
    return null;
  }

  try {
    const url = new URL(value.trim());

    if (url.protocol !== "https:") {
      return null;
    }

    if (url.username || url.password) {
      return null;
    }

    if (!url.hostname || !url.hostname.includes(".")) {
      return null;
    }

    return url.href;
  } catch {
    return null;
  }
}

function normalizeSurvey(row) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    created_at: row.created_at,
    ends_at: row.ends_at,
    destination_url: row.destination_url,
    is_published: Boolean(row.is_published),
    created_on: row.created_on,
    updated_on: row.updated_on,
  };
}

/* =========================================================
   SURVEY ADMIN AUTHENTICATION
========================================================= */

/*
 * Returns:
 * { ok: true, authenticated: true }
 * { ok: true, authenticated: false }
 * { ok: false, response: Response }
 */
async function checkSurveyAdminSession(
  request,
  env
) {
  if (!isSurveyAdminConfigured(env)) {
    return {
      ok: false,
      response: json(
        {
          error:
            "Survey administration is not configured.",
        },
        503
      ),
    };
  }

  const token = getCookie(
    request,
    SURVEY_ADMIN_COOKIE_NAME
  );

  if (
    !token ||
    !/^[a-f0-9]{64}$/.test(token)
  ) {
    return {
      ok: true,
      authenticated: false,
    };
  }

  let tokenHash;

  try {
    tokenHash = await sha256(token);
  } catch {
    return {
      ok: false,
      response: json(
        {
          error:
            "Could not verify the administrator session.",
        },
        503
      ),
    };
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    const session = await env.SURVEYS_DB.prepare(
      `SELECT token_hash, expires_at
       FROM admin_sessions
       WHERE token_hash = ?
         AND expires_at > ?
       LIMIT 1`
    )
      .bind(tokenHash, now)
      .first();

    return {
      ok: true,
      authenticated: Boolean(session),
    };
  } catch (error) {
    console.error(
      "Could not read survey admin session:",
      error?.message || error
    );

    return {
      ok: false,
      response: json(
        {
          error:
            "Could not verify the administrator session.",
        },
        503
      ),
    };
  }
}

async function handleSurveyAdminLogin(
  request,
  env
) {
  if (!isSameOrigin(request)) {
    return json(
      {
        error: "Cross-origin request rejected.",
      },
      403
    );
  }

  if (!isSurveyAdminConfigured(env)) {
    return json(
      {
        error:
          "Survey administration is not configured.",
      },
      503
    );
  }

  const parsed = await readJson(request);

  if (!parsed.ok) {
    return parsed.response;
  }

  const password = parsed.data.password;

  if (typeof password !== "string") {
    return json(
      {
        error: "Password is required.",
      },
      400
    );
  }

  if (
    password.length >
    1024
  ) {
    return json(
      {
        error: "Invalid password.",
      },
      401
    );
  }

  /*
   * The password is stored as a Cloudflare Worker Secret.
   * It is never sent back to the browser.
   */
  if (password !== env.SURVEY_ADMIN_PASSWORD) {
    return json(
      {
        authenticated: false,
        error: "Incorrect password.",
      },
      401
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresAt =
    now + SURVEY_ADMIN_SESSION_TTL;

  const token = generateSessionKey();
  const tokenHash = await sha256(token);

  try {
    await env.SURVEYS_DB.prepare(
      `INSERT INTO admin_sessions
         (token_hash, created_at, expires_at)
       VALUES (?, ?, ?)`
    )
      .bind(tokenHash, now, expiresAt)
      .run();
  } catch (error) {
    console.error(
      "Could not create survey admin session:",
      error?.message || error
    );

    return json(
      {
        error:
          "Could not create an administrator session.",
      },
      503
    );
  }

  try {
    await env.SURVEYS_DB.prepare(
      `DELETE FROM admin_sessions
       WHERE expires_at <= ?`
    )
      .bind(now)
      .run();
  } catch (error) {
    console.error(
      "Survey admin session cleanup failed:",
      error?.message || error
    );
  }

  return json(
    {
      authenticated: true,
      expiresAt,
    },
    200,
    {
      "Set-Cookie": surveyAdminCookieHeader(
        token,
        SURVEY_ADMIN_SESSION_TTL
      ),
    }
  );
}

async function handleSurveyAdminMe(
  request,
  env
) {
  const result = await checkSurveyAdminSession(
    request,
    env
  );

  if (!result.ok) {
    return result.response;
  }

  if (!result.authenticated) {
    return json(
      {
        authenticated: false,
      },
      401,
      {
        "Set-Cookie": clearSurveyAdminCookie(),
      }
    );
  }

  return json({
    authenticated: true,
  });
}

async function handleSurveyAdminLogout(
  request,
  env
) {
  if (!isSameOrigin(request)) {
    return json(
      {
        error: "Cross-origin request rejected.",
      },
      403
    );
  }

  const token = getCookie(
    request,
    SURVEY_ADMIN_COOKIE_NAME
  );

  if (
    token &&
    /^[a-f0-9]{64}$/.test(token)
  ) {
    if (!isSurveyAdminConfigured(env)) {
      return json(
        {
          error:
            "Survey administration is not configured.",
        },
        503
      );
    }

    try {
      const tokenHash = await sha256(token);

      await env.SURVEYS_DB.prepare(
        `DELETE FROM admin_sessions
         WHERE token_hash = ?`
      )
        .bind(tokenHash)
        .run();
    } catch (error) {
      console.error(
        "Could not revoke survey admin session:",
        error?.message || error
      );

      return json(
        {
          error:
            "Could not end the administrator session.",
        },
        503
      );
    }
  }

  return json(
    {
      ok: true,
    },
    200,
    {
      "Set-Cookie": clearSurveyAdminCookie(),
    }
  );
}

/* =========================================================
   PUBLIC SURVEY API
========================================================= */

/*
 * GET /api/surveys
 *
 * Returns published surveys that have not expired.
 * Dates are Unix timestamps in seconds.
 */
async function handlePublicSurveys(env) {
  if (!isSurveyDbConfigured(env)) {
    return json(
      {
        error: "Survey database is not configured.",
      },
      503
    );
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    const result = await env.SURVEYS_DB.prepare(
      `SELECT
         id,
         title,
         description,
         created_at,
         ends_at,
         destination_url,
         is_published,
         created_on,
         updated_on
       FROM surveys
       WHERE is_published = 1
         AND (
           ends_at IS NULL
           OR ends_at > ?
         )
       ORDER BY created_on DESC, created_at DESC`
    )
      .bind(now)
      .all();

    const surveys = (result.results || []).map(
      normalizeSurvey
    );

    return json({
      ok: true,
      surveys,
      count: surveys.length,
    });
  } catch (error) {
    console.error(
      "Could not load public surveys:",
      error?.message || error
    );

    return json(
      {
        error: "Could not load surveys.",
      },
      503
    );
  }
}

/* =========================================================
   ADMIN SURVEY API
========================================================= */

/*
 * GET /api/surveys/admin
 *
 * Requires a valid administrator session.
 * Returns published, unpublished and expired surveys.
 */
async function handleAdminSurveyList(
  request,
  env
) {
  const auth = await checkSurveyAdminSession(
    request,
    env
  );

  if (!auth.ok) {
    return auth.response;
  }

  if (!auth.authenticated) {
    return json(
      {
        authenticated: false,
        error: "Administrator sign-in required.",
      },
      401
    );
  }

  try {
    const result = await env.SURVEYS_DB.prepare(
      `SELECT
         id,
         title,
         description,
         created_at,
         ends_at,
         destination_url,
         is_published,
         created_on,
         updated_on
       FROM surveys
       ORDER BY created_on DESC, created_at DESC`
    ).all();

    const surveys = (result.results || []).map(
      normalizeSurvey
    );

    return json({
      ok: true,
      surveys,
      count: surveys.length,
    });
  } catch (error) {
    console.error(
      "Could not load admin surveys:",
      error?.message || error
    );

    return json(
      {
        error:
          "Could not load the survey management list.",
      },
      503
    );
  }
}

/*
 * POST /api/surveys/admin
 *
 * Creates a survey.
 *
 * Expected JSON:
 * {
 *   "title": "Survey title",
 *   "description": "Survey description",
 *   "created_at": "2026-10-17T10:00",
 *   "ends_at": "2026-10-31T23:59",
 *   "destination_url": "https://example.com/survey",
 *   "is_published": true
 * }
 *
 * created_at may be a Unix timestamp or date string.
 * ends_at may be null or empty for no end date.
 */
async function handleCreateSurvey(
  request,
  env
) {
  if (!isSameOrigin(request)) {
    return json(
      {
        error: "Cross-origin request rejected.",
      },
      403
    );
  }

  const auth = await checkSurveyAdminSession(
    request,
    env
  );

  if (!auth.ok) {
    return auth.response;
  }

  if (!auth.authenticated) {
    return json(
      {
        authenticated: false,
        error: "Administrator sign-in required.",
      },
      401
    );
  }

  const parsed = await readJson(request);

  if (!parsed.ok) {
    return parsed.response;
  }

  const data = parsed.data;

  if (typeof data.title !== "string") {
    return json(
      {
        error: "Survey title is required.",
      },
      400
    );
  }

  const title = data.title.trim();

  if (
    title.length < 1 ||
    title.length > MAX_SURVEY_TITLE_LENGTH
  ) {
    return json(
      {
        error:
          `Title must contain between 1 and ${MAX_SURVEY_TITLE_LENGTH} characters.`,
      },
      400
    );
  }

  let description = "";

  if (data.description !== undefined &&
      data.description !== null) {
    if (typeof data.description !== "string") {
      return json(
        {
          error: "Description must be text.",
        },
        400
      );
    }

    description = data.description.trim();
  }

  if (
    description.length >
    MAX_SURVEY_DESCRIPTION_LENGTH
  ) {
    return json(
      {
        error:
          `Description must not exceed ${MAX_SURVEY_DESCRIPTION_LENGTH} characters.`,
      },
      400
    );
  }

  const createdAtInput =
    data.created_at !== undefined
      ? data.created_at
      : data.createdAt;

  const createdAt = parseSurveyTimestamp(
    createdAtInput
  );

  if (
    !createdAt.ok ||
    createdAt.value === null
  ) {
    return json(
      {
        error:
          "A valid survey creation date is required.",
      },
      400
    );
  }

  const endsAtInput =
    data.ends_at !== undefined
      ? data.ends_at
      : data.endsAt;

  const endsAt = parseSurveyTimestamp(
    endsAtInput
  );

  if (!endsAt.ok) {
    return json(
      {
        error: "The survey end date is invalid.",
      },
      400
    );
  }

  if (
    endsAt.value !== null &&
    endsAt.value <= createdAt.value
  ) {
    return json(
      {
        error:
          "The end date must be later than the creation date.",
      },
      400
    );
  }

  const destinationInput =
    data.destination_url !== undefined
      ? data.destination_url
      : data.destinationUrl;

  const destinationUrl =
    validateSurveyDestination(destinationInput);

  if (!destinationUrl) {
    return json(
      {
        error:
          "A valid HTTPS destination URL is required.",
      },
      400
    );
  }

  let isPublished = 1;

  if (data.is_published !== undefined) {
    if (
      data.is_published === true ||
      data.is_published === 1
    ) {
      isPublished = 1;
    } else if (
      data.is_published === false ||
      data.is_published === 0
    ) {
      isPublished = 0;
    } else {
      return json(
        {
          error:
            "is_published must be a boolean.",
        },
        400
      );
    }
  }

  const id = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);

  try {
    await env.SURVEYS_DB.prepare(
      `INSERT INTO surveys (
         id,
         title,
         description,
         created_at,
         ends_at,
         destination_url,
         is_published,
         created_on,
         updated_on
       )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        id,
        title,
        description,
        createdAt.value,
        endsAt.value,
        destinationUrl,
        isPublished,
        now,
        now
      )
      .run();
  } catch (error) {
    console.error(
      "Could not create survey:",
      error?.message || error
    );

    return json(
      {
        error:
          "Could not save the survey. Please try again.",
      },
      503
    );
  }

  return json(
    {
      ok: true,
      message: "Survey created successfully.",
      survey: {
        id,
        title,
        description,
        created_at: createdAt.value,
        ends_at: endsAt.value,
        destination_url: destinationUrl,
        is_published: Boolean(isPublished),
        created_on: now,
        updated_on: now,
      },
    },
    201
  );
}

/* =========================================================
   REQUEST ROUTER
========================================================= */

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  /* Existing health endpoint */

  if (
    path === "/api/health" &&
    method === "GET"
  ) {
    return handleHealth(env);
  }

  /* Existing Firebase session endpoints */

  if (
    path === "/api/session/login" &&
    method === "POST"
  ) {
    return handleLogin(request, env);
  }

  if (
    path === "/api/session/me" &&
    method === "GET"
  ) {
    return handleMe(request, env);
  }

  if (
    path === "/api/session/logout" &&
    method === "POST"
  ) {
    return handleLogout(request, env);
  }

  /* Survey administrator authentication */

  if (
    path === "/api/survey-admin/login" &&
    method === "POST"
  ) {
    return handleSurveyAdminLogin(
      request,
      env
    );
  }

  if (
    path === "/api/survey-admin/me" &&
    method === "GET"
  ) {
    return handleSurveyAdminMe(
      request,
      env
    );
  }

  if (
    path === "/api/survey-admin/logout" &&
    method === "POST"
  ) {
    return handleSurveyAdminLogout(
      request,
      env
    );
  }

  /* Public survey listing */

  if (
    path === "/api/surveys" &&
    method === "GET"
  ) {
    return handlePublicSurveys(env);
  }

  /* Administrator survey management */

  if (
    path === "/api/surveys/admin" &&
    method === "GET"
  ) {
    return handleAdminSurveyList(
      request,
      env
    );
  }

  if (
    path === "/api/surveys/admin" &&
    method === "POST"
  ) {
    return handleCreateSurvey(
      request,
      env
    );
  }

  /* Reject unknown API routes */

  if (path.startsWith("/api/")) {
    return json(
      {
        error: "Not found",
      },
      404
    );
  }

  /* Serve static files */

  if (env.ASSETS) {
    return env.ASSETS.fetch(request);
  }

  return json(
    {
      error: "Static assets are not configured.",
    },
    500
  );
}

/* =========================================================
   CLOUDFLARE WORKER ENTRY POINT
========================================================= */

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(
        request,
        env
      );
    } catch (error) {
      console.error(
        "Moon Studio Forms request failed:",
        error?.message || error
      );

      return json(
        {
          error: "Internal server error.",
        },
        500
      );
    }
  },
};
