
const COOKIE_NAME = "__Host-ms_session";
const SESSION_TTL = 7 * 24 * 60 * 60;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;

    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();

    if (key === name) {
      try {
        return decodeURIComponent(value);
      } catch {
        return null;
      }
    }
  }

  return null;
}

function cookieHeader(value, maxAge) {
  return [
    `${COOKIE_NAME}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
  ].join("; ");
}

function generateSessionKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  // Hexadecimal avoids cookie encoding problems while remaining
  // cryptographically random and difficult to guess.
  return Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function handleRequest(request, env) {
  const url = new URL(request.url);

  if (url.pathname === "/api/health" && request.method === "GET") {
    return json({
      ok: true,
      service: "Moon Studio Forms",
      sessionSystem: "not-configured",
    });
  }

  if (url.pathname === "/api/session/me" && request.method === "GET") {
    const sessionKey = getCookie(request, COOKIE_NAME);

    if (!sessionKey) {
      return json({ authenticated: false }, 401);
    }

    // Session verification will be implemented after D1 is connected.
    return json({
      authenticated: false,
      message: "Session verification is not configured yet.",
    }, 501);
  }

  if (url.pathname === "/api/session/logout" && request.method === "POST") {
    const sessionKey = getCookie(request, COOKIE_NAME);

    // Session revocation in D1 will be added after database setup.
    // Do not treat clearing the browser cookie alone as full revocation.
    void sessionKey;

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Set-Cookie": cookieHeader("", 0),
      },
    });
  }

  if (
    url.pathname === "/api/session/login" &&
    request.method === "POST"
  ) {
    // Login stays disabled until Firebase ID-token verification
    // and D1 session storage are implemented.
    return json({
      error: "Login is not configured yet.",
    }, 501);
  }

  if (url.pathname.startsWith("/api/")) {
    return json({ error: "Not found" }, 404);
  }

  if (env.ASSETS) {
    return env.ASSETS.fetch(request);
  }

  return json({ error: "Static assets are not configured." }, 500);
}

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error("Moon Studio Forms request failed:", error);
      return json({ error: "Internal server error" }, 500);
    }
  },
};
