
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      return Response.json({
        success: true,
        message: "Moon Studio Forms API is running."
      });
    }

    if (url.pathname === "/api/db-check") {
      try {
        const result = await env.DB
          .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'")
          .first();

        return Response.json({
          success: true,
          database: "connected",
          usersTable: result ? "exists" : "missing"
        });
      } catch (error) {
        return Response.json({
          success: false,
          database: "error",
          message: "Could not query the database."
        }, { status: 500 });
      }
    }

    return new Response("Moon Studio Forms", {
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
};
