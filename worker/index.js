
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      return Response.json({
        success: true,
        message: "Moon Studio Forms API is running."
      });
    }

    return new Response("Moon Studio Forms", {
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
};
