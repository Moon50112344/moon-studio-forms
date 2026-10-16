
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // API gốc — kiểm tra Worker đang hoạt động
    if (url.pathname === "/api" || url.pathname === "/api/") {
      return Response.json({
        success: true,
        name: "Moon Studio Forms",
        status: "online",
        version: "0.1.0",
        message: "API is running."
      });
    }

    // Các API khác sẽ được bổ sung sau
    return Response.json(
      {
        success: false,
        error: "API endpoint not found."
      },
      { status: 404 }
    );
  }
};
