const port = parseInt(process.env.PORT || "8081", 10);
Bun.serve({
  port,
  fetch() {
    return new Response(JSON.stringify({ status: "OK", timestamp: Date.now() }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
});
