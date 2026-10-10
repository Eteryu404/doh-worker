const BLOCKLIST_URL = "https://raw.githubusercontent.com/Eteryu404/dns-blocklists/refs/heads/main/output/doh_combined.txt";
const UPSTREAM_DOH = "https://cloudflare-dns.com/dns-query";

let blocklistSet = new Set();
let lastFetchTime = 0;
const CACHE_TTL = 3600 * 1000; // Odświeżaj listę w pamięci Workera co 1 godzinę

async function loadBlocklist() {
  const now = Date.now();
  if (blocklistSet.size > 0 && (now - lastFetchTime) < CACHE_TTL) {
    return;
  }
  try {
    const res = await fetch(BLOCKLIST_URL);
    if (res.ok) {
      const text = await res.text();
      const lines = text.split('\n');
      const newSet = new Set();
      for (let i = 0; i < lines.length; i++) {
        const domain = lines[i].trim();
        if (domain) newSet.add(domain);
      }
      blocklistSet = newSet;
      lastFetchTime = now;
      console.log(`Pomyślnie załadowano czarną listę: ${blocklistSet.size} domen.`);
    }
  } catch (err) {
    console.error("Błąd podczas pobierania listy domen z GitHub:", err);
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Pobierz/odśwież listę domen w tle
    ctx.waitUntil(loadBlocklist());

    // 1. Ładna, wyśrodkowana, zielona strona główna
    if (url.pathname === "/") {
      const html = `<!DOCTYPE html>
      <html lang="pl">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>DoH Worker Status</title>
          <style>
              body {
                  background-color: #0f172a;
                  color: #22c55e;
                  display: flex;
                  justify-content: center;
                  align-items: center;
                  height: 100vh;
                  margin: 0;
                  font-family: system-ui, -apple-system, sans-serif;
              }
              h1 {
                  font-size: 1.8rem;
                  text-align: center;
                  padding: 20px;
              }
          </style>
      </head>
      <body>
          <h1>DoH Minimal Worker is Running!</h1>
      </body>
      </html>`;

      return new Response(html, {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    if (url.pathname === "/dns-query") {
      let domainName = "";

      if (request.method === "GET") {
        domainName = url.searchParams.get("name") || "";
      }

      if (request.method === "GET" && !url.search) {
        return new Response("DoH Endpoint is Active. Please configure this URL in your DNS client.", { status: 200 });
      }

      if (domainName && blocklistSet.has(domainName.toLowerCase())) {
        return new Response(
          JSON.stringify({ Status: 3, Comment: "Blocked by Custom DoH Worker" }),
          { status: 200, headers: { "Content-Type": "application/dns-json" } }
        );
      }

      return await fetch(UPSTREAM_DOH + url.search, {
        method: request.method,
        headers: request.headers,
        body: request.method === "POST" ? request.body : null
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};
