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

    if (url.pathname === "/dns-query" || url.pathname === "/") {
      let domainName = "";

      // Obsługa zapytań DoH metodą GET (?name=example.com lub ?dns=...)
      if (request.method === "GET") {
        domainName = url.searchParams.get("name") || "";
      }

      // Jeśli wywoływana domena znajduje się na czarnej liście -> zwracamy NXDOMAIN
      if (domainName && blocklistSet.has(domainName.toLowerCase())) {
        return new Response(
          JSON.stringify({ Status: 3, Comment: "Blocked by Custom DoH Worker" }),
          { status: 200, headers: { "Content-Type": "application/dns-json" } }
        );
      }

      // Przekazanie zapytania do bezpiecznego DNS Cloudflare (Upstream)
      return await fetch(UPSTREAM_DOH + url.search, {
        method: request.method,
        headers: request.headers,
        body: request.method === "POST" ? request.body : null
      });
    }

    return new Response("DoH Minimal Worker is Running!", { status: 200 });
  }
};
