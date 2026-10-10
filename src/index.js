const BLOCKLIST_URL = "https://raw.githubusercontent.com/Eteryu404/dns-blocklists/refs/heads/main/output/doh_combined.txt";
const UPSTREAM_DOH = "https://cloudflare-dns.com/dns-query";

let blocklistSet = new Set();
let lastFetchTime = 0;
const CACHE_TTL = 3600 * 1000;

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
        let line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;
        // Oczyszczanie ewentualnych prefiksów hosts (0.0.0.0 / 127.0.0.1)
        line = line.replace(/^(0\.0\.0\.0|127\.0\.0\.1)\s+/, '').split('#')[0].trim();
        if (line) {
          newSet.add(line.toLowerCase());
        }
      }
      blocklistSet = newSet;
      lastFetchTime = now;
      console.log(`Załadowano bloklistę: ${blocklistSet.size} domen.`);
    }
  } catch (err) {
    console.error("Błąd podczas pobierania bloklisty:", err);
  }
}

// Funkcja sprawdzająca domenę oraz jej domeny nadrzędne (subdomeny)
function isBlocked(domain, blocklist) {
  if (blocklist.has(domain)) return true;
  const parts = domain.split('.');
  for (let i = 1; i < parts.length; i++) {
    const parent = parts.slice(i).join('.');
    if (blocklist.has(parent)) return true;
  }
  return false;
}

function extractDomainFromDNS(buffer) {
  try {
    let offset = 12;
    let parts = [];
    while (offset < buffer.byteLength) {
      let len = buffer[offset];
      if (len === 0) break;
      offset++;
      if (offset + len > buffer.byteLength) break;
      let label = new TextDecoder().decode(buffer.subarray(offset, offset + len));
      parts.push(label);
      offset += len;
    }
    return parts.join('.');
  } catch (e) {
    return "";
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (blocklistSet.size === 0) {
      await loadBlocklist();
    } else {
      ctx.waitUntil(loadBlocklist());
    }

    if (url.pathname === "/") {
      return new Response("DoH Minimal Worker is Running!", { status: 200 });
    }

    if (url.pathname === "/dns-query") {
      let domainName = "";
      let queryBuffer = null;

      if (request.method === "GET") {
        const dnsParam = url.searchParams.get("dns");
        if (dnsParam) {
          let base64 = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
          while (base64.length % 4) base64 += '=';
          const binaryString = atob(base64);
          queryBuffer = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
            queryBuffer[i] = binaryString.charCodeAt(i);
          }
        } else {
          domainName = url.searchParams.get("name") || "";
        }
      } else if (request.method === "POST") {
        const arrayBuffer = await request.arrayBuffer();
        queryBuffer = new Uint8Array(arrayBuffer);
      }

      if (queryBuffer) {
        domainName = extractDomainFromDNS(queryBuffer);
      }

      // Sprawdzenie domeny wraz z dziedziczeniem subdomen
      if (domainName && isBlocked(domainName.toLowerCase(), blocklistSet)) {
        return new Response(
          JSON.stringify({ Status: 3, Comment: "Blocked by Custom DoH Worker" }),
          { status: 200, headers: { "Content-Type": "application/dns-json" } }
        );
      }

      return await fetch(UPSTREAM_DOH + url.search, {
        method: request.method,
        headers: request.headers,
        body: queryBuffer ? queryBuffer : (request.method === "POST" ? request.body : null)
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};
