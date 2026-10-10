const BLOCKLIST_URL = "https://raw.githubusercontent.com/Eteryu404/dns-blocklists/refs/heads/main/output/doh_combined.txt";
const UPSTREAM_DOH = "https://cloudflare-dns.com/dns-query";

let blocklistSet = new Set();
let lastFetchTime = 0;
const CACHE_TTL = 3600 * 1000; // Odświeżaj listę co 1 godzinę

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
        if (domain) newSet.add(domain.toLowerCase());
      }
      blocklistSet = newSet;
      lastFetchTime = now;
      console.log(`Załadowano bloklistę: ${blocklistSet.size} domen.`);
    }
  } catch (err) {
    console.error("Błąd podczas pobierania bloklisty:", err);
  }
}

// Funkcja wyciągająca domenę z binarnego pakietu DNS
function extractDomainFromDNS(buffer) {
  try {
    let offset = 12; // Nagłówek DNS ma zawsze 12 bajtów
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

    // Jeśli lista jest pusta, poczekaj z obsłużeniem zapytania do momentu jej pobrania
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
          // Dekodowanie zapytania DoH z formatu base64url (?dns=...)
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

      // Sprawdzenie, czy domena jest na czarnej liście -> zwracamy NXDOMAIN
      if (domainName && blocklistSet.has(domainName.toLowerCase())) {
        return new Response(
          JSON.stringify({ Status: 3, Comment: "Blocked by Custom DoH Worker" }),
          { status: 200, headers: { "Content-Type": "application/dns-json" } }
        );
      }

      // Przekazanie zapytania do nadrzędnego Cloudflare
      return await fetch(UPSTREAM_DOH + url.search, {
        method: request.method,
        headers: request.headers,
        body: queryBuffer ? queryBuffer : (request.method === "POST" ? request.body : null)
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};
