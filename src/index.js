const BLOCKLIST_URL = "https://raw.githubusercontent.com/Eteryu404/dns-blocklists/refs/heads/main/output/doh_combined.txt";
const UPSTREAM_DOH = "https://cloudflare-dns.com/dns-query";

let blocklistSet = new Set();
let lastFetchTime = 0;
const CACHE_TTL = 3600 * 1000; // 1 godzina

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
        line = line.replace(/^(0\.0\.0\.0|127\.0\.0\.1)\s+/, '').split('#')[0].trim();
        if (line) {
          newSet.add(line.toLowerCase().replace(/\.$/, ''));
        }
      }
      if (newSet.size > 0) {
        blocklistSet = newSet;
        lastFetchTime = now;
        console.log(`Załadowano bloklistę: ${blocklistSet.size} domen.`);
      }
    }
  } catch (err) {
    console.error("Błąd podczas pobierania bloklisty:", err);
  }
}

// Sprawdzanie domeny i jej subdomen (hierarchiczne)
function isBlocked(domain, blocklist) {
  const cleanDomain = domain.toLowerCase().replace(/\.$/, '');
  if (blocklist.has(cleanDomain)) return true;
  
  const parts = cleanDomain.split('.');
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

// Generowanie binarnej odpowiedzi NXDOMAIN na podstawie istniejącego zapytania binarnego
function buildNxdomainWireFormat(requestBuffer) {
  if (!requestBuffer || requestBuffer.byteLength < 12) {
    return new Uint8Array([
      0x00, 0x00, // Transaction ID
      0x81, 0x83, // Flags: QR=1, RCODE=3 (NXDOMAIN)
      0x00, 0x01, // QDCOUNT
      0x00, 0x00, // ANCOUNT
      0x00, 0x00, // NSCOUNT
      0x00, 0x00  // ARCOUNT
    ]);
  }

  const responseBuffer = new Uint8Array(requestBuffer.slice(0));
  responseBuffer[2] = 0x81;
  responseBuffer[3] = 0x83; // NXDOMAIN
  responseBuffer[6] = 0x00; responseBuffer[7] = 0x00; // ANCOUNT
  responseBuffer[8] = 0x00; responseBuffer[9] = 0x00; // NSCOUNT
  responseBuffer[10] = 0x00; responseBuffer[11] = 0x00; // ARCOUNT

  return responseBuffer;
}

// Generowanie binarnego pakietu NXDOMAIN od zera dla zapytań typu ?name=...
function buildNxdomainResponseForDomain(domainName, qtype = 1) {
  const cleanDomain = domainName.toLowerCase().replace(/\.$/, '');
  const labels = cleanDomain ? cleanDomain.split('.') : [];
  
  let qnameLen = 1;
  for (const label of labels) {
    qnameLen += label.length + 1;
  }
  
  const bufferLen = 12 + qnameLen + 4;
  const responseBuffer = new Uint8Array(bufferLen);
  
  // Header
  responseBuffer[0] = Math.floor(Math.random() * 256);
  responseBuffer[1] = Math.floor(Math.random() * 256);
  responseBuffer[2] = 0x81;
  responseBuffer[3] = 0x83; // NXDOMAIN
  responseBuffer[4] = 0x00;
  responseBuffer[5] = 0x01; // QDCOUNT = 1
  
  // Question section
  let offset = 12;
  for (const label of labels) {
    responseBuffer[offset] = label.length;
    offset++;
    for (let i = 0; i < label.length; i++) {
      responseBuffer[offset] = label.charCodeAt(i);
      offset++;
    }
  }
  responseBuffer[offset] = 0x00;
  offset++;
  
  // QTYPE
  responseBuffer[offset] = (qtype >> 8) & 0xFF;
  responseBuffer[offset + 1] = qtype & 0xFF;
  offset += 2;
  
  // QCLASS (IN = 1)
  responseBuffer[offset] = 0x00;
  responseBuffer[offset + 1] = 0x01;
  
  return responseBuffer;
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

      // Blokowanie domeny – zawsze zwracamy binarny DNS wire format (NXDOMAIN)
      if (domainName && isBlocked(domainName, blocklistSet)) {
        let responseBuffer;
        if (queryBuffer) {
          responseBuffer = buildNxdomainWireFormat(queryBuffer);
        } else {
          const typeParam = parseInt(url.searchParams.get("type")) || 1;
          responseBuffer = buildNxdomainResponseForDomain(domainName, typeParam);
        }

        return new Response(responseBuffer, {
          status: 200,
          headers: {
            "Content-Type": "application/dns-message",
            "Cache-Control": "public, max-age=300"
          }
        });
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
