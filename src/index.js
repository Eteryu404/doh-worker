const BLOCKLIST_URL = "https://raw.githubusercontent.com/Eteryu404/dns-blocklists/refs/heads/main/output/doh_combined.txt";
const DEFAULT_UPSTREAM = "https://cloudflare-dns.com/dns-query";

// Awaryjna lista blokad na wypadek braku łączności z GitHubem
const FALLBACK_BLOCKLIST = new Set([
  "doubleclick.net",
  "googlesyndication.com",
  "googleadservices.com",
  "google-analytics.com",
  "googletagmanager.com",
  "facebook.com",
  "facebook.net",
  "fbcdn.net",
  "adservice.google.com",
  "ads.google.com",
  "telemetry.microsoft.com",
  "v10.events.data.microsoft.com"
]);

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
    } else {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch (err) {
    console.error("Błąd podczas pobierania bloklisty:", err);
    if (blocklistSet.size === 0) {
      blocklistSet = FALLBACK_BLOCKLIST;
      console.log("Użyto awaryjnej listy blokad.");
    }
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

// Parser domen z obsługą kompresji DNS (RFC 1035)
function extractDomainFromDNS(buffer) {
  try {
    let offset = 12;
    let parts = [];
    let jumped = false;
    let safety = 0;

    while (offset < buffer.byteLength && safety < 128) {
      safety++;
      const len = buffer[offset];

      if (len === 0) break;

      // Obsługa kompresji (bity 11xxxxxx = 0xC0)
      if ((len & 0xC0) === 0xC0) {
        if (offset + 1 >= buffer.byteLength) break;
        const pointer = ((len & 0x3F) << 8) | buffer[offset + 1];
        offset = pointer;
        jumped = true;
        continue;
      }

      offset++;
      if (offset + len > buffer.byteLength) break;
      const label = new TextDecoder().decode(buffer.subarray(offset, offset + len));
      parts.push(label);
      offset += len;

      if (jumped) break; // Po skoku zakończenie przetwarzania etykiety
    }

    return parts.join('.');
  } catch (e) {
    return "";
  }
}

// Generowanie odpowiedzi NXDOMAIN z walidacją bufora
function buildNxdomainWireFormat(requestBuffer) {
  if (!requestBuffer || requestBuffer.byteLength < 12) {
    return new Uint8Array([
      0x00, 0x00, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]);
  }

  const qdcount = (requestBuffer[4] << 8) | requestBuffer[5];
  if (qdcount === 0 || requestBuffer.byteLength < 17) {
    return new Uint8Array([
      requestBuffer[0], requestBuffer[1], 0x81, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
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

// Generowanie binarnej odpowiedzi NXDOMAIN dla zapytań ?name=... z walidacją dł. etykiety
function buildNxdomainResponseForDomain(domainName, qtype = 1) {
  const cleanDomain = domainName.toLowerCase().replace(/\.$/, '');
  const rawLabels = cleanDomain ? cleanDomain.split('.') : [];
  
  // Walidacja etykiet (maks. 63 znaki na etykietę)
  const labels = rawLabels.filter(l => l.length > 0 && l.length <= 63);
  
  let qnameLen = 1;
  for (const label of labels) {
    qnameLen += label.length + 1;
  }
  
  const bufferLen = 12 + qnameLen + 4;
  const responseBuffer = new Uint8Array(bufferLen);
  
  // Determinostyczny Transaction ID (0x0000)
  responseBuffer[0] = 0x00;
  responseBuffer[1] = 0x00;
  responseBuffer[2] = 0x81;
  responseBuffer[3] = 0x83; // NXDOMAIN
  responseBuffer[4] = 0x00;
  responseBuffer[5] = 0x01; // QDCOUNT = 1
  
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
  
  // QTYPE & QCLASS
  responseBuffer[offset] = (qtype >> 8) & 0xFF;
  responseBuffer[offset + 1] = qtype & 0xFF;
  offset += 2;
  responseBuffer[offset] = 0x00;
  responseBuffer[offset + 1] = 0x01;
  
  return responseBuffer;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upstreamUrl = (env && env.UPSTREAM_DOH) ? env.UPSTREAM_DOH : DEFAULT_UPSTREAM;

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

      // Zwrot odpowiedzi NXDOMAIN przy zablokowaniu
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

      // Oczyszczanie nagłówków przy przekazywaniu do upstreamu
      const forwardHeaders = new Headers(request.headers);
      forwardHeaders.delete("host");
      forwardHeaders.delete("cf-connecting-ip");
      forwardHeaders.delete("cf-ray");
      forwardHeaders.delete("cf-ipcountry");

      // Poprawka dla metody GET: wysyłanie body TYLKO przy POST
      const isPost = request.method === "POST";
      return await fetch(upstreamUrl + url.search, {
        method: request.method,
        headers: forwardHeaders,
        body: isPost ? queryBuffer : null
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};
