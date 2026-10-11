# doh-worker ⚡

Wydajny, bezserwerowy resolver DNS-over-HTTPS (DoH) działający na krawędzi (Cloudflare Workers). 

Automatycznie pobiera i buforuje listę z repozytorium `dns-blocklists`, filtrując reklamy, trackery i malware w locie – bez potrzeby utrzymywania własnego VPS-a czy homelabu.

---

## Kluczowe funkcje

* **Zgodność z RFC 8484:** Natywna obsługa binarnych zapytań DNS (`application/dns-message`) przesyłanych metodami GET i POST.
* **Hierarchiczne dopasowanie:** Inteligentnie sprawdza domeny i subdomeny (np. blokada `bad.com` automatycznie obejmuje `tracker.bad.com`).
* **Parser DNS (RFC 1035):** Wbudowane parsowanie binarnego bufora z pełną obsługą wskaźników kompresji.
* **Odporność na awarie (Fallback):** Posiada wbudowaną listę awaryjną oraz logikę zapobiegającą *retry storms* w przypadku problemów z pobieraniem głównych list z GitHub Actions.
* **Krawędziowe NXDOMAIN:** Generuje i zwraca gotową odpowiedź blokady bezpośrednio z Cloudflare, bez odpytywania upstreamu.
* **Bezpieczeństwo transportu:** Usuwa nagłówki identyfikacyjne klienta przed przekazaniem legalnego ruchu do nadrzędnego resolvera.
