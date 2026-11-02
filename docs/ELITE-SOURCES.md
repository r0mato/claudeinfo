# ELITE-SOURCES — Inventario de fuentes
**Fecha:** 2026-11-02 · 13 documentos, 5 dominios. Todas consultadas en esta sesión.

## Tier 1 — Investigación original

| # | Documento | Autor / fecha | Writeups | Skill |
|---|---|---|---|---|
| 1 | [HTTP/1.1 must die: the desync endgame](https://portswigger.net/research/http1-must-die) | James Kettle, 2025-08-06 (act. 2025-10-17) | 4 (`protocolo`) | `desync-triage` |
| 2 | [Smashing the state machine](https://portswigger.net/research/smashing-the-state-machine) | James Kettle, 2023-08-09 (act. 2023-09-18) | 4 (`race`) | `race-window` |
| 3 | [Splitting the email atom](https://portswigger.net/research/splitting-the-email-atom) | Gareth Heyes, 2024-08-07 (act. 2025-06-27) | 5 (`auth`) | — |
| 4 | [Account hijacking using "dirty dancing" in sign-in OAuth-flows](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/) | Frans Rosén / Detectify, 2022-07-06 | 5 (`auth`) | `oauth-flow-audit` |

**CVEs documentados:** CVE-2025-32094 (Akamai), CVE-2022-4037 (GitLab/Devise),
CVE-2024-21725 (Joomla).

**Vendors con caso nombrado:** Akamai, Cloudflare, Heroku, Netlify, GitLab, T-Mobile,
LastPass, Sky, AWS (ALB), Microsoft (IIS), Joomla, GitHub, Zendesk, Facebook, Google,
Apple, Devise/Rails, IdnaConvert, Sendmail 8.15.2, Postfix 3.6.4.

## Tier 2 — Cheat sheets de élite

| # | Documento | Writeups | Skill |
|---|---|---|---|
| 5 | [PortSwigger XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) (act. 2026-10-21) | 9 (`xss`) | `xss-sink-triage` |
| 6 | [PortSwigger SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) | 6 (`inyeccion`) | — |
| 7 | [PortSwigger JWT attacks](https://portswigger.net/web-security/jwt) + [algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion) | 7 (`auth`) | `jwt-attack-tree` |
| 8 | [OWASP XS-Leaks Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html) (CC BY-SA 4.0) | 4 (`info-disclosure`) | — |
| 9 | [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | 3 (`ssrf`) | `ssrf-escalation` |
| 10 | [OWASP OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) | 3 (`inyeccion`) | — |
| 11 | [PortSwigger access control / IDOR](https://portswigger.net/web-security/access-control) | 4 (`idor`) | — |
| 12 | [PortSwigger business logic flaws](https://portswigger.net/web-security/logic-flaws/examples) | 2 (`logica-negocio`) | — |

## Tier 1 — Entrevistas (mindset)

| # | Documento | Sujeto / fecha | Tipo |
|---|---|---|---|
| 13 | [The rabhi route to root](https://www.yeswehack.com/community/rabhi-root-bug-bounty-blueprint) | rabhi, nº1 histórico YesWeHack, 2025-09-16 | texto |
| 14 | [Chackal and Serizao on passion, persistence and partnerships](https://www.yeswehack.com/community/bug-bounty-targets-chackal-serizao) | Chackal (12º) y Serizao (21º), 2024-03-13 | texto |
| 15 | [We think we know our mind is our best hacking tool](https://pentest-tools.com/blog/we-think-we-know-inti-de-ceukelaire) | Inti De Ceukelaire, act. 2024-02-28 | **transcripción de audio** |

⚠️ La fuente 15 es una transcripción con errores evidentes ("using your might" por
"mind", "Intigrity" por "Intigriti"). Marcada con `[sic]` en `ELITE-MINDSET.md`.

## Fuentes consultadas y NO usadas

| Fuente | Por qué |
|---|---|
| OWASP SSTI Prevention Cheat Sheet | **Cero payloads.** Clase SSTI rechazada entera. |
| `splitting-the-email-atom.pdf` | Binario sin texto legible. |
| Critical Thinking Podcast / HackerNotes | Audio; sin transcripciones alcanzables y sin Chrome MCP en esta sesión. |
| NahamSec blog | No alcanzada por presupuesto de fetches; XSS quedó cubierto. |

## Fuentes prohibidas por el contrato — cumplimiento

No se usó: ningún repositorio genérico de GitHub tipo `awesome-*`, ningún foro
underground, ningún material filtrado, ningún blog de "cómo empecé en bug bounty" sin
payload reproducible. Los únicos enlaces a GitHub que aparecen son **citados por las
fuentes Tier 1** (la wordlist de secretos JWT de Wallarm, `rsa_sign2n`, Turbo Intruder),
nunca como fuente primaria.

## Nota sobre el alcance de la investigación

Sesión **100% pasiva**: no se atacó ningún objetivo, no se envió una sola petición a
ningún sistema de terceros. Todo el contenido proviene de investigación publicada. Las
propias fuentes declaran su autorización — PortSwigger: *"All case-studies were
identified through authorized testing on targets with vulnerability disclosure programs
(VDPs)."*

---
# FASE 5 — fuentes adicionales (2026-11-02)

## Tier 1 — Investigación original (nuevas)

| # | Documento | Autor / fecha | Writeups |
|---|---|---|---|
| 16 | [Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection) | James Kettle, 2015-08-05 (act. 2025-09-03) | 5 (`inyeccion`) |
| 17 | [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning) | James Kettle, 2018-08-09 | 2 (`cache`) |
| 18 | [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement) | James Kettle, 2020-08-05 | 3 (`cache`) |
| 19 | [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks) | James Kettle, 2022-08-10 | 3 (`protocolo`) |
| 20 | [Listen to the whispers: web timing attacks that actually work](https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work) | James Kettle, 2024-08-07 | 2 (`ssrf`, `info-disclosure`) |
| 21 | [Cracking the lens](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface) | James Kettle, 2017-07-27 | 2 (`ssrf`) |
| 22 | [Widespread prototype pollution gadgets](https://portswigger.net/research/widespread-prototype-pollution-gadgets) | Gareth Heyes, 2022-06-22 | 2 (`inyeccion`) |

**CVEs añadidos:** CVE-2022-23959 (Varnish), CVE-2022-22720 (Apache).
**Recompensas verificadas:** $15.000 + $8.000 + $5.000 + $5.000 (Yahoo, total $33.000),
$10.000 (GitHub), $4.000 (Apache vía Internet Bug Bounty), $1.000 (Mozilla).

## Tier 2 — Academy (nuevas)

| # | Documento | Writeups |
|---|---|---|
| 23 | [GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql) | 3 (`inyeccion`) |
| 24 | [NoSQL injection](https://portswigger.net/web-security/nosql-injection) | 2 (`inyeccion`) |
| 25 | [XXE](https://portswigger.net/web-security/xxe) + [blind XXE](https://portswigger.net/web-security/xxe/blind) | 2 (`inyeccion`) |
| 26 | [Prototype pollution](https://portswigger.net/web-security/prototype-pollution) (+ client-side, server-side, preventing) | 1 (`inyeccion`) |
| 27 | [Deserialization](https://portswigger.net/web-security/deserialization) + exploiting | 0 — material extraído, writeup pendiente |
| 28 | [SSTI](https://portswigger.net/web-security/server-side-template-injection) | contribuye a los 5 de SSTI |

## Mapa de prioridades para continuar

Se consultó [Top 10 Web Hacking Techniques of 2024](https://portswigger.net/research/top-10-web-hacking-techniques-of-2024)
(James Kettle, 2025-02-04; 121 nominaciones, 103 tras filtrar, panel de Nicolas Grégoire,
Soroush Dalili, STÖK, LiveOverflow y Kettle) **como mapa, no como fuente**. Es el
backlog priorizado por el propio sector:

| # | Técnica | Autor | Fuente primaria |
|---|---|---|---|
| 1 | Confusion Attacks: Apache HTTP Server | Orange Tsai | https://blog.orange.tw/posts/2024-08-confusion-attacks-en/ |
| 2 | SQL Injection Isn't Dead: Smuggling Queries at the Protocol Level | Paul Gerste | https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/DEF%20CON%2032%20-%20Paul%20Gerste%20-%20SQL%20Injection%20Isn%27t%20Dead%20Smuggling%20Queries%20at%20the%20Protocol%20Level.pdf |
| 3 | Unveiling TE.0 HTTP Request Smuggling (Google Cloud) | Arnolfo, Gregorio, @_medusa_1_ | https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/ |
| 4 | WorstFit: Hidden Transformers in Windows ANSI | Orange Tsai, splitline | https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/ |
| 5 | Exploring the DOMPurify library: Bypasses and Fixes | Mizu | https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes |
| 6 | DoubleClickjacking | Paulos Yibelo | https://www.paulosyibelo.com/2024/12/doubleclickjacking-what.html |
| 7 | CVE-2024-4367 — JS arbitrario en PDF.js | Thomas Rinsma | https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/ |
| 8 | OAuth Non-Happy Path to ATO | Oxrz | https://blog.voorivex.team/oauth-non-happy-path-to-ato |
| 9 | ChatGPT ATO — Wildcard Web Cache Deception | Harel | https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html |
| 10 | Hijacking OAuth flows via Cookie Tossing | Elliot Ward | https://snyk.io/articles/hijacking-oauth-flows-via-cookie-tossing/ |

Nota: PortSwigger excluye su propia investigación del voto. Los tres suyos que estaban en
la preselección de 15 son `gotta-cache-em-all`, `splitting-the-email-atom` (ya usado, 5
writeups) y `listen-to-the-whispers` (ya usado, 2 writeups).

## Fuente que falló en Fase 5

| Fuente | Por qué |
|---|---|
| `portswigger.net/research/sso-wars-the-token-menace` | HTTP 404. El fallback `/web-security/saml` **también** 404. La clase SAML/SSO queda sin cubrir; no se rellenó de memoria. |

---
# FASE 6 — primarios del Top 10 Web Hacking Techniques of 2024

Seis de los diez primarios, extraídos directamente. El ranking se usó como mapa en la
Fase 5; esta fase lo ejecuta.

| Top 10 | Documento | Autor / fecha | Writeups | CVEs |
|---|---|---|---|---|
| **#1** | [Confusion Attacks: Apache HTTP Server](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/) | Orange Tsai, 2024-08-09 | 4 (`idor`, `protocolo`, `info-disclosure`, `ssrf`) | CVE-2024-38472, CVE-2024-39573 (los 2 que la fuente mapea) |
| **#3** | [Unveiling TE.0 HTTP Request Smuggling](https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/) | Arnolfo, Gregorio, @_medusa_1_, 2024-07-17 | 1 (`protocolo`) | — ($8.500) |
| **#5** | [Exploring the DOMPurify library](https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes) | Mizu, 2024-11-17 | 1 (`xss`) | — |
| **#7** | [CVE-2024-4367 en PDF.js](https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/) | Thomas Rinsma, 2024-05-20 | 1 (`xss`) | CVE-2024-4367 |
| **#9** | [ChatGPT ATO — Wildcard Web Cache Deception](https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html) | Harel / Nokline, 2024-02-04 | 1 (`cache`) | — ($6.500) |
| **#10** | [Hijacking OAuth flows via Cookie Tossing](https://snyk.io/articles/hijacking-oauth-flows-via-cookie-tossing/) | Elliot Ward / Snyk, 2024-11-26 | 1 (`auth`) | CVE-2024-21583, CVE-2024-28233 |

Fuente complementaria leída para el #10:
[Cookie tossing attacks](https://www.thomashouhou.com/post/cookie-tossing-attacks)
(Thomas Houhou, 2024-07-15, versión escrita de su charla en Area41). Solo los primeros
39.402 de 61.222 caracteres llegaron verbatim.

**Recompensas verificadas en esta fase:** $8.500 (Google Cloud), $6.500 (OpenAI).

## Advertencia sobre la fiabilidad de las fuentes primarias

Esta fase produjo un hallazgo que no es técnico: **las fuentes primarias se contradicen
consigo mismas con frecuencia**. Seis casos documentados en
`_refactor/ELITE-REJECTED.md` §M. Dos con consecuencias prácticas:

1. **Snyk escribe `__Host__`** (dos guiones bajos finales) donde el prefijo correcto de
   RFC 6265bis es **`__Host-`**. Aplicar su forma literal produce una corrección
   inoperante con apariencia de aplicada.
2. **El bloque de código de DOMPurify (Fig. 55) y el enlace de PoC en vivo del propio
   artículo no coinciden.** Se conservan ambas versiones.

Más dos redacciones en el original: Orange Tsai redacta su sección 3-1-2 y el noveno CVE
del lote; Bugcrowd redacta el nombre del tercer autor de TE.0.

## Pendiente del Top 10 (4 de 10)

| # | Técnica | Nota |
|---|---|---|
| #2 | SQL Injection Isn't Dead (Paul Gerste, DEF CON 32) | PDF de diapositivas: riesgo de binario ilegible, ya visto con el PDF de `splitting-the-email-atom` |
| #4 | WorstFit: Hidden Transformers in Windows ANSI (Orange Tsai, splitline) | — |
| #6 | DoubleClickjacking (Paulos Yibelo) | Abriría una clase nueva |
| #8 | OAuth Non-Happy Path to ATO (Oxrz) | Complementaría los 5 writeups de OAuth |

Más `gotta-cache-em-all` de PortSwigger (preselección de 15), que refuerza `cache`.
