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
