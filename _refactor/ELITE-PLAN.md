# ELITE-PLAN — Investigación pasiva de élite
**Fecha:** 2026-11-02
**Repo raíz:** `/home/user/claudeinfo` (rama `claude/quirky-feynman-s2jxet`)
**Estado inicial:** repo VACÍO (0 commits). No había `writeups/`, `skills/`, `docs/` ni `_refactor/`. Creadas en Paso 0.

---

## 0 — HALLAZGOS DE VIABILIDAD (test real, no teoría)

Antes de planificar hice un fetch de prueba contra Tier 1
(`portswigger.net/research/http1-must-die`, James Kettle, 2025-08-06). Cargó bien
(HTTP 200, 55 KB). Tres hallazgos cambian el plan:

### H1 — La conversión HTML→texto COLAPSA los saltos de línea en bloques de código
Los payloads de request smuggling dependen **enteramente** de la posición exacta de
CRLF. El fetch devuelve `POST / HTTP/1.1 Host: x Content-Length: 35 0 GET /robots.txt...`
en una sola línea. Eso **no es reproducible** y chocaría con el contrato
("literal, no resumido").

**Decisión:** priorizar clases cuyo payload es **robusto a la conversión**
(una línea): vectores XSS, URLs SSRF, cadenas SQLi/SSTI, comandos curl, queries
GraphQL, manipulaciones JWT. Las clases multi-línea de protocolo (desync, smuggling)
se tratan como conjunto reducido y se marcan `confianza: media` con una nota
explícita de que la estructura de líneas se reconstruyó del render colapsado,
siempre con URL de origen para verificación. **No afirmaré literalidad que no tengo.**

### H2 — Las fuentes Tier 1 redactan hostnames por política de divulgación
PortSwigger usa `<redacted>` en los case studies. El contrato prohíbe placeholders y
la validación de Fase 4 hace `grep REDACTED`. Aplicado literalmente, esto
**rechazaría casi todo el Tier 1**, que es exactamente la fuente más valiosa.

**Decisión propuesta** — distinguir dos cosas que el contrato mezcla:
- **Placeholder de instancia** (`YOUR-LAB-ID`, `<target>`) → irreproducible → **RECHAZAR**.
- **Host redactado en research publicada donde el vendor SÍ está nombrado en prosa**
  → **ACEPTAR**, sustituyendo por el host que el artículo da literal cuando existe.
  De este artículo salen hosts reales utilizables: `auth.lastpass.com`,
  `h1.sec.gitlab.net`, `app.netlify.com`, `www.sky.com`.
- Bloque con host redactado **y** vendor sin nombrar → **RECHAZAR**.

### H3 — No hay Chrome MCP en esta sesión
Verificado: no existen herramientas de navegador (ni `mcp__claude-in-chrome__*` ni
built-in browser; requieren app de escritorio u ordenador vinculado). Dispongo solo de
**WebSearch + agente web-fetch**. Fuentes con paywall, audio o JS duro
(Critical Thinking Podcast en audio, partes de YesWeHack) pueden fallar y se anotarán
en `ELITE-REJECTED.md` como fallo de acceso, no como fallo de calidad.

---

## 1 — AVISO CRÍTICO: EL CONTENEDOR ES EFÍMERO

El prompt dice "NO hagas git push, el usuario lo hará manualmente". Problema real:
**esta sesión es un contenedor cloud desechable.** No es tu máquina. Cuando la sesión
quede inactiva o termine, el contenedor se recicla y **todo lo no empujado se pierde**.
No puedes hacer `git push` tú luego: el repo local al que me refiero no existirá.

Opciones (elige una en tu OK):
- **(A) Recomendada** — yo hago commit y `git push -u origin claude/quirky-feynman-s2jxet`
  y abro PR en borrador. Tú revisas y haces merge o descartas. Nada toca `main`.
- **(B)** Yo hago solo commit local, sin push. Queda en el historial git del contenedor.
  Si la sesión muere antes de que lo recuperes, **se pierde**.
- **(C)** Literal al prompt: ni commit ni push. Máximo riesgo de pérdida total.

---

## 2 — CLASES Y CUOTA (objetivo ~110, techo duro 120)

| Clase | Cuota | Fuentes principales (Tier 1 / Tier 2) |
|---|---|---|
| `xss` | 20 | PortSwigger XSS cheat sheet + research (DOM, mXSS), OWASP XSS Filter Evasion, NahamSec blind XSS |
| `inyeccion` | 18 | PortSwigger SQLi/SSTI, NoSQLi, cmd injection, GraphQL, prototype pollution, deserialización (CVE con advisory) |
| `auth` | 16 | Frans Rosén / Detectify Labs (OAuth), SAML, JWT, OWASP Auth + Cheat Sheet Series |
| `protocolo` | 14 | **(carpeta nueva, ver §4)** HTTP/1.1 Must Die, HTTP Desync Attacks, browser-powered desync |
| `ssrf` | 12 | PortSwigger SSRF research, AWS IMDSv1→v2, OWASP SSRF cheatsheet |
| `info-disclosure` | 12 | OWASP XS-Leaks, source maps / Next.js, exposición `.git`, fuga de headers, cache deception |
| `idor` | 10 | Reports H1 divulgados con ID verificable, OWASP API Top 10 (BOLA), GraphQL node IDs |
| `logica-negocio` | 10 | PortSwigger business logic, flujos de pago, OWASP WSTG |
| `race` | 8 | Kettle "Smashing the State Machine", single-packet attack, TOCTOU con advisory |

Regla de parada por clase: **15 búsquedas sin candidato válido → cierro esa clase** y lo
anoto. Prefiero 60 verificados que 120 rellenados.

## 3 — SKILLS (máx 6, ≤200 líneas cada una, contrato estricto)

1. `desync-triage` — árbol V-H / H-V, Expect, gadgets de respuesta temprana
2. `xss-sink-triage` — de reflejo a ejecución, dirigido por contexto de sink
3. `oauth-flow-audit` — OAuth/OIDC/SAML: redirect_uri, state, confusión de flujo
4. `ssrf-escalation` — de SSRF ciego a metadata cloud / interno
5. `idor-at-scale` — enumeración de referencias + matriz de autorización
6. `race-window` — single-packet attack, máquinas de estado, TOCTOU

Cada una con: frontmatter (`name`, `description` ≤200 chars, `model`), bloque
`0 — SEÑAL CITADA`, árbol de coste creciente, "Cuándo esta skill NO es la correcta"
con `skill:<nombre>`, "Trampas de falso positivo" (2-3 señales de muerte), output
declarado en `evidencias/<skill>-<slug>.md`.

## 4 — DECISIÓN QUE NECESITA TU OK: carpeta `writeups/protocolo/`

El Paso 0 fija 8 carpetas y no incluye protocolo/desync — pero el enum de frontmatter
del propio contrato **sí admite `clase: protocolo`**, y el mejor material Tier 1
disponible (Kettle) es exactamente eso. Propongo crear `writeups/protocolo/`.
Si prefieres no salirte de las 8, reparto desync entre `info-disclosure` y `auth`
según impacto, aunque queda peor clasificado.

## 5 — CONVENCIÓN DE CAMPOS DERIVADOS (honestidad de procedencia)

El contrato pide `control_negativo` y `remediación`, que la mayoría de writeups
publicados **no incluyen** explícitamente. El propio spec admite remediación
"del writeup o derivada". Aplico lo mismo al control negativo y lo marco:
- Campo tomado literal de la fuente → sin marca.
- Campo derivado por mí (diseño de test A/B, remediación inferida) → sufijo
  `# [derivado]` en la línea. Así nunca confundes lo citado con lo razonado.

## 6 — FASES

- **Fase 0** (hecha) — raíz, estructura, test de viabilidad, este plan.
- **Fase 1** — writeups. Un source Tier 1 rinde varios writeups (del artículo de
  prueba salen ~8). Estimo 25-35 fetches.
- **Fase 2** — 6 skills.
- **Fase 3** — `docs/ELITE-MINDSET.md`, 12-15 principios con fuente + aplicación.
- **Fase 4** — validación (frontmatter, placeholders, `wc -l` de skills),
  `ELITE-REPORT.md`, `docs/ELITE-SOURCES.md`, `ELITE-COUNTER.txt`.

## 7 — LÍMITES QUE RESPETO

Sin atacar ningún target. Solo lectura de research pública. Sin repos genéricos tipo
`awesome-*`. Sin material filtrado. Sin inventar payloads. Todo ruta relativa a la raíz.

---
## DECISIONES DEL USUARIO (2026-11-02)
- **Persistencia:** opción (A) — commit + `git push -u origin claude/quirky-feynman-s2jxet` + PR en **borrador**. No se toca `main`.
- **Redacción H2:** aceptar writeup cuando el vendor está nombrado en prosa, sustituyendo el host literal cuando el artículo lo da. Rechazar si host redactado **y** vendor sin nombrar.
- **`writeups/protocolo/`:** creada (9ª clase, coherente con el enum de frontmatter).
