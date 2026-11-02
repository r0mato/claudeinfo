# ELITE-REPORT — Informe final
**Fecha:** 2026-11-02 · **Repo:** `r0mato/claudeinfo` · **Rama:** `claude/quirky-feynman-s2jxet`
**Estado inicial:** repo vacío, 0 commits, sin estructura.

---

## 1 — Resumen

| Capa | Fase 1-4 | **Fase 5** | **Total** | Techo |
|---|---|---|---|---|
| Writeups | 56 | +27 | **83** | 120 |
| Skills | 6 | — | **6** | 6 |
| Principios de mindset | 20 | — | **20** | 10-15 (superado) |
| Fuentes consultadas | 15 | +13 | **28 documentos** | — |
| CVEs documentados | 3 | +2 | **5** | — |

**Validación: 83/83** con los 12 campos de frontmatter y YAML parseable · **0**
placeholders prohibidos · **6/6** skills bajo el límite de 200 líneas · **6/6**
referencias cruzadas `skill:` resueltas.

## 2 — Writeups por clase

| Clase | Total | Fase 5 | Nota |
|---|---|---|---|
| `inyeccion` | **24** | +15 | SSTI resucitada de 0 a 5; GraphQL, NoSQL, XXE, prototype pollution |
| `auth` | 17 | — | JWT (7), parsers de correo (5), OAuth (5) |
| `xss` | 9 | — | cerrada: agotados los principios distintos de la fuente |
| `protocolo` | **7** | +3 | desync Expect + client-side desync + pause-based |
| `ssrf` | **6** | +3 | scoped SSRF por timing, cabecera Host (Yahoo) |
| `cache` | **5** | +5 | carpeta nueva; GitHub $10k, Mozilla $1k |
| `info-disclosure` | **5** | +1 | XS-Leaks + dual-packet sync |
| `idor` | 4 | — | solo lo atado a producto/versión concreta |
| `race` | 4 | — | 4 de 9 casos de la fuente tenían objetivo nombrado |
| `logica-negocio` | 2 | — | 4 de 6 clases de la fuente no tienen un solo payload |

## 3 — Lo que cambió en Fase 5, y por qué

El informe de la Fase 4 identificó que las cuotas incumplidas no eran un problema de
esfuerzo sino **de fuente**: los cheat sheets de OWASP y las páginas docentes de la
Academy tienen técnica pero no casos. La Fase 5 lo confirmó y lo corrigió por el único
camino viable: **ir a la investigación original**.

El contraste es medible. Siete papers de PortSwigger Research rindieron **27 writeups con
objetivos nombrados, recompensas verificadas y 2 CVEs nuevos**, mientras que en la Fase 1
el cheat sheet de SSRF de OWASP —una fuente excelente para defender— rindió 3 writeups
sin un solo objetivo real.

La conclusión transferible: **para un catálogo con criterio de "objetivo identificable",
un paper de investigación rinde entre 5 y 10 veces más que un cheat sheet defensivo.**

### SSTI: de clase muerta a 5 writeups
La Fase 1 cerró SSTI con cero porque la página de OWASP **no contiene un solo payload**.
El paper original de Kettle (2015) sí los tiene, con cuatro productos nombrados —
Alfresco, XWiki Enterprise, CodePen, y los sandboxes de Smarty y Twig con sus versiones
de corrección.

### Carpeta nueva `cache/`
Declarada, no consultada de nuevo: el precedente de `protocolo/` ya estaba aprobado por
el mismo motivo (material Tier 1 abundante que no encaja en las clases originales). Usa
`clase: otra`, que está en el enum del contrato.

## 4 — Recompensas y CVEs verificados

| Objetivo | Importe | Fuente |
|---|---|---|
| Yahoo (Apache Traffic Server overseer) | **$15.000** | Cracking the lens |
| GitHub (fat GET) | **$10.000** | Web Cache Entanglement |
| Yahoo (técnica `@`, 17 servidores) | $8.000 | Cracking the lens |
| Yahoo (normalización de ruta) | $5.000 | Cracking the lens |
| Yahoo (segundo servidor) | $5.000 | Cracking the lens |
| Apache (vía Internet Bug Bounty) | $4.000 | Browser-powered desync |
| Mozilla SHIELD | $1.000 | Practical Web Cache Poisoning |

**CVEs:** CVE-2025-32094 (Akamai) · CVE-2024-21725 (Joomla) · CVE-2022-4037
(GitLab/Devise) · CVE-2022-22720 (Apache) · CVE-2022-23959 (Varnish).

**Corrección a una premisa mía:** en el brief de *Cracking the lens* afirmé que
documentaba "pagos muy grandes". Era falso — el máximo es $15.000, el total $33.000, y
**el paper no contiene ningún CVE**. El agente lo corrigió. Lo registro porque una
premisa errónea en un brief contamina la extracción, y aquí no lo hizo solo porque hubo
verificación.

## 5 — Distribución de confianza

| `confianza` | Writeups | Qué significa |
|---|---|---|
| `alta` | **47** | payload literal verificado, objetivo o producto nombrado |
| `media` | **36** | caveat declarado en el propio writeup |
| `baja` | **0** | nada se guardó con confianza baja: se rechazó |

(Contadas con `grep`, no estimadas.)

## 6 — El hallazgo técnico que condiciona todo (H1)

La conversión HTML→texto **colapsa los saltos de línea en los bloques de código**. En la
Fase 5 esto dejó de ser un inconveniente y pasó a ser **crítico** en un caso concreto:

Los payloads de JavaScript de los ataques client-side desync contienen comentarios `//`.
Colapsados en una línea, **comentan el resto del bloque y el código no se ejecuta**. Un
investigador que copie ese payload de un render obtendrá un fallo silencioso y lo
atribuirá al objetivo.

Está declarado en el writeup afectado, con la precisión de que los `\r\n` **dentro** de
los literales de cadena sí son fiables — son escapes, no saltos reales, y son justo la
parte que importa para el desync.

## 7 — Qué sigue sin cubrirse

| Hueco | Por qué | Vía |
|---|---|---|
| **SAML / SSO** | Las dos URLs de PortSwigger dan **404**. No se rellenó de memoria. | Otra fuente |
| `idor`, `logica-negocio` | Las fuentes docentes no tienen objetivos reales | Reportes divulgados de HackerOne con ID verificable |
| Deserialización | Material extraído; writeups no escritos | Pendiente, no bloqueado |

## 8 — Backlog priorizado (no por mí, por el sector)

Consulté el **Top 10 Web Hacking Techniques of 2024** de PortSwigger *como mapa, no como
fuente*: 121 nominaciones, 103 tras filtrar, y un panel de Nicolas Grégoire, Soroush
Dalili, STÖK, LiveOverflow y Kettle. Las 10 URLs primarias están en
`docs/ELITE-SOURCES.md`.

Los tres primeros de la lista son material de primer orden y ninguno está cubierto aquí:
las **Confusion Attacks** de Orange Tsai sobre Apache HTTP Server (#1), la **inyección SQL
a nivel de protocolo** de Paul Gerste (#2), y el **TE.0 request smuggling** contra miles
de sitios de Google Cloud (#3) — este último de los mismos investigadores acreditados en
el caso de GitLab que ya está en `writeups/protocolo/`.

## 9 — Las decisiones de criterio, consolidadas

1. **Redacción con vendor nombrado** (acordado): acepto el host redactado cuando el
   vendor aparece en prosa, usando el host literal donde el artículo lo da.
2. **Material docente solo si está atado a algo concreto**: un producto, una cabecera o
   una versión. Por eso entraron Spring <5.3, `X-Original-URL`, MongoDB y GraphQL, y se
   rechazó el `?customer_number=132355` genérico.
3. **Campos derivados marcados** con `# [derivado]`. Nunca verás un campo razonado
   presentado como citado.
4. **No reconstruyo payloads que solo existen en imágenes.** En Fase 5 eso dejó fuera el
   árbol de decisión por motor de SSTI, los diagramas de pause-based desync y las
   capturas de DOM Invader — material que me habría venido bien y que no invento.
5. **Registro lo que la fuente NO dice.** `ELITE-REJECTED.md` documenta que
   `?constructor.prototype.foo=bar`, `Host: localhost`, `X-Forwarded-Host` en
   *Cracking the lens*, `<%= 7*7 %>` y los gadgets de jQuery/Lodash **no están** en las
   fuentes que se les atribuyen. Un catálogo que solo recoge lo que encontró pierde esa
   información, que es la que evita propagar folclore.
