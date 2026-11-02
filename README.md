# claudeinfo — biblioteca de referencia de seguridad ofensiva

Catálogo de técnicas de seguridad web documentadas **desde investigación publicada**, con
payload literal, precondición, control negativo y criterios de descarte. Material de
referencia defensiva y educativa: no contiene objetivos, credenciales ni infraestructura.

## Estructura

```
writeups/<clase>/<slug>.md    83 writeups, 10 clases, frontmatter de 12 campos
skills/<nombre>/SKILL.md       6 árboles de decisión de triaje (≤200 líneas)
docs/ELITE-MINDSET.md         20 principios de caza con fuente atribuible
docs/ELITE-SOURCES.md         inventario de las 28 fuentes + backlog priorizado
_refactor/ELITE-REPORT.md     informe de construcción y decisiones de criterio
_refactor/ELITE-REJECTED.md   40+ candidatos descartados, con el motivo
```

## Writeups por clase

| Clase | N | Destacado |
|---|---|---|
| `inyeccion` | 24 | SQLi por motor, SSTI (RCE por motor), GraphQL, NoSQL, XXE, prototype pollution |
| `auth` | 17 | JWT (7), parsers de correo (5), OAuth (5) |
| `xss` | 9 | vectores sin interacción del usuario |
| `protocolo` | 7 | desync HTTP/1.1, client-side desync, CVE-2025-32094, CVE-2022-23959 |
| `ssrf` | 6 | scoped SSRF por timing, cabecera Host (Yahoo, $15.000) |
| `cache` | 5 | envenenamiento de caché (GitHub $10.000, Mozilla $1.000) |
| `info-disclosure` | 5 | XS-Leaks, dual-packet sync |
| `idor` | 4 | `X-Original-URL`, Spring <5.3, `Referer` |
| `race` | 4 | single-packet attack, CVE-2022-4037 |
| `logica-negocio` | 2 | importe negativo, descuento reversible |

**CVEs documentados:** CVE-2025-32094 (Akamai) · CVE-2024-21725 (Joomla) ·
CVE-2022-4037 (GitLab/Devise) · CVE-2022-22720 (Apache) · CVE-2022-23959 (Varnish).

## Cómo leer un writeup

El frontmatter lleva 12 campos. Los tres que más deciden si vale la pena seguir:

- **`precondicion`** — qué tiene que ser cierto. Si no se cumple, no sigas.
- **`control_negativo`** — el par A/B que distingue un hallazgo real de un artefacto.
  Es el campo más importante del formato y el que más informes salva.
- **`mata`** — criterios de descarte, para cerrar una vía rápido en lugar de insistir.

## Convenciones de procedencia

Este catálogo distingue siempre lo **citado** de lo **razonado**:

- Sin marca → literal de la fuente.
- `# [derivado]` → diseñado o inferido por mí (controles negativos, remediaciones
  deducidas, estimaciones de CVSS). Nunca presentado como cita.
- `confianza: alta` → payload verificado y objetivo nombrado (47 writeups).
- `confianza: media` → hay un caveat declarado en el propio writeup: estructura CRLF
  reconstruida, host redactado por política de divulgación, o payload parcial (36).
- Cuando una fuente **no** contiene un payload, el writeup lo dice y **no** se inventa.
  Ver `_refactor/ELITE-REJECTED.md` §D.

## Alcance y uso previsto

Investigación 100% pasiva: ninguna petición se envió a ningún sistema de terceros. El
contenido procede de PortSwigger Research (11 papers), OWASP Cheat Sheet Series,
Detectify Labs y entrevistas publicadas, todas citadas en `docs/ELITE-SOURCES.md`, que
incluye además el backlog priorizado según el Top 10 Web Hacking Techniques del sector.

Pensado para pruebas autorizadas: programas de bug bounty con alcance declarado,
compromisos de pentesting contratados, CTF y defensa. Las propias fuentes operan bajo esa
regla — PortSwigger declara en su investigación de desync: *"All case-studies were
identified through authorized testing on targets with vulnerability disclosure programs
(VDPs)."*

Un writeup incluye payload de exfiltración (`onbeforeunload-exfiltracion-sendbeacon.md`)
con su límite explícito: solo contra cuentas propias del investigador y un host bajo su
control. Demostrar la capacidad basta para un informe; recolectar datos de usuarios
reales excede el permiso de cualquier programa.
