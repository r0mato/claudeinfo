# claudeinfo — biblioteca de referencia de seguridad ofensiva

Catálogo de técnicas de seguridad web documentadas **desde investigación publicada**, con
payload literal, precondición, control negativo y criterios de descarte. Material de
referencia defensiva y educativa: no contiene objetivos, credenciales ni infraestructura.

## Estructura

```
writeups/<clase>/<slug>.md    96 writeups, 10 clases, frontmatter de 12 campos
skills/<nombre>/SKILL.md       6 árboles de decisión de triaje (≤200 líneas)
docs/ELITE-MINDSET.md         20 principios de caza con fuente atribuible
docs/ELITE-SOURCES.md         inventario de las 34 fuentes + backlog priorizado
_refactor/ELITE-REPORT.md     informe de construcción y decisiones de criterio
_refactor/ELITE-REJECTED.md   40+ candidatos descartados, con el motivo
```

## Writeups por clase

| Clase | N | Destacado |
|---|---|---|
| `inyeccion` | 28 | SQLi por motor, SSTI (RCE por motor), GraphQL, NoSQL, XXE, prototype pollution, deserialización |
| `auth` | 18 | JWT (7), parsers de correo (5), OAuth (5), cookie tossing |
| `xss` | 11 | vectores sin interacción, mXSS en DOMPurify, PDF.js |
| `protocolo` | 9 | desync HTTP/1.1, client-side desync, TE.0 (Google Cloud), handler confusion en Apache |
| `ssrf` | 7 | scoped SSRF por timing, cabecera Host (Yahoo, $15.000), UNC en Apache |
| `cache` | 6 | GitHub $10.000, ChatGPT $6.500, Mozilla $1.000 |
| `info-disclosure` | 6 | XS-Leaks, dual-packet sync, DocumentRoot confusion |
| `idor` | 5 | `X-Original-URL`, Spring <5.3, `Referer`, ACL de Apache con `%3F` |
| `race` | 4 | single-packet attack, CVE-2022-4037 |
| `logica-negocio` | 2 | importe negativo, descuento reversible |

**10 CVEs como sujeto:** CVE-2025-32094 (Akamai) · CVE-2024-21725 (Joomla) ·
CVE-2024-21583 (GitPod) · CVE-2024-28233 (JupyterHub) · CVE-2024-38472 y CVE-2024-39573
(Apache) · CVE-2024-4367 (PDF.js) · CVE-2022-4037 (GitLab/Devise) · CVE-2022-22720
(Apache) · CVE-2022-23959 (Varnish).

Incluye 6 de los 10 primarios del **Top 10 Web Hacking Techniques of 2024**, entre ellos
el nº1 (Orange Tsai, Apache) y el nº3 (TE.0 contra Google Cloud).

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
- `confianza: alta` → payload verificado y objetivo nombrado (56 writeups).
- `confianza: media` → hay un caveat declarado en el propio writeup: estructura CRLF
  reconstruida, host redactado por política de divulgación, o payload parcial (40).
- Cuando una fuente **no** contiene un payload, el writeup lo dice y **no** se inventa.
  Ver `_refactor/ELITE-REJECTED.md` §D.

## Alcance y uso previsto

Investigación 100% pasiva: ninguna petición se envió a ningún sistema de terceros. El
contenido procede de PortSwigger Research (11 papers), OWASP Cheat Sheet Series,
Detectify Labs, los primarios del Top 10 Web Hacking Techniques of 2024 (Orange Tsai,
Mizu, Bugcrowd, Snyk, Codean Labs, Nokline) y entrevistas publicadas, todas citadas en
`docs/ELITE-SOURCES.md`.

Las fuentes primarias **se contradicen entre sí y consigo mismas** con más frecuencia de
lo esperable. `_refactor/ELITE-REJECTED.md` §M documenta las discrepancias detectadas,
incluida una errata en una remediación publicada (`__Host__` donde debe ser `__Host-`)
que produciría una corrección inoperante con apariencia de aplicada.

Pensado para pruebas autorizadas: programas de bug bounty con alcance declarado,
compromisos de pentesting contratados, CTF y defensa. Las propias fuentes operan bajo esa
regla — PortSwigger declara en su investigación de desync: *"All case-studies were
identified through authorized testing on targets with vulnerability disclosure programs
(VDPs)."*

Un writeup incluye payload de exfiltración (`onbeforeunload-exfiltracion-sendbeacon.md`)
con su límite explícito: solo contra cuentas propias del investigador y un host bajo su
control. Demostrar la capacidad basta para un informe; recolectar datos de usuarios
reales excede el permiso de cualquier programa.
