# claudeinfo — biblioteca de referencia de seguridad ofensiva

Catálogo de técnicas de seguridad web documentadas **desde investigación publicada**, con
payload literal, precondición, control negativo y criterios de descarte. Material de
referencia defensiva y educativa: no contiene objetivos, credenciales ni infraestructura.

## Estructura

```
writeups/<clase>/<slug>.md    56 writeups, 9 clases, frontmatter de 12 campos
skills/<nombre>/SKILL.md       6 árboles de decisión de triaje (≤200 líneas)
docs/ELITE-MINDSET.md         20 principios de caza con fuente atribuible
docs/ELITE-SOURCES.md         inventario de las 15 fuentes consultadas
_refactor/ELITE-REPORT.md     informe de construcción y decisiones de criterio
_refactor/ELITE-REJECTED.md   40+ candidatos descartados, con el motivo
```

## Writeups por clase

| Clase | N | Destacado |
|---|---|---|
| `auth` | 17 | JWT (7), parsers de correo (5), OAuth (5) |
| `xss` | 9 | vectores sin interacción del usuario |
| `inyeccion` | 9 | SQLi por motor (6), argument injection (3) |
| `idor` | 4 | `X-Original-URL`, Spring <5.3, `Referer` |
| `info-disclosure` | 4 | XS-Leaks |
| `protocolo` | 4 | desync HTTP/1.1, CVE-2025-32094 |
| `race` | 4 | single-packet attack, CVE-2022-4037 |
| `ssrf` | 3 | confusión de parsers, metadata cloud |
| `logica-negocio` | 2 | importe negativo, descuento reversible |

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
- `confianza: alta` → payload verificado y objetivo nombrado (32 writeups).
- `confianza: media` → hay un caveat declarado en el propio writeup: estructura CRLF
  reconstruida, host redactado por política de divulgación, o payload parcial (24).
- Cuando una fuente **no** contiene un payload, el writeup lo dice y **no** se inventa.
  Ver `_refactor/ELITE-REJECTED.md` §D.

## Alcance y uso previsto

Investigación 100% pasiva: ninguna petición se envió a ningún sistema de terceros. El
contenido procede de PortSwigger Research, OWASP Cheat Sheet Series, Detectify Labs y
entrevistas publicadas, todas citadas en `docs/ELITE-SOURCES.md`.

Pensado para pruebas autorizadas: programas de bug bounty con alcance declarado,
compromisos de pentesting contratados, CTF y defensa. Las propias fuentes operan bajo esa
regla — PortSwigger declara en su investigación de desync: *"All case-studies were
identified through authorized testing on targets with vulnerability disclosure programs
(VDPs)."*

Un writeup incluye payload de exfiltración (`onbeforeunload-exfiltracion-sendbeacon.md`)
con su límite explícito: solo contra cuentas propias del investigador y un host bajo su
control. Demostrar la capacidad basta para un informe; recolectar datos de usuarios
reales excede el permiso de cualquier programa.
