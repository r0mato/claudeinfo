# ELITE-REJECTED — Candidatos rechazados y fallos de acceso
**Fecha:** 2026-11-02

Este fichero es tan importante como los writeups: registra lo que NO entró y por qué,
para no repetir el trabajo. Es la aplicación del principio 15 de `docs/ELITE-MINDSET.md`
(los escenarios que fallaron son inventario, no tiempo perdido).

---

## A — Rechazados por falta de payload literal (criterio 1 del contrato)

| Candidato | Fuente | Motivo |
|---|---|---|
| **Toda la clase SSTI** | OWASP SSTI Prevention Cheat Sheet | La página contiene **cero** payloads. No tiene `{{7*7}}`, `${7*7}`, `<%= %>` ni ninguna sonda aritmética. Lo único con sintaxis de plantilla es `"Hello {{" + name + "}}"`, que ilustra el patrón vulnerable, no un ataque. Para SSTI hace falta otra fuente. |
| Confianza excesiva en controles de cliente | PortSwigger logic-flaws/examples | Sin payload literal. Solo nombra Burp Proxy como herramienta. |
| Suposiciones sobre el comportamiento del usuario (3 subsecciones) | PortSwigger logic-flaws/examples | Sin payloads. La metodología de "borrar parámetros" no nombra ninguno. |
| Oráculo de cifrado | PortSwigger logic-flaws/examples | Sin algoritmo, sin parámetro, sin texto cifrado de ejemplo. |
| Discrepancias de parser de correo (esa página) | PortSwigger logic-flaws/examples | Sin direcciones de ejemplo. **Recuperado por otra vía**: la investigación dedicada (`splitting-the-email-atom`) sí tiene payloads, y de ahí salieron 5 writeups en `writeups/auth/`. |
| Partial construction (race) | Smashing the state machine | La precondición es literal (`null` en JSON, array vacío en PHP) pero no hay payload. Incorporado como paso conceptual en `skill:race-window`. |
| Fragmentos de session-handler (race) | Smashing the state machine | El código es literal pero es **pseudocódigo hipotético** del autor, sin objetivo real. Incorporado a la skill. |
| DNS rebinding / DNS pinning | OWASP SSRF | Descrito en prosa, sin payload. La cita defensiva sí se usó en `skill:ssrf-escalation`. |
| Bypass por cadena de redirección | OWASP SSRF | La página dice "Unsafe redirect" y **no da ninguna cadena**. |
| Codificaciones de IP (hex, octal, dword, mixta) | OWASP SSRF | Nombra las codificaciones solo al describir resultados de librerías. **No da una sola cadena de IP codificada.** Rechazado pese a ser material valioso: inventarlas habría sido fabricar el payload. |
| XS-Leak por atributo ID + fragmento + blur | OWASP XS-Leaks | Sin código de ataque: solo prosa y una imagen. |

## B — Rechazados por falta de objetivo real identificable (criterio 2)

| Candidato | Fuente | Motivo |
|---|---|---|
| CL.TE clásico (bloque 1) | HTTP/1.1 must die | Host redactado **y** vendor sin nombrar. Es el ejemplo didáctico del artículo. Incorporado como base conceptual de `skill:desync-triage`. |
| V-H → CL.0 (`<redacted-food-corp>`) | HTTP/1.1 must die | Host redactado y vendor sin nombrar: falla la regla H2 acordada con el usuario. |
| Fuga de memoria vía Expect (bloques 18-19) | HTTP/1.1 must die | Muestra fragmentos de memoria con token Bearer, pero el vendor no está nombrado. |
| Deadlock HEAD + Expect (bloque 17) | HTTP/1.1 must die | `api.<redacted>`, vendor sin nombrar. Usado como señal de detección en la skill. |
| EXNESS ($7.500) | HTTP/1.1 must die | Recompensa citada pero **ningún bloque de payload asociado**. |
| Cesta multi-endpoint | Smashing the state machine | "an online shop", sin nombre. Sin código de petición. |
| Colisión diferida (20 minutos) | Smashing the state machine | "a major website that really doesn't want me to name them". Incorporado a la skill por su valor metodológico. |
| IDOR genérico (`customer_number=132355`, `/static/12144.txt`) | PortSwigger access-control/idor | URLs literales pero sobre `insecure-website.com` y **sin vendor, CVE ni ID de reporte**. Material docente. Decisión declarada al usuario: solo se aceptan los que están atados a un producto, cabecera o versión concreta (de ahí los 4 que sí entraron: `X-Original-URL`, Spring <5.3, JS de cliente, `Referer`). |

## C — Payloads presentes solo en imágenes (no reconstruidos)

De `splitting-the-email-atom` (Gareth Heyes), los vectores **finales y funcionales** contra
GitHub, Zendesk, GitLab Enterprise, GitLab web y Joomla aparecen únicamente en capturas
de pantalla. El texto da la sonda, el par entrada/salida de Zendesk y fragmentos de
codificación por objetivo, y eso es lo que se reprodujo.

**No se reconstruyeron.** Una dirección de correo de este tipo depende de cada carácter
(comillas, barras invertidas, `=00`, charset), y una reconstrucción a ojo sería un payload
inventado con apariencia de literal — el peor resultado posible para este catálogo. Los 5
writeups de esa familia llevan `confianza: media` por este motivo, declarado en cada uno.

También image-only en esa fuente: "How encoded-word works", las dos sondas de
encoded-word, "Changing the charset", "Blending Q-Encoded and UTF-7", "Base64
encoded-word", el fuzzer de Punycode y las capturas de Turbo Intruder.

## D — Ausencias de la fuente (no se inventó nada para rellenar)

| Hueco | Fuente | Qué se hizo |
|---|---|---|
| **SQLite** | PortSwigger SQLi cheat sheet | No aparece en toda la página. Marcado como ausente en cada writeup de SQLi en lugar de añadir payloads de memoria. |
| Extracción por error en **Oracle** | PortSwigger SQLi cheat sheet | Ausente de esa sección. Declarado explícitamente en el writeup. |
| Rutas y cabeceras de IMDS | OWASP SSRF | La página da hosts e IPs y **nada más**: ni rutas, ni token de IMDSv2, ni `Metadata-Flavor`, ni DigitalOcean/Oracle/Alibaba. Declarado en el writeup; remite a documentación del proveedor. |
| URLs de ejemplo de esquemas no HTTP | OWASP SSRF | Solo da los nombres de esquema. El writeup lo declara y aporta los usos por esquema **marcados como análisis propio**. |
| Valor de ejemplo de `jku` | PortSwigger JWT | Ausente. Se reprodujo la estructura del JWK Set, que sí está. |
| Valor de ejemplo de `Referer` | PortSwigger access-control | Ausente. La petición del writeup está marcada como reconstrucción. |
| Valor de `X-Rewrite-URL` | PortSwigger access-control | Ausente. Marcado como simetría derivada. |
| `COEP` | OWASP XS-Leaks | **No se menciona en ninguna parte** de la página. No se incluyó como defensa documentada. |
| `THRESHOLD` del sondeo de caché | OWASP XS-Leaks | La propia fuente lo deja sin asignar. Se reprodujo con el defecto incluido y se convirtió en procedimiento de calibración, en lugar de inventar un umbral. |

## E — Excluido por criterio de seguridad (no por calidad)

**Afirmación jurídica sobre Bélgica** (entrevista a Inti De Ceukelaire): sostiene que se
puede atacar cualquier sitio en territorio belga sin permiso siempre que se actúe
éticamente. **Excluida de `docs/ELITE-MINDSET.md`** por tres razones: es una afirmación
legal de una jurisdicción concreta y no un principio de metodología; no se verificó contra
la ley belga en esta sesión; y en un documento de principios podría llevar a alguien a
actuar sin autorización. La regla operativa de este repo es la contraria, y es la que
siguen las propias fuentes técnicas citadas.

## F — Fallos de acceso (no de calidad)

| Recurso | Resultado |
|---|---|
| `splitting-the-email-atom.pdf` (PortSwigger) | Devolvió binario comprimido sin texto legible. No se pudo usar para verificar el número exacto de barras invertidas de los payloads. Es la causa directa de los caveats de fidelidad de esa familia. |
| Sección "requires user interaction" del XSS cheat sheet | Quedó fuera de la ventana de texto verbatim del fetch (el resto volvió como resumen generado). **No se usó**: los 3 payloads que aparecían en el resumen no están verificados y se descartaron. |
| Critical Thinking Podcast / HackerNotes | Fuente Tier 1 prevista en el plan. **No usada**: el contenido es audio y las búsquedas solo devolvieron descripciones de episodios, no transcripciones. Sin Chrome MCP en esta sesión (hallazgo H3) no había vía alternativa. Sustituida por la entrevista a Inti De Ceukelaire, que sí tiene transcripción. |
| NahamSec blog | Prevista en el plan, **no alcanzada** por presupuesto de fetches. El material de XSS quedó cubierto por PortSwigger. |

## G — Nota sobre marcadores de plantilla heredados

Cuatro writeups de `writeups/inyeccion/` contienen `YOUR-CONDITION-HERE`,
`TABLE-NAME-HERE` y `QUERY-1-HERE`. **No son placeholders muertos**: son marcadores de la
propia fuente (PortSwigger) en plantillas de técnica que se instancian con un valor
obtenido en el paso anterior. No coinciden con el grep del contrato
(`YOUR-LAB-ID|<target>|REDACTED`), y en cada writeup se acompañan de una **instanciación
concreta** para que sean ejecutables tal cual. Decisión declarada, no omisión.
