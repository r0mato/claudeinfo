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

---
# FASE 5 — rechazados y fallos de acceso adicionales

## H — Fallos de acceso (Fase 5)

| Recurso | Resultado |
|---|---|
| `portswigger.net/research/sso-wars-the-token-menace` | **HTTP 404**. Fallo permanente. |
| `portswigger.net/web-security/saml` (fallback) | **HTTP 404** también. Consecuencia: **la clase SAML/SSO quedó sin cubrir**. No se rellenó de memoria: ni XSW, ni exclusión de firma, ni la truncación por comentario XML en el `NameID`, ni confusión de audiencia. Hace falta otra fuente. |

## I — Ausencias de la fuente (Fase 5)

| Hueco | Fuente | Qué se hizo |
|---|---|---|
| Payloads serializados de **Java, Ruby y Python** | PortSwigger deserialization | Solo hay dos cadenas PHP literales y la firma `ac ed` / `rO0`. La forma `ac ed 00 05`, `__toString`, ysoserial.net y gadgetinspector **no están**. No se inventó ninguna. |
| **Cadena de gadgets** completa | PortSwigger deserialization | No hay ningún payload de cadena. Solo el comando de ysoserial con placeholders `[payload]` y `'[command]'`, que son texto de la propia página. |
| Payload **PHAR** | PortSwigger deserialization | Se describe el wrapper `phar://`, sin payload. |
| Payload de **subida SVG/DOCX** para XXE | PortSwigger XXE | La página los nombra como superficie de ataque y no da payload. |
| `?constructor.prototype.foo=bar` y `{"constructor": ...}` | Prototype pollution (4 páginas) | **No aparecen en ninguna.** La fuente da la ruta del constructor solo como expresiones JS. Circulan como payloads de esta clase; no son de PortSwigger. |
| **jQuery, Lodash, Vue, Chart.js, Wistia** como gadgets | Prototype pollution | No aparecen en ninguna de las cuatro páginas. `ppmap` tampoco. |
| `Host: localhost`, `X-Forwarded-Host`, "Host override via line wrapping" | Cracking the lens | **Ninguno está en el paper.** Los tres circulan atribuidos a este trabajo. Se declara en el writeup. |
| `Fastly-SSL`, `X-Forwarded-Port` | Ambos papers de caché | No aparecen en ninguno de los dos. |
| `<%= 7*7 %>` y `#{7*7}` | SSTI (paper + Academy) | No están. Solo `<%=foobar%>` (ERB) y `#{prop}` (Jade). |
| Sondas SSTI de **Velocity, Mako, Handlebars, Django, Tornado, Flask, Pug** | SSTI | Sin sonda documentada. No se inventaron. |
| Extracción por error en **Oracle** (SQLi) | SQLi cheat sheet | Ausente de esa sección, ya registrado en Fase 1. |

## J — Corrección de una premisa mía

En el brief de *Cracking the lens* afirmé que el paper documentaba "pagos muy grandes".
**Era falso y el agente lo corrigió**: el máximo es **$15.000** y el total declarado
*"a healthy $33,000"*, repartido en cuatro hallazgos de Yahoo. Y el paper **no contiene
ningún CVE**. Se registra porque una premisa errónea en un brief es una forma de
contaminar la extracción, y aquí no lo hizo solo porque el agente verificó.

## K — Contenido solo en imágenes (Fase 5, no reconstruido)

- **SSTI:** los dos diagramas de metodología y, crucialmente, **el árbol de decisión por
  motor** de la Academy — que es justo donde viven las ramas de identificación por motor.
- **Cache poisoning:** los diagramas de metodología de ambos papers, la salida de
  `/cdn-cgi/trace`, y la petición que fija la sobrescritura de query en el caso de Drupal.
- **Pause-based desync:** todos los diagramas de secuencia (Varnish, Apache, ALB).
- **Timing attacks:** la ecuación señal/ruido (`article-equation.png`), los diagramas de
  división temporal y de caché DNS, y la captura de Collaborator.
- **Prototype pollution:** las cuatro capturas de DOM Invader que muestran los sinks de
  Google Analytics, GTM y Adobe.

## L — Material disponible y NO escrito (pendiente, no rechazado)

Esto no son rechazos: es material extraído y verificado para el que no se escribió
writeup en esta pasada. Queda listo para continuar.

- **SSTI:** Velocity (cadena `$class.inspect("java.lang.Runtime")`), Smarty (escape de
  modo seguro con `getStreamVariable` y `writeFile`, corregido en 3.1.24), Mako, y los
  dos casos de estudio completos — Alfresco (backdoor FreeMarker + cadena de XSS
  almacenado con CSRF) y XWiki Enterprise (Velocity auto-modificante).
- **Caché:** Ghost/blog.cloudflare.com, HubSpot/goodhire.com, Pinterest, Taobao (método
  unkeyed), Adobe/WP Rocket, DoS por redirección en Cloudflare, normalización `%3f` en
  nginx/Mozilla, y `X-Original-URL` en Drupal/Symfony/Zend (**CVE-2018-14773**).
- **Desync:** Cisco Web VPN (**CVE-2022-20713**), Verisign (chunk fragmentado), Pulse
  Secure, AWS ALB.
- **Timing:** descubrimiento de parámetros por cuartil inferior, inyección JSON ciega
  (200 µs), contaminación de parámetros del lado servidor, y bypass de firewall por ruta
  alternativa.
- **Deserialización:** los dos objetos PHP serializados literales con sus métodos
  mágicos, y la detección por firma `rO0` / `ac ed`.
