---
clase: otra
tech: github-rack
cwe: CWE-444
cvss: 7.5 # [derivado] recompensa $10,000 segun la fuente
payload: |
  # ADVERTENCIA (H1): el render colapso los saltos de linea. Estructura reconstruida.
  #
  # PETICION LITERAL de la fuente. Un GET CON CUERPO ('fat GET'):
  GET /contact/report-abuse?report=albinowax HTTP/1.1
  Host: github.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 22

  report=innocent-victim
  #
  # Mecanica: la cache construye la clave con el METODO y la URL, asi que ve
  # 'GET /contact/report-abuse?report=albinowax'. La aplicacion, en cambio, da
  # prioridad al parametro del CUERPO. Resultado: la entrada de cache de
  # '?report=albinowax' contiene una pagina preparada para reportar a otra persona.
  #
  # Cita LITERAL de la fuente sobre la precondicion de infraestructura:
  #   'This is bad news for websites that use Varnish without the builtin.vcl snippet
  #    in conjunction with a framework that supports GET requests with bodies
  #    (hereafter referred to as "fat GET requests").'
  #
  # ---- VARIANTE ZENDESK (secuestro de login) ----
  # Peticion LITERAL de la fuente (sin lineas Content-Type/Content-Length en el texto):
  GET /en-us/signin HTTP/1.1
  Host: example.zendesk.com

  return_to=/access/logout?return_to=/./access/return_to?flash_digest=secret-token%2526return_to=/final-page?foo=foo%252526bar=bar
precondicion: "(1) La cache calcula la clave a partir del metodo y la URL, IGNORANDO el cuerpo. (2) El framework de aplicacion acepta cuerpos en peticiones GET y da prioridad a los parametros del cuerpo sobre los de la query. La fuente nombra Varnish sin el fragmento builtin.vcl, Rack::Cache y Ruby on Rails como la combinacion que lo permite."
como_se_descubre: |
  Señal en recon: objetivo detras de Varnish (cabecera 'Via: 1.1 varnish') o
  Rack::Cache, con una aplicacion Rails.
  Sonda: enviar un GET con un parametro en la query y el MISMO parametro con otro
  valor en el cuerpo, y observar cual gana en la respuesta. Si gana el del cuerpo, el
  framework acepta fat GET; si la respuesta se cachea bajo la clave de la query, el
  envenenamiento es posible.
  El concepto que generaliza: la cache y la aplicacion discrepan sobre QUE ES la
  peticion. Es la misma forma que el desync HTTP y la confusion de parsers de URL.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: GET ?report=X con cuerpo report=Y  -> la respuesta refleja Y (gana el cuerpo)
  # B: GET ?report=X sin cuerpo           -> la respuesta refleja X
  # C: GET ?report=X sin cuerpo, DESPUES de A
  #    -> si refleja Y, la entrada de cache quedo envenenada bajo la clave de A
  # El paso C es el hallazgo. A y B solos solo demuestran precedencia de parametros,
  # que es una curiosidad del framework; C demuestra impacto sobre terceros.
mata: |
  - La cache incluye el cuerpo en la clave (o rechaza GET con cuerpo) -> muere.
  - Varnish CON el fragmento builtin.vcl, que descarta el cuerpo de los GET.
  - El framework ignora los cuerpos en peticiones GET.
  - El paso C no reproduce el valor del cuerpo -> no hay envenenamiento, solo
    precedencia de parametros.
fuente: "https://portswigger.net/research/web-cache-entanglement (James Kettle, publicado 2020-08-05, act. 2025-09-03). Peticiones y la cita sobre Varnish literales. La fuente indica para GitHub: parcheado, recompensa de $10,000 (la mayor del paper). Para Zendesk: parcheado, sin recompensa indicada. Respuesta documentada de Cloudflare al mismo problema: 'Do not trust GET request bodies'. Sin CVE."
confianza: media
fecha: 2026-11-02
---
# [CACHÉ] Fat GET — un GET con cuerpo que la caché y la aplicación leen distinto (GitHub, $10.000)

## Principio
La caché construye su clave con el método y la URL. El cuerpo no entra. Pero algunos
frameworks aceptan cuerpos en peticiones `GET` y **dan prioridad a los parámetros del
cuerpo** sobre los de la query.

El resultado es que caché y aplicación discrepan sobre qué es la petición: la caché
archiva la respuesta bajo `?report=albinowax` mientras la aplicación generó una página
para `report=innocent-victim`. Es la misma forma que el desync HTTP y la confusión de
parsers de URL — dos componentes leyendo el mismo mensaje con reglas distintas.

## Payload
```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

La precondición de infraestructura, literal de la fuente:

> *"This is bad news for websites that use Varnish without the builtin.vcl snippet in
> conjunction with a framework that supports GET requests with bodies (hereafter referred
> to as 'fat GET requests')."*

La variante contra Zendesk secuestra el flujo de inicio de sesión:

```http
GET /en-us/signin HTTP/1.1
Host: example.zendesk.com

return_to=/access/logout?return_to=/./access/return_to?flash_digest=secret-token%2526return_to=/final-page?foo=foo%252526bar=bar
```

## El tercer paso es el hallazgo
Que el parámetro del cuerpo gane sobre el de la query es una **curiosidad del
framework**, no una vulnerabilidad. Lo que la convierte en una es pedir el recurso
después, sin cuerpo, y recibir la respuesta preparada por el atacante. Sin ese paso el
informe describe precedencia de parámetros; con él, describe envenenamiento de caché
contra todos los usuarios de la página.

Es la misma lección que en el caso de Mozilla, y conviene interiorizarla porque es la
que decide la severidad en toda esta clase.

## Impacto
En GitHub, la página de reportar abuso quedaba cacheada preparada para denunciar a un
tercero. Recompensa: **$10.000**, la mayor del paper. En Zendesk, secuestro del flujo de
login.

Nota de la fuente sobre la respuesta de Cloudflare al mismo problema: lo "parchearon" vía
documentación, con la frase *"Do not trust GET request bodies"* — que traslada el
problema al desarrollador en lugar de resolverlo en la capa que lo causa.

## Remediación
Cita literal de la fuente, que es inusualmente concreta:

> *"Firstly, avoid ever rewriting the cache key. Instead, rewrite the actual request -
> this achieves the same performance gains while massively reducing the likelihood of
> cache poisoning problems."*

> *"Second, ensure your application doesn't support fat GET requests."*

Y la de fondo, que es la tesis del paper:

> *"The only realistic way to achieve resilience against this attack is to acknowledge
> that web caching redefines what's exploitable, and treat 'unexploitable'
> vulnerabilities as genuine security issues."*
