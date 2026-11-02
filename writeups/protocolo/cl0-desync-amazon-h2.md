---
clase: protocolo
tech: amazon-h2
cwe: CWE-444
cvss: 9.3 # [derivado] captura de peticiones completas de usuarios reales, con tokens de autenticacion
payload: |
  # ADVERTENCIA (H1): el render colapso los saltos de linea. Reconstruida desde la
  # sintaxis HTTP. Notese 'X: XGET' sin espacio: ahi habia un salto de linea.
  #
  # PETICION LITERAL de la fuente. La fuente aclara que este caso es H2.0 y que
  # amazon.com 'ignored the CL on requests sent to /b/':
  POST /b/ HTTP/2
  Host: www.amazon.com
  Content-Length: 23

  GET /404 HTTP/1.1
  X: XGET / HTTP/1.1
  Host: www.amazon.com
  #
  # Respuestas observadas, LITERALES:
  #   HTTP/2 200 OK   Content-Type: text/html
  #   HTTP/2 200 OK   Content-Type: image/x-icon
  #
  # ---- VARIANTE CL.0 GENERICA (otro objetivo, redactado) ----
  # LITERAL de la fuente. 'xyzGET' sin espacio: ahi habia un salto de linea.
  POST / HTTP/1.1
  Host: redacted
  Content-Length: 3

  xyzGET / HTTP/1.1
  Host: redacted
  #   -> HTTP/1.1 200 OK   Location: /en
  #      HTTP/1.1 405 Method Not Allowed
  #
  # La fuente dice de la variante CL.0 que 'could even be triggered by a browser' y
  # que podria haberse lanzado 'using fetch()', pero NO da el codigo JS para ella.
  # No lo construyo.
precondicion: "El servidor ignora el Content-Length en determinados endpoints. En el caso de Amazon, concretamente en las peticiones a /b/. La fuente clasifica este caso como H2.0 (peticion HTTP/2 cuyo CL se ignora al degradar), no como CL.0 puro. Requiere reutilizacion de conexion para alcanzar a otros usuarios."
como_se_descubre: |
  Hallazgo de la fuente sobre como se encontro la clase: 'When I attempted to simplify
  the request, I discovered that the Transfer-Encoding header was actually completely
  ignored.' Es decir, el descubrimiento salio de SIMPLIFICAR un payload que ya
  funcionaba, no de añadir complejidad.
  Esa es una heuristica reutilizable: cuando un exploit funciona, quitarle piezas una a
  una revela cual era realmente necesaria — y a veces revela que el mecanismo es otro
  y mas simple que el supuesto.
  La fuente menciona ademas 'a crude scan check for CL.0/H2.0 desync vulnerabilities'.
control_negativo: |
  # [derivado] diseño de test A/B sobre la secuencia de deteccion de la fuente
  # A: POST /b/ con CL declarado y prefijo en el cuerpo
  #    -> la SEGUNDA respuesta corresponde al prefijo (404 / otro Content-Type)
  # B: el mismo POST con cuerpo VACIO
  #    -> la segunda respuesta es la normal
  # C: ALTERAR el prefijo del cuerpo y comprobar que la segunda respuesta SIGUE el cambio
  # El paso C es el unico concluyente. En este caso concreto la señal es muy visible:
  # dos respuestas 200 con Content-Type DISTINTO (text/html y image/x-icon), lo que es
  # mucho mas difícil de explicar por casualidad que dos codigos de estado iguales.
mata: |
  - El servidor respeta el Content-Length en todos los endpoints.
  - HTTP/2 extremo a extremo sin degradacion.
  - El paso C no sigue al cuerpo -> comportamiento fijo, no desync.
  - Amazon lo haya corregido (la fuente no indica el desenlace).
fuente: "https://portswigger.net/research/browser-powered-desync-attacks (James Kettle, 2022-08-10, act. 2025-09-03). Peticiones literales. Sobre Amazon la fuente indica que el PoC almacenaba peticiones completas de usuarios reales 'including authentication tokens' en una lista de la compra, que el autor podria haber construido un gusano de desync, y literalmente: 'I opted out of perhaps $30,000 due to Amazon's bug bounty program being incompatible with public research.' Sin CVE. El articulo no indica el desenlace del reporte."
confianza: media
fecha: 2026-11-02
---
# [PROTOCOLO] CL.0 / H2.0 en amazon.com — capturar peticiones completas de usuarios reales

## Principio
Si un servidor ignora el `Content-Length` en algún endpoint, el cuerpo de la petición
queda en la conexión y se interpreta como una petición nueva. No hace falta ninguna
ambigüedad entre `Content-Length` y `Transfer-Encoding`: basta que un endpoint no
esperase un `POST`.

## Payload
```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: XGET / HTTP/1.1
Host: www.amazon.com
```

Respuestas observadas:

```
HTTP/2 200 OK   Content-Type: text/html
HTTP/2 200 OK   Content-Type: image/x-icon
```

La variante CL.0 genérica sobre otro objetivo:

```http
POST / HTTP/1.1
Host: redacted
Content-Length: 3

xyzGET / HTTP/1.1
Host: redacted
```

Nota de lectura: `X: XGET` y `xyzGET` aparecen sin espacio porque ahí había un salto de
línea que el render colapsó. Es exactamente donde empieza la petición inyectada.

## La señal más limpia de toda la familia
Dos respuestas `200 OK` con **Content-Type distinto** —`text/html` e `image/x-icon`— es
una evidencia mucho más difícil de explicar por casualidad que dos códigos de estado
iguales. Cuando se busca una señal que convenza a un triador, esta clase de contraste
—mismo estado, tipo de contenido incompatible— vale más que un 404.

## Cómo se descubrió, y la heurística que deja
Cita literal: *"When I attempted to simplify the request, I discovered that the
Transfer-Encoding header was actually completely ignored."*

El hallazgo salió de **simplificar** un payload que ya funcionaba, no de añadirle
complejidad. Es una heurística reutilizable: cuando un exploit funciona, quitarle piezas
una a una revela cuál era realmente necesaria — y a veces revela que el mecanismo es
distinto y más simple del supuesto. Ahí nació la clase CL.0 entera.

## Impacto
La fuente describe que su PoC almacenaba peticiones completas de usuarios reales *"including
authentication tokens"* en una lista de la compra, y que podría haber construido un
**gusano de desync**. Es el techo de impacto de la clase: no se roba una sesión, se
cosechan todas las que pasen por la conexión.

## Nota sobre divulgación
El autor declara: *"I opted out of perhaps $30,000 due to Amazon's bug bounty program
being incompatible with public research."* Merece recogerse porque documenta un coste
real de la investigación pública: los términos de un programa pueden obligar a elegir
entre cobrar y publicar. El artículo no indica el desenlace del reporte.

## Remediación
De la fuente: HTTP/2 extremo a extremo. Y para implementadores de servidores HTTP:
*"Never assume a request won't have a body"* — que es, literalmente, la causa raíz de
este caso.
