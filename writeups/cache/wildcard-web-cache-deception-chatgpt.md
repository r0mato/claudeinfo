---
clase: otra
tech: cloudflare-cdn
cwe: CWE-524
cvss: 9.1 # [derivado] recompensa $6,500; robo del token de autenticacion de la victima
payload: |
  # LA URL. LITERAL de la fuente, identica en los dos sitios donde aparece:
  https://chat.openai.com/share/%2F..%2Fapi/auth/session?cachebuster=123
  #
  # Mecanica, cita LITERAL de la fuente:
  #   'Cloudflare's CDN did NOT decode and did NOT normalize a URL encoded path
  #    traversal, but the web server did.'
  #
  # El CDN ve una ruta bajo '/share/' y la cachea. El servidor de origen decodifica
  # '%2F' a '/', resuelve el '..' y sirve '/api/auth/session'.
  #
  # Regla de cache INFERIDA por el autor (no es configuracion real; la fuente dice que
  # 'looked something like this'):
  /share/*
  # Como la deduje, segun la fuente: 'https://chat.openai.com/share/random-path-that-
  # does-not-exist' tambien se cacheaba, luego la clave depende del PREFIJO de ruta y
  # no de la extension del fichero.
  #
  # NOTA: la fuente NO usa sufijo '.css' y su traversal es UNA sola secuencia
  # '%2F..%2F'. No añado ni uno ni otra.
  # La fuente NO explica el parametro 'cachebuster'.
  #
  # Endpoint cuya respuesta se cachea: /api/auth/session
  # Contenido, segun la fuente: 'a sensitive API endpoint which contains the user's
  # auth token'. La fuente NO muestra el cuerpo de la respuesta ni nombra la cookie.
  #
  # Cabecera de confirmacion de cache - LITERAL:
  Cf-Cache-Status: HIT
  # ADVERTENCIA: la fuente muestra esta cabecera sobre una URL de chat compartido
  # (/share/CHAT-UUID) durante el descubrimiento, NO sobre la URL del traversal. No da
  # cabeceras de respuesta para la URL del ataque.
precondicion: "Un CDN (Cloudflare) con una regla de cache por PREFIJO DE RUTA amplia, y un desacuerdo de normalizacion: el CDN no decodifica ni normaliza el traversal URL-codificado, y el servidor de origen si. Las dos condiciones son necesarias y vienen de capas distintas."
como_se_descubre: |
  La secuencia de descubrimiento es el valor del caso:
  1. Observar que una URL de chat compartido devuelve 'Cf-Cache-Status: HIT'.
  2. Probar una ruta INEXISTENTE bajo el mismo prefijo. Que tambien se cachee revela
     que la regla depende del prefijo de ruta, NO de la extension del fichero. Esa
     observacion es la que abre todo: una regla por prefijo es una regla cuyo alcance
     se puede abandonar con un traversal.
  3. Escapar del alcance con '%2F..%2F' hacia un endpoint sensible.
  El patron generalizable, que coincide con el writeup de 'img%2f' contra la CSP de un
  CDN sobre S3: todo control de seguridad aplicado por COINCIDENCIA DE PREFIJO DE RUTA
  sobre una capa que normaliza la ruta DISTINTO tiene un bypass de codificacion.
control_negativo: |
  # [derivado] diseño de test A/B — la fuente NO da ninguno
  # A: la URL del traversal con un cachebuster unico, SIN sesion
  #    -> si devuelve datos de sesion de alguien, la cache esta envenenada
  # B: la misma URL CON sesion propia -> devuelve el token propio y lo deja en cache
  # C: /api/auth/session directo -> devuelve el token propio y NO se cachea
  # El control C es el que demuestra que el problema es la RUTA y no el endpoint: el
  # endpoint sensible se comporta bien cuando se pide por su nombre real.
  # ADVERTENCIA ETICA: la secuencia B->A con la cuenta PROPIA del investigador
  # demuestra el fallo completo sin tocar la sesion de ningun tercero. Hacerlo al
  # reves —esperar a que caiga el token de un usuario real— es causar el impacto en
  # lugar de demostrarlo.
mata: |
  - El CDN normaliza y decodifica la ruta antes de aplicar la regla de cache.
  - La regla de cache se aplica por objeto o por extension verificada, no por prefijo.
  - El endpoint sensible responde con Cache-Control: no-store.
  - OpenAI lo haya corregido: la fuente NO da remediacion ni respuesta del proveedor
    para este fallo, solo para uno anterior de Nagli ('OpenAI notified users... and
    quickly patched the bug… Or did they?').
fuente: "https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html (Harel Security Research; el pie enlaza a nokline en GitHub y h4r3l en Twitter; sin linea de autoria. Fecha: 2024-02-04). Votada tecnica nº9 de 2024. URL y cita de Cloudflare literales. Recompensa LITERAL: 'my biggest bounty thus far of $6500'. SIN CVE. La fuente NO da remediacion ni respuesta del proveedor. El diagrama del ataque es una IMAGEN (ChatGPT_Attack.svg) y no se reconstruye."
confianza: media
fecha: 2026-11-02
---
# [CACHÉ] Wildcard web cache deception en ChatGPT — `%2F..%2F` escapa del alcance de la regla

## Principio
El CDN cachea todo lo que esté bajo un prefijo de ruta. El servidor de origen normaliza la
ruta antes de servir. Si el CDN **no** decodifica el traversal y el origen **sí**, los dos
discrepan sobre qué recurso es este.

Cita literal del desacuerdo:

> *"Cloudflare's CDN did NOT decode and did NOT normalize a URL encoded path traversal,
> but the web server did."*

## Payload
```
https://chat.openai.com/share/%2F..%2Fapi/auth/session?cachebuster=123
```

El CDN ve una ruta bajo `/share/` y la cachea. El origen decodifica `%2F` a `/`, resuelve
el `..` y sirve `/api/auth/session` — *"a sensitive API endpoint which contains the user's
auth token"*.

Nota de procedencia: la fuente **no** usa sufijo `.css` y su traversal es **una sola**
secuencia `%2F..%2F`. Las dos cosas circulan como parte de esta técnica; no añado ninguna.
Tampoco explica el parámetro `cachebuster`.

## El paso de descubrimiento que lo abre todo
La regla de caché que el autor **infiere** es `/share/*`, y la deduce de una observación
concreta: `https://chat.openai.com/share/random-path-that-does-not-exist` **también se
cacheaba**.

Eso revela que la clave depende del **prefijo de ruta** y no de la extensión del fichero —
y una regla por prefijo es una regla cuyo alcance se puede abandonar con un traversal. Toda
la vulnerabilidad cuelga de haber probado una ruta inexistente y mirado la cabecera de
caché.

Es el mismo patrón que `img%2f` contra la CSP de un CDN sobre S3
(`writeups/auth/oauth-gadget-cdn-csp-bypass-s3-svg.md`), y la regla general vale la pena
retenerla: **todo control de seguridad aplicado por coincidencia de prefijo de ruta sobre
una capa que normaliza la ruta distinto tiene un bypass de codificación.**

## Advertencia sobre la cabecera de confirmación
La fuente muestra `Cf-Cache-Status: HIT`, pero **sobre una URL de chat compartido durante
el descubrimiento, no sobre la URL del traversal**. No publica cabeceras de respuesta para
la URL del ataque, ni el cuerpo de la respuesta, ni el nombre de la cookie. De ahí
`confianza: media`.

## Nota ética sobre la verificación
La fuente no da control negativo. El orden correcto es demostrar el fallo **con la cuenta
propia del investigador**: pedir la URL autenticado, comprobar que el token propio queda en
caché, y recuperarlo sin sesión. Eso prueba la cadena completa sin tocar la sesión de
ningún tercero.

Hacerlo al revés —dejar la URL envenenada y esperar a que caiga el token de un usuario
real— es causar el impacto en lugar de demostrarlo, y excede el permiso de cualquier
programa.

## Impacto
El token de autenticación de la víctima queda en una caché compartida, recuperable por
cualquiera que pida la misma URL. Con él, según la fuente, el atacante puede *"view chats,
billing information, and more"*. Su propia valoración: *"This is game over."*

Recompensa: **$6.500**, la mayor del autor hasta entonces. Sin CVE.

## Remediación
La fuente **no da remediación ni respuesta del proveedor** para este fallo. Lo único que
menciona es el parche de un fallo anterior de Nagli, con un comentario escéptico:
*"OpenAI notified users of ChatGPT of this vulnerability, and quickly patched the bug… Or
did they?"*

`# [derivado]`: el CDN debe **normalizar y decodificar la ruta antes** de evaluar la regla
de caché, y el endpoint sensible debe responder con `Cache-Control: no-store`. Las dos
capas, porque cada una cierra el fallo por su lado y ninguna depende de la otra.
