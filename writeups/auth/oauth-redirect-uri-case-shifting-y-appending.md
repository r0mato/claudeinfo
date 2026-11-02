---
clase: auth
tech: oauth2-redirect-uri
cwe: CWE-601
cvss: 8.1 # [derivado]
payload: |
  # A3 - CASE SHIFTING. URL LITERAL de la fuente:
  https://oauthprovider.example.com/oauth2/v2.0/authorize?response_type=id_token&client_id=client-id&redirect_uri=https://example.com/CaLlBaCk&scope=openid%20profile%20email&nonce=1&state=yyy
  # -> https://example.com/CaLlBaCk#id_token=xxx
  # El proveedor compara la ruta SIN distinguir mayusculas; las rutas del sitio SI
  # distinguen. El flujo se rompe con el fragmento aun en la URL.
  # La fuente advierte: es mas dificil con 'code', porque el intercambio del token
  # vuelve a comprobar el redirect_uri.
  #
  # A4 - PATH APPENDING. LITERAL de la fuente:
  response_type=id_token&
  redirect_uri=https://example.com/callbackxxx
  # -> https://example.com/callbackxxx#id_token
  #
  # A5 - PARAMETER APPENDING. LITERALES de la fuente:
  response_type=code&redirect_uri=https://example.com/callback%3fcode=xxx%26
  # -> https://example.com/callback?code=xxx&code=real-code
  response_type=code&redirect_uri=https://example.com/callback%23id_token=xxx%26
  # -> https://example.com/callback#id_token=xxx&id_token=real-id_token
  #
  # A6 - LEFTOVERS. De 125 flujos de Google analizados, 5 sitios aceptaban tambien su
  # pagina de inicio como redirect_uri. Valores LITERALES aceptados:
  https://example.com/
  https://example.com
  https://www.example.com/
  https://www.example.com
  # (base registrada en el ejemplo: redirect_uri=https://auth.example.com/callback)
precondicion: "Varia por variante. A3: el proveedor compara la ruta sin distinguir mayusculas y el sitio si. A4: el proveedor acepta caracteres de ruta extra tras el redirect_uri registrado (el autor lo reporto a los proveedores). A5: el proveedor añade sus parametros DESPUES de los del atacante y el sitio trata los nombres duplicados de forma inconsistente. A6: la pagina de inicio esta registrada como redirect valido; importa sobre todo con id_token o token."
como_se_descubre: |
  Para A3/A4: probar variaciones de la ruta del redirect_uri registrado (cambiar
  mayusculas, añadir sufijos) y observar si el proveedor las acepta. Si acepta y el
  sitio devuelve 404 o error, se ha logrado el objetivo: el token queda en una pagina
  que no lo consume.
  Para A5: la pregunta es que hace el sitio con parametros DUPLICADOS. ¿Lee el primero
  o el ultimo? Si lee el primero, el atacante lo controla.
  Para A6: enumerar que redirect_uris acepta el proveedor para ese client_id. El dato
  de la fuente (5 de 125, un 4%) indica que merece comprobarse siempre.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: redirect_uri=https://example.com/CaLlBaCk  -> aceptado por el proveedor,
  #    error en el sitio, token en el fragmento SIN consumir
  # B: redirect_uri=https://example.com/callback  -> flujo normal, token consumido
  # El par confirma la discrepancia de sensibilidad a mayusculas entre las DOS capas.
  # Para A5, control adicional: enviar ?code=A&code=B a la ruta de callback y
  # observar cual gana. Es el experimento que decide si la variante es explotable y
  # se puede hacer SIN tocar el flujo OAuth.
mata: |
  - El proveedor compara el redirect_uri por igualdad EXACTA de cadena -> mueren A3 y A4.
  - El sitio lee el ULTIMO parametro duplicado -> muere A5 (el real gana).
  - Solo esta registrada la ruta de callback, no la pagina de inicio -> muere A6.
  - Con response_type=code, el intercambio del token revalida redirect_uri
    -> A3 se complica (advertencia explicita de la fuente).
  - Sin gadget de fuga en la pagina de destino, no hay exfiltracion.
fuente: "https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/ (Frans Rosen, Detectify, 2022-07-06). Payloads y la estadistica 5-de-125 son literales de la pagina. Sin CVEs ni recompensas indicados."
confianza: alta
fecha: 2026-11-02
---
# [AUTH] Cuatro formas de romper `redirect_uri` sin salir del dominio registrado

## Principio
La validación de `redirect_uri` suele pensarse como "¿apunta a mi dominio?". Pero entre
el proveedor y el sitio hay **dos** comparadores distintos de la misma cadena, y basta
que discrepen en un detalle —mayúsculas, un sufijo, el orden de los parámetros
duplicados— para que el proveedor acepte una URL que el sitio no sabe atender. El
atacante no necesita redirigir a otro dominio: le basta una ruta del dominio legítimo
que no consuma el token.

## Payload
**Case shifting.** El proveedor compara la ruta sin distinguir mayúsculas; el
enrutador del sitio sí distingue:

```
https://oauthprovider.example.com/oauth2/v2.0/authorize?response_type=id_token&client_id=client-id&redirect_uri=https://example.com/CaLlBaCk&scope=openid%20profile%20email&nonce=1&state=yyy
```
→ `https://example.com/CaLlBaCk#id_token=xxx`

La fuente advierte que esto es más difícil con `code`, porque el intercambio del token
revalida el `redirect_uri`.

**Path appending.** El proveedor tolera caracteres extra tras la ruta registrada:

```
response_type=id_token&redirect_uri=https://example.com/callbackxxx
```
→ `https://example.com/callbackxxx#id_token`

**Parameter appending.** El atacante inyecta su propio parámetro y el proveedor añade
el real **detrás**:

```
response_type=code&redirect_uri=https://example.com/callback%3fcode=xxx%26
```
→ `https://example.com/callback?code=xxx&code=real-code`

```
response_type=code&redirect_uri=https://example.com/callback%23id_token=xxx%26
```
→ `https://example.com/callback#id_token=xxx&id_token=real-id_token`

**Leftovers.** De 125 flujos de Google que el autor analizó, **5 sitios** aceptaban
también su página de inicio como `redirect_uri`:

```
https://example.com/
https://example.com
https://www.example.com/
https://www.example.com
```

## El control negativo más rentable
Para la variante de parámetros duplicados hay un experimento que **no requiere tocar el
flujo OAuth**: enviar `?code=A&code=B` a la ruta de callback y mirar cuál gana. Si el
sitio lee el primero, el atacante lo controla y la variante es explotable; si lee el
último, el código real gana y la variante muere. Una petición resuelve la pregunta antes
de invertir en montar el flujo completo.

## Impacto
Las cuatro variantes producen lo mismo: un token válido en una página del dominio
legítimo que no lo consume. El 4% de la muestra de la fuente en el caso de los
*leftovers* sugiere que no es una rareza y que conviene enumerar siempre qué
`redirect_uri` acepta el proveedor.

## Remediación
Comparar `redirect_uri` por **igualdad exacta de cadena**, incluidas mayúsculas, ruta y
ausencia de sufijos, y registrar solo las rutas que realmente atienden la respuesta —
nunca la página de inicio. `# [derivado]`: en el lado del sitio, tratar un parámetro
duplicado como error y no elegir silenciosamente uno de los dos. Y la regla de la fuente
sobre que ninguna página del flujo, **incluidas las de error**, cargue recursos de
terceros.
