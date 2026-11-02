---
clase: auth
tech: oauth2-response-mode
cwe: CWE-601
cvss: 8.1 # [derivado]
payload: |
  # Valores LITERALES de la fuente, agrupados por modo. Son los UNICOS que da:
  #
  # query:
  response_mode=query            # Apple
  response_type=code             # Google o Facebook
  #
  # fragment:
  response_mode=fragment         # Apple y Microsoft
  # (o un response_type que contenga id_token o token: Google, Facebook, Atlassian)
  #
  # web-message:
  response_mode=web_message      # Apple
  redirect_uri=storagerelay://...                                              # Google
  redirect_uri=https://staticxx.facebook.com/.../connect/xd_arbiter/...        # Facebook
  # El proveedor responde con un postMessage, LITERAL de la fuente:
  postMessage('{"access_token":"xxx"}','https://example.com')
  #
  # form-post:
  response_mode=form_post        # Apple
  ux_mode=redirect&login_uri=https://example.com/callback   # Google Sign-In
  #
  # Los '...' son marcadores de la propia fuente, no elisiones mias.
precondicion: "El proveedor soporta modos de respuesta que el sitio no implementa. Cada modo entrega el token por un canal distinto (query, fragmento, postMessage, POST de formulario) y el sitio solo sabe consumir uno. Los otros dejan el token sin consumir."
como_se_descubre: |
  Enumerar que modos acepta el proveedor para ese client_id y comparar con el que el
  sitio usa. Cada modo no implementado es un 'non-happy path' candidato.
  El modo mas interesante es web_message: en lugar de dejar el token en la URL, el
  proveedor lo ENVIA por postMessage. Si existe un receptor con comprobacion de origen
  debil, el token llega directamente a quien escuche, sin necesidad de leer la URL.
  La fuente añade una nota critica sobre web_message: no puede validar la RUTA, solo
  el origen. Por eso cualquier pagina del origen valido sirve como punto de entrega.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: response_mode=web_message  -> el token llega por postMessage
  # B: response_mode=query (el del sitio) -> el token llega en la URL y el sitio lo consume
  # Para A, verificar en la consola si existe un listener que lo reciba. Si no hay
  # listener, el token se emite y se pierde: condicion creada pero no cobrable.
  # El par distingue 'el proveedor acepta el modo' de 'el modo es explotable'.
mata: |
  - El proveedor permite restringir los modos por cliente -> muere.
  - El sitio consume el token en todos los modos que el proveedor acepta.
  - No hay receptor de postMessage con origen debil (para web_message).
  - redirect_uri estrictamente validado, incluida la ruta.
fuente: "https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/ (Frans Rosen, Detectify, 2022-07-06). Valores literales de la pagina. Proveedores nombrados: Apple, Google, Facebook, Microsoft, Atlassian, GitHub (este ultimo con un solo response type)."
confianza: alta
fecha: 2026-11-02
---
# [AUTH] Conmutación de `response_mode` — cuatro canales de entrega, un solo consumidor

## Principio
`response_mode` decide **por qué canal** llega el token: en la query, en el fragmento,
por `postMessage` o en un POST de formulario. Un sitio implementa uno. El proveedor
acepta varios. Cada modo que el sitio no implementa es un canal por el que el token
llega y nadie lo recoge.

## Payload
Los valores literales que da la fuente, por modo:

**query**
```
response_mode=query            # Apple
response_type=code             # Google o Facebook
```

**fragment**
```
response_mode=fragment         # Apple y Microsoft
```

**web-message**
```
response_mode=web_message      # Apple
redirect_uri=storagerelay://...                                        # Google
redirect_uri=https://staticxx.facebook.com/.../connect/xd_arbiter/...  # Facebook
```

Con este modo el proveedor no deja el token en la URL: lo **envía**.

```javascript
postMessage('{"access_token":"xxx"}','https://example.com')
```

**form-post**
```
response_mode=form_post        # Apple
ux_mode=redirect&login_uri=https://example.com/callback   # Google Sign-In
```

Los `...` son marcadores de la propia fuente.

## El modo que cambia la naturaleza del ataque
`web_message` merece atención aparte. Los otros modos dejan el token *en reposo* en la
URL, y hace falta un gadget que lo lea. `web_message` lo pone *en tránsito*: el
proveedor lo manda por `postMessage`, y cualquier receptor con comprobación de origen
débil lo recibe sin tener que leer nada.

Y aquí está el detalle que la fuente señala y que decide el alcance: `web_message`
**no puede validar la ruta**, solo el origen. Así que cualquier página del origen
autorizado sirve como punto de entrega — incluidas las páginas de error, que es
precisamente donde el baile roto termina.

## Impacto
Igual que la conmutación de `response_type`: crea la condición. Con `web_message`, la
distancia hasta el token es menor porque no hace falta un gadget que lea `location.href`,
solo un receptor permisivo.

## Remediación
De la fuente: *"having the ability to enable only the response-types and modes you
actually support from an OAuth-provider is one solution."* Y la regla del IETF sobre no
cargar recursos de terceros en ninguna página del flujo, **incluidas las de error**.

`# [derivado]`: todo receptor de `postMessage` debe comprobar `event.origin` contra una
constante, nunca con `indexOf` ni con expresiones laxas — y dado que `web_message` no
valida rutas, el origen debe tratarse como un ámbito completo, no como una página.
