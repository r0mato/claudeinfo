---
name: oauth-flow-audit
description: Auditoria de flujos de inicio de sesion OAuth/OIDC buscando rutas no felices que dejan el token sin consumir en la URL, y gadgets de terceros que lo leen.
model: claude-opus-5
---

# 0 — SEÑAL CITADA

> "Account hijacking using 'dirty dancing' in sign-in OAuth-flows" — Frans Rosén,
> Detectify, 2022-07-06.

La cita que define la defensa, del borrador del IETF *OAuth 2.0 Security Best Current
Practice*:

> "The page rendered as a result of the OAuth authorization response and the
> authorization endpoint SHOULD NOT include third-party resources or links to external
> sites."

Y la extension del autor, en negrita en el original:

> "This also includes the error-pages that might show up if the endpoint fails to
> complete the sign-in process successfully."

**La idea central:** el ataque no busca que el proveedor falle. Busca que **el sitio no
consuma** lo que el proveedor emite correctamente. El ataque tiene dos mitades
independientes y hacen falta las dos:

1. **Romper el baile** -> el token queda varado en `location.href`
2. **Un gadget** que lea esa URL -> el token sale

Sin gadget no hay exfiltracion. Reportar la mitad como si fuera el todo es un error de
triaje.

Sobre PKCE, el autor responde: **"Not really"**. El atacante prepara el enlace con su
propio `code_challenge`, asi que un codigo filtrado desde una pagina de error sigue
siendo canjeable.

---

# 1 — Arbol de decision (coste creciente)

## Paso 1 — Inventariar el baile (coste: 1 flujo completo)
Capturar el inicio de sesion legitimo y anotar: `client_id`, `redirect_uri`,
`response_type`, `response_mode`, `scope`, `state`.

Cita literal de la fuente sobre el alcance del inventario:
> "Know what kind of pages that are involved in the OAuth-dance. This includes
> exception- or error pages that could be triggered to show up in the flow if any
> parameters expected in the dance are wrong or missing."

## Paso 2 — Conmutar `response_type` (coste: 2 flujos)
Pasar a una forma multivalor para empujar todo al fragmento:
```
response_type=code,id_token     # Google
response_type=code+id_token     # Apple (con response_mode=fragment)
```
El fragmento no se envia al servidor, asi que el sitio no lo consume.

**Verificar en la consola** que el valor sigue en `location.href` tras cargar. Si el
sitio lo consume y limpia la URL, esta rama muere.

NOTA: `response_type=code%20token` circula en material de terceros pero **no aparece en
esta fuente**. No usarlo como si fuera suyo.

## Paso 3 — Conmutar `response_mode` (coste: 2-4 flujos)
```
response_mode=fragment | web_message | form_post | query
```
`web_message` es el de mayor valor: el proveedor **envia** el token por `postMessage`
en lugar de dejarlo en reposo. Detalle que decide el alcance: `web_message` **no puede
validar la ruta**, solo el origen, asi que cualquier pagina del origen sirve como punto
de entrega — incluidas las de error.

## Paso 4 — Atacar `redirect_uri` sin salir del dominio (coste: 4 flujos)
Cuatro variantes, todas dentro del dominio registrado:
```
.../CaLlBaCk                          # case shifting
.../callbackxxx                       # path appending
.../callback%3fcode=xxx%26            # parameter appending
https://example.com/   (pagina de inicio)   # leftovers
```
Dato de la fuente: de **125** flujos de Google analizados, **5** aceptaban tambien su
pagina de inicio como `redirect_uri`. Un 4%: merece comprobarse siempre.

Aviso de la fuente: el case shifting es mas dificil con `code`, porque el intercambio
del token revalida el `redirect_uri`.

**Control barato y aparte:** enviar `?code=A&code=B` a la ruta de callback y ver cual
gana. Si el sitio lee el **primero**, la variante de parametros duplicados es
explotable. Una peticion, sin montar el flujo.

## Paso 5 — Buscar el gadget (coste: alto, revision de JS)
Con el token varado, inventariar lo que puede leerlo en esa pagina:

- **listeners de `postMessage`** con comprobacion de origen debil (sin comprobacion,
  `indexOf`, o allowlist vacia)
- **`postMessage` emisor con `'*'`** como `targetOrigin`
- **XSS en un dominio sandbox** embebible, para robar `window.name`
- **iframes que solo validan `window.parent`**: el atacante controla ese padre
- **iframes de almacenamiento/analitica** que reenvian `location.href`
- **widgets** que publican su token de API al padre

## Paso 6 — Encadenar (coste: muy alto)
Solo con las dos mitades confirmadas.

---

# 2 — Trampas de falso positivo

**1. Media cadena reportada como completa.** Un token varado en la URL sin gadget que
lo lea no es secuestro de cuenta. Señal de muerte: no se identifica ningun lector de
`location.href` en esa pagina. Reportar entonces la conmutacion como fallo de
configuracion, con su severidad real.

**2. El sitio si consume el token.** Parece varado porque se ve en la URL un instante.
Señal de muerte: leer `location.href` en la consola **despues** de que la pagina
termine de cargar; si el valor ya no esta, el sitio lo consumio y limpio.

**3. Gadget de terceros que cambia sin aviso.** La fuente advierte que modificaciones
posteriores via Google Tag Manager o del propio proveedor del SDK pueden **introducir**
la fuga mas tarde. Consecuencia para el triaje: un flujo que hoy no es explotable puede
serlo mañana sin que cambie el codigo del sitio, asi que la ausencia de gadget hoy no
cierra el riesgo — es un argumento para aplicar la regla del IETF, no para archivar.

---

# 3 — Cuándo esta skill NO es la correcta

- El problema esta en la **validacion** del token emitido, no en el flujo que lo emite
  -> `skill:jwt-attack-tree`
- Hay XSS en el dominio principal independiente del flujo OAuth
  -> `skill:xss-sink-triage`
- El `redirect_uri` permite salir a un **dominio externo**: es un open redirect clasico
  y se reporta como tal, sin necesidad de este arbol.
- El gadget resulta ser una CSP que se cae por codificacion de ruta en un CDN: el
  hallazgo es de la plataforma -> ver `writeups/auth/oauth-gadget-cdn-csp-bypass-s3-svg.md`

---

# 4 — Output

Escribir en `evidencias/oauth-flow-audit-<slug>.md`:

- inventario del baile: todos los parametros del flujo legitimo
- lista de **todas** las paginas del flujo, incluidas las de error
- qué `response_type` y `response_mode` acepta el proveedor para ese `client_id`
- variantes de `redirect_uri` aceptadas, con la de la pagina de inicio comprobada
- resultado del control `?code=A&code=B`
- gadget identificado, con el fichero y la linea de JS, o constancia de que no hay
- las dos mitades, declaradas por separado, y la severidad que corresponde si solo
  existe una
- las tres trampas, con resultado
