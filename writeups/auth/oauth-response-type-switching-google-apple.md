---
clase: auth
tech: oauth2-oidc
cwe: CWE-601
cvss: 8.1 # [derivado] la fuente no da CVSS ni recompensas; estimado por secuestro de cuenta con un clic
payload: |
  # GOOGLE - flujo normal (code en la QUERY), URL LITERAL de la fuente:
  https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?client_id=client-id.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid%20email%20profile&response_type=code&access_type=offline&state=yyy&prompt=consent&flowName=GeneralOAuthFlow
  # -> https://example.com/callback?code=xxx&state=yyy
  #
  # GOOGLE - response_type conmutado a 'code,id_token': todo pasa al FRAGMENTO:
  https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?client_id=client-id.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid%20email%20profile&response_type=code,id_token&access_type=offline&state=yyy&prompt=consent&flowName=GeneralOAuthFlow
  # -> https://example.com/callback#code=xxx&state=yyy&id_token=zzz
  #
  # APPLE - flujo normal:
  https://appleid.apple.com/auth/authorize?response_type=code&response_mode=query&scope=&state=zzz&client_id=client-id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback
  # -> https://example.com/callback?code=xxx&state=yyy
  #
  # APPLE - 'code+id_token' con response_mode=fragment:
  https://appleid.apple.com/auth/authorize?response_type=code+id_token&response_mode=fragment&scope=&state=zzz&client_id=client-id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback
  # -> https://example.com/callback#code=xxx&state=yyy&id_token=zzz
  #
  # NOTA: 'response_type=code%20token' NO aparece en la fuente. No lo uso.
precondicion: "El proveedor acepta response_types que el SITIO no usa. Observacion literal de la fuente: no ha visto un proveedor que permita a un cliente restringir esto. Segun la especificacion que la fuente cita, un response_type multivalor que incluya un valor de fragmento debe devolver TODO en el fragmento. El sitio, al no esperar nada en el fragmento, no consume el token: queda en la URL."
como_se_descubre: |
  Inventario del baile OAuth: capturar el flujo de inicio de sesion legitimo y anotar
  response_type, response_mode y redirect_uri. Despues conmutar response_type a una
  forma multivalor e inspeccionar DONDE acaban los parametros. La señal buscada es
  que el code o el id_token aparezcan en el FRAGMENTO de una pagina que no los espera.
  El fragmento es la clave: no se envia al servidor, se queda en el navegador, asi que
  el sitio no lo consume y el valor persiste en location.href esperando a que algo lo lea.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: response_type=code,id_token  -> parametros en el FRAGMENTO, el sitio no los consume,
  #    permanecen en location.href (verificar en la consola del navegador)
  # B: response_type=code           -> parametros en la QUERY, el sitio los consume y
  #    normalmente redirige, limpiando la URL
  # El par confirma el 'non-happy path': lo relevante no es que el proveedor emita el
  # token, sino que el sitio NO lo consuma y quede accesible desde JS.
mata: |
  - El proveedor permite al cliente restringir response_types y modes -> muere
    (es la solucion que la propia fuente propone).
  - El sitio consume y limpia el fragmento al cargar.
  - No hay gadget de fuga en la pagina de destino -> el token queda en la URL pero
    nada puede leerlo (ver los writeups oauth-gadget-*: sin gadget no hay exfiltracion).
  - redirect_uri estricto que impida llegar a una pagina con scripts de terceros.
fuente: "https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/ (Frans Rosen, Security Advisor en Detectify, 2022-07-06). URLs literales de la pagina. Proveedores nombrados: Google, Apple, Facebook, Microsoft, Atlassian, GitHub. La fuente no indica recompensas. Dedicatoria a Nir Goldshlager y Egor Homakov."
confianza: alta
fecha: 2026-11-02
---
# [AUTH] Conmutación de `response_type` en OAuth — dejar el código varado en el fragmento

## Principio
Rosén llama a esto *"breaking the OAuth dance"*: el objetivo no es que el proveedor
falle, sino que **el sitio no consuma** lo que el proveedor emite correctamente. Si el
`response_type` se conmuta a una forma multivalor, la especificación obliga a devolver
todo en el **fragmento**. Y el fragmento no se envía al servidor: se queda en el
navegador. Un sitio que espera el código en la query no lo recoge, así que el token
válido permanece en `location.href` — vivo, utilizable, y legible por cualquier
JavaScript de esa página.

## Payload
Flujo normal de Google, con el código en la query:

```
https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?client_id=client-id.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid%20email%20profile&response_type=code&access_type=offline&state=yyy&prompt=consent&flowName=GeneralOAuthFlow
```
→ `https://example.com/callback?code=xxx&state=yyy`

El mismo flujo con `response_type=code,id_token`:

```
https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?client_id=client-id.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid%20email%20profile&response_type=code,id_token&access_type=offline&state=yyy&prompt=consent&flowName=GeneralOAuthFlow
```
→ `https://example.com/callback#code=xxx&state=yyy&id_token=zzz`

Apple, con `response_mode` explícito:

```
https://appleid.apple.com/auth/authorize?response_type=code+id_token&response_mode=fragment&scope=&state=zzz&client_id=client-id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback
```
→ `https://example.com/callback#code=xxx&state=yyy&id_token=zzz`

Nota: `response_type=code%20token` circula mucho en material de terceros pero **no
aparece en esta fuente**, así que no lo incluyo.

## Impacto
Por sí solo, un token válido varado en una URL. El secuestro de cuenta con un clic
llega al combinar esto con un *gadget* que lea la URL — los writeups `oauth-gadget-*`
de esta carpeta. Esta separación en dos mitades es la estructura de la investigación y
conviene conservarla: la conmutación crea la condición, el gadget la cobra. Sin gadget
no hay exfiltración, y es un error de triaje reportar la mitad como si fuera el todo.

## Remediación
La fuente cita el borrador del IETF *OAuth 2.0 Security Best Current Practice*:
*"The page rendered as a result of the OAuth authorization response and the
authorization endpoint SHOULD NOT include third-party resources or links to external
sites."* Y el autor añade, en negrita en el original: *"This is 100% accurate. This also
includes the error-pages that might show up if the endpoint fails to complete the
sign-in process successfully."*

Del lado del proveedor: *"having the ability to enable only the response-types and modes
you actually support from an OAuth-provider is one solution."* Es la corrección de
raíz — mientras el cliente no pueda restringir los modos, el atacante elige el baile.

## Sobre PKCE
No ayuda aquí. El autor responde a la pregunta con un *"Not really"*: el atacante
prepara el enlace de autorización con su **propio** `code_challenge`, así que un código
filtrado desde una página de error sigue siendo canjeable por él.
