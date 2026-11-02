---
clase: auth
tech: jwt-rs256
cwe: CWE-347
cvss: 9.1 # [derivado] suplantacion total usando una clave PUBLICA
payload: |
  # Pseudocodigo LITERAL de la fuente, que muestra la causa raiz:
  function verify(token, secretOrPublicKey){ algorithm = token.getAlgHeader(); if(algorithm == "RS256"){ // Use the provided key as an RSA public key } else if (algorithm == "HS256"){ // Use the provided key as an HMAC secret key } }
  #
  # Patron de llamada vulnerable, LITERAL de la fuente:
  publicKey = <public-key-of-server>; token = request.getCookie("session"); verify(token, publicKey);
  #
  # PASOS LITERALES del ataque (pagina de algorithm-confusion):
  # 1) Obtener la clave publica del servidor. Puede estar en un JWK Set en
  #    /jwks.json o /.well-known/jwks.json
  # 2) Convertirla a formato X.509 PEM.
  # 3) Modificar el JWT. Literal: 'Just make sure that the alg header is set to HS256.'
  # 4) Literal: 'Sign the token using the HS256 algorithm with the RSA public key
  #    as the secret.'
  #
  # Pasos en la extension Burp JWT Editor (literales de la fuente):
  #   - pestaña 'JWT Editor Keys' -> 'New RSA Key' -> pegar el JWK obtenido
  #   - marcar el radio 'PEM' y copiar la clave PEM resultante
  #   - pestaña 'Decoder' -> codificar la PEM en Base64
  #   - 'JWT Editor Keys' -> 'New Symmetric Key' -> 'Generate'
  #   - sustituir el valor de 'k' por la PEM codificada en Base64
  #   - guardar la clave
  #
  # Si la clave publica no esta expuesta, comando LITERAL para derivarla de dos tokens:
  docker run --rm -it portswigger/sig2n <token1> <token2>
precondicion: "La libreria usa un verify() generico que elige el algoritmo a partir de la cabecera 'alg' del token, mientras el desarrollador le pasa siempre una clave RSA publica fija. Entonces un token firmado con HS256 se verifica usando esa clave publica COMO SECRETO HMAC. Hace falta ademas obtener la clave publica del servidor."
como_se_descubre: |
  Señal en recon: tokens con alg RS256, y un JWK Set publicado en /jwks.json o
  /.well-known/jwks.json (ambas rutas nombradas por la fuente). Esa combinacion es
  exactamente el escenario: la clave publica esta disponible por diseño, porque se
  supone que ser publica no tiene coste.
  Si no esta expuesta, la fuente da el camino: derivarla de dos tokens existentes con
  sig2n (requiere Docker CLI).
control_negativo: |
  # [derivado] diseño de test A/B
  # A: token alg=HS256 firmado con la clave PUBLICA del servidor (en X.509 PEM,
  #    byte a byte) -> aceptado = confusion de algoritmos confirmada
  # B: token alg=HS256 firmado con una clave publica DISTINTA (p.ej. propia)
  #    -> debe ser rechazado
  # El par B descarta 'firma no verificada'.
  # ADVERTENCIA de la fuente sobre falsos negativos en A: la clave debe coincidir con
  # la copia del servidor BYTE A BYTE, incluido el formato X.509 PEM y los caracteres
  # no imprimibles como los saltos de linea. Un fallo de A suele ser un problema de
  # formato de clave, no de que el objetivo no sea vulnerable.
mata: |
  - La libreria fija el algoritmo esperado en el servidor y no lo lee del token -> muere.
  - Se valida 'alg' contra allowlist que solo permita RS256.
  - B tambien se acepta -> es 'firma no verificada'.
  - A falla pese a todo: revisar PRIMERO el formato exacto de la clave (ver advertencia)
    antes de concluir que no es vulnerable.
fuente: "https://portswigger.net/web-security/jwt y https://portswigger.net/web-security/jwt/algorithm-confusion. La fuente llama a la clase 'algorithm confusion attacks', tambien 'key confusion attacks'. Pseudocodigo, pasos, pasos de Burp y comando sig2n literales. Herramienta jwt_forgery.py de https://github.com/silentsignal/rsa_sign2n tambien nombrada."
confianza: alta
fecha: 2026-11-02
---
# [AUTH] Confusión de algoritmos RS256→HS256 — usar la clave pública como secreto HMAC

## Principio
En un esquema asimétrico la clave pública es pública: publicarla no tiene coste porque
solo sirve para *verificar*. La confusión de algoritmos rompe esa premisa. Si el
verificador decide el algoritmo leyendo el token, el atacante le dice `HS256` y la
librería interpreta la clave RSA pública como un **secreto HMAC** — un secreto que, por
definición, el atacante conoce. La clave pública pasa a servir para firmar.

## Causa raíz
Pseudocódigo literal de la fuente:

```javascript
function verify(token, secretOrPublicKey){ algorithm = token.getAlgHeader(); if(algorithm == "RS256"){ // Use the provided key as an RSA public key } else if (algorithm == "HS256"){ // Use the provided key as an HMAC secret key } }
```

Y el patrón de llamada que lo activa:

```javascript
publicKey = <public-key-of-server>; token = request.getCookie("session"); verify(token, publicKey);
```

El desarrollador pasa una clave pública y asume que se usará como pública. La librería
decide otra cosa según lo que diga el atacante.

## Pasos
1. Obtener la clave pública del servidor — puede estar en `/jwks.json` o
   `/.well-known/jwks.json`.
2. Convertirla a formato X.509 PEM.
3. Modificar el JWT. Literal: *"Just make sure that the `alg` header is set to HS256."*
4. Literal: *"Sign the token using the HS256 algorithm with the RSA public key as the
   secret."*

En la extensión JWT Editor de Burp: `JWT Editor Keys` → **New RSA Key** y pegar el JWK;
marcar el radio **PEM** y copiar la clave; en `Decoder`, codificarla en Base64; volver a
`JWT Editor Keys` → **New Symmetric Key** → **Generate**; sustituir el valor de `k` por
la PEM en Base64; guardar.

Si la clave pública no está expuesta, se puede derivar de dos tokens existentes:

```bash
docker run --rm -it portswigger/sig2n <token1> <token2>
```

## La causa número uno de falso negativo
La fuente advierte que la clave debe coincidir con la copia del servidor **byte a byte**,
incluido el formato X.509 PEM y los caracteres no imprimibles como los saltos de línea.
Esto merece subrayarse: cuando el ataque falla, lo primero que hay que revisar es el
formato exacto de la clave, no la hipótesis. Un salto de línea de más o de menos produce
un rechazo idéntico al de un objetivo no vulnerable, y ahí se abandonan hallazgos
válidos.

## Impacto
Suplantación total con firma válida, partiendo de información que el servidor publica
deliberadamente. Es el vector más contraintuitivo de la familia precisamente por eso:
el material del ataque no es un secreto filtrado, es un dato público.

## Remediación
De la fuente: *"Make sure that you perform robust signature verification on any JWTs
that you receive, and account for edge-cases such as JWTs signed using unexpected
algorithms."* `# [derivado]`: no usar el `verify()` genérico con una clave y confiar en
el token para elegir el algoritmo. Fijar el algoritmo esperado en el servidor y
rechazar cualquier token que declare otro. La fuente menciona que desde Burp Suite
Professional 2022.5.1 el escáner detecta automáticamente varias de estas fallas, lo que
la convierte en una comprobación de regresión viable en CI.
