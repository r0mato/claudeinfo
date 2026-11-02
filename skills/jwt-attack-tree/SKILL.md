---
name: jwt-attack-tree
description: Arbol de ataque sobre JWT ordenado por coste creciente, de la comprobacion de un caracter a la confusion de algoritmos. Evita el falso negativo mas comun de cada rama.
model: claude-opus-5
---

# 0 — SEÑAL CITADA

> PortSwigger Web Security Academy, "JWT attacks" y "Algorithm confusion attacks".

La cita que explica por que esta familia existe, sobre la causa raiz de la confusion de
algoritmos (pseudocodigo literal de la fuente):

```javascript
function verify(token, secretOrPublicKey){ algorithm = token.getAlgHeader(); if(algorithm == "RS256"){ // Use the provided key as an RSA public key } else if (algorithm == "HS256"){ // Use the provided key as an HMAC secret key } }
```

El defecto estructural de JWT: **el dato que decide como validar viaja dentro del dato
a validar.** `alg`, `jwk`, `jku`, `kid` y `x5c` son todos instancias del mismo error.

Regla de oro derivada: la clave de verificacion debe resolverse desde configuracion del
servidor, nunca desde contenido del token.

---

# 1 — Arbol de decision (coste creciente)

## Paso 1 — ¿Se verifica la firma? (coste: 1 peticion)
Cambiar **un caracter** del payload sin recalcular la firma. Reenviar.

- **Aceptado** -> PARAR. La firma no se verifica (`decode()` en lugar de `verify()`).
  Es el techo de impacto al minimo coste; todo lo demas es innecesario.
- **Rechazado** -> seguir. Ya se sabe que hay verificacion real.

## Paso 2 — Leer la cabecera (coste: 0 peticiones)
Decodificar y anotar: `alg`, y la presencia de `jwk`, `jku`, `kid`, `cty`, `x5c`.
Cada parametro presente es una rama del arbol. Esto no cuesta nada y decide el orden
del resto.

## Paso 3 — `alg: none` (coste: 2 peticiones)
```json
{ "alg": "none", "typ": "JWT" }
```
**El punto final es obligatorio.** Cita literal: *"Even if the token is unsigned, the
payload part must still be terminated with a trailing dot."* La tercera seccion queda
vacia pero presente: `<header>.<payload>.`

- **Falla** -> probar variantes de capitalizacion. Si acepta `None` y rechaza `none`,
  el filtro es textual: hallazgo en si mismo.

## Paso 4 — Rama simetrica: fuerza bruta offline (coste: 0 peticiones al objetivo)
Solo si `alg` es HS256.
```bash
hashcat -a 0 -m 16500 <jwt> <wordlist>
```
Wordlist que la fuente enlaza: `github.com/wallarm/jwt-secrets`.
Nota literal: con mas de una ejecucion hace falta `--show`.

Ventaja decisiva: el ataque es **offline**. Cita literal: hashcat *"doesn't rely on
sending requests to the server"*. Sin limite de intentos, sin ruido, sin bloqueos.
Cuando hay HS256, esta rama es la de menor riesgo y se prueba antes que las demas.

## Paso 5 — Rama de clave aportada: `jwk` (coste: 3 peticiones)
Generar par RSA propio, poner la publica en `jwk`, firmar con la privada.
Herramienta: extension Burp **JWT Editor**, ataque **Embedded JWK**.

## Paso 6 — Rama de clave remota: `jku` (coste: 4 peticiones + host propio)
Apuntar `jku` a un JWK Set alojado por el investigador; el `kid` del token debe
coincidir con el de la clave del Set.

**Doble hallazgo:** si llega la peticion saliente al host propio, queda probado que el
servidor descarga URLs arbitrarias — **una SSRF reportable por si misma**, aunque el
token se rechace. Si hay allowlist de dominios, el problema se transforma en parseo de
URL -> `skill:ssrf-escalation`.

## Paso 7 — Rama de ruta: `kid` path traversal (coste: 4 peticiones)
```json
{ "kid": "../../../dev/null", "typ": "JWT", "alg": "HS256" }
```
`/dev/null` se lee como cadena vacia: firmar con cadena vacia da firma valida. No hay
que **adivinar** el contenido de un fichero, solo elegir uno cuyo contenido se conozca.
Requiere traversal **y** algoritmo simetrico: con RS256 el fichero tendria que ser una
clave privada valida.

La fuente señala tambien SQLi por `kid` si las claves estan en base de datos.

## Paso 8 — Confusion de algoritmos RS256 -> HS256 (coste: alto)
1. Obtener la clave publica: `/jwks.json` o `/.well-known/jwks.json`
2. Convertir a X.509 PEM
3. Poner `alg` a HS256
4. Firmar con HS256 usando **la clave publica RSA como secreto**

Si la publica no esta expuesta, derivarla de dos tokens:
```bash
docker run --rm -it portswigger/sig2n <token1> <token2>
```

---

# 2 — Trampas de falso positivo

**1. Formato de clave, leido como "no vulnerable".** En el paso 8 la clave debe
coincidir con la del servidor **byte a byte**, incluido el X.509 PEM y los saltos de
linea. Un salto de mas produce un rechazo **identico** al de un objetivo seguro. Señal
de muerte: el ataque falla y no se ha verificado el formato exacto antes de concluir.

**2. Token mal formado, leido como politica.** `alg: none` sin el punto final se
rechaza por formato, no por seguridad. Señal de muerte: no se probo la variante con
punto final.

**3. Firma no verificada confundida con la rama concreta.** Si se acepta un token con
`jwk` propio, puede ser por confiar en la clave embebida o porque no se verifica nada.
Señal de muerte: firmar con una clave que **no** corresponde al `jwk` declarado y ver
que tambien se acepta. Son fallos distintos con remediaciones distintas.

---

# 3 — Cuándo esta skill NO es la correcta

- El token no es un JWT (cookie opaca, sesion de servidor): no aplica.
- El JWT viaja correctamente firmado pero **los claims no gobiernan la autorizacion**:
  el servidor consulta la base de datos. Aunque el token se manipule no hay escalada
  -> ver `writeups/idor/` (no hay skill para esta clase; ver ELITE-REPORT)
- El problema esta en el flujo que **emite** el token (OAuth/OIDC), no en su
  validacion -> `skill:oauth-flow-audit`
- `jku` revela que el servidor descarga URLs arbitrarias y eso es el hallazgo principal
  -> `skill:ssrf-escalation`

---

# 4 — Output

Escribir en `evidencias/jwt-attack-tree-<slug>.md`:

- cabecera decodificada completa y qué ramas abre
- paso alcanzado y por que se paro
- para el paso 1: el caracter cambiado y la respuesta
- para HS256: comando hashcat y resultado (o constancia de no exito)
- para `jku`: si llego peticion saliente al host propio (SSRF aparte)
- para el paso 8: formato exacto de la clave usada, y confirmacion de haberlo
  verificado byte a byte antes de concluir
- las tres trampas, con resultado
