---
clase: auth
tech: jwt-jku
cwe: CWE-347
cvss: 9.1 # [derivado] suplantacion total con firma valida
payload: |
  # La fuente NO muestra un valor literal de cabecera 'jku'. Lo que SI muestra es la
  # estructura literal del JWK Set que el servidor descarga de esa URL:
  { "keys": [ { "kty": "RSA", "e": "AQAB", "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab", "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ" }, { "kty": "RSA", "e": "AQAB", "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA", "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw" } ] }
  #
  # Flujo: el atacante aloja un JWK Set con su propia clave publica, apunta 'jku' a
  # esa URL, y firma el token con su clave privada. El servidor descarga la clave del
  # atacante y la firma cuadra.
  #
  # El 'kid' del token debe coincidir con el 'kid' de la clave del atacante en el Set.
precondicion: "El servidor DESCARGA la clave desde la URL indicada en 'jku'. La fuente indica que los sitios mas seguros solo descargan de dominios de confianza, y que las discrepancias de parseo de URL pueden a veces esquivar ese filtro (la propia fuente remite a su tema de SSRF para ello)."
como_se_descubre: |
  Señal en recon: cabecera 'jku' presente en los tokens legitimos, o un JWK Set
  publicado en /jwks.json o /.well-known/jwks.json (rutas que la fuente nombra). La
  presencia de uno de esos endpoints indica que el servidor trabaja con JWK Sets y
  por tanto que 'jku' puede ser una via.
  El encadenamiento importante: si hay allowlist de dominios, el vector se convierte
  en un problema de parseo de URL -> ver writeups de SSRF (confusion de parsers).
control_negativo: |
  # [derivado] diseño de test A/B
  # A: 'jku' apuntando a un JWK Set controlado por el investigador, token firmado
  #    con la clave privada correspondiente -> aceptado = el servidor descarga y confia
  # B: 'jku' apuntando a una URL controlada que NO devuelve un JWK Set valido
  #    -> debe fallar; confirma ademas que el servidor realmente hace la peticion
  # El par B tiene un segundo uso: la peticion saliente hacia el host del investigador
  # PRUEBA la descarga incluso si el token acaba rechazado. Es decir, B detecta la
  # SSRF subyacente aunque la suplantacion no llegue a funcionar.
mata: |
  - Allowlist estricta de hosts para 'jku' sin discrepancias de parseo -> muere.
  - El servidor ignora 'jku' y usa claves de configuracion -> muere.
  - No se observa peticion saliente en el control B -> el servidor no descarga nada.
fuente: "https://portswigger.net/web-security/jwt (seccion 'Injecting self-signed JWTs via the jku parameter'). Estructura del JWK Set literal de la pagina; la pagina no da un valor de ejemplo para 'jku'. Rutas /jwks.json y /.well-known/jwks.json nombradas en la pagina de confusion de algoritmos."
confianza: media
fecha: 2026-11-02
---
# [AUTH] Inyección de `jku` — el servidor descarga la clave del atacante

## Principio
`jku` (*JWK Set URL*) le dice al servidor de dónde bajar la clave pública con la que
verificar. Si el servidor obedece sin restringir el destino, el atacante le indica su
propio servidor. Es la misma circularidad que `jwk`, con un salto de red en medio — y
ese salto añade un segundo problema: el servidor hace una petición HTTP a una URL que
controla el atacante, que es una SSRF por construcción.

## Payload
La fuente no publica un valor de ejemplo para la cabecera `jku`. Lo que sí publica es la
estructura del JWK Set que el servidor descarga:

```json
{ "keys": [ { "kty": "RSA", "e": "AQAB", "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab", "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ" }, { "kty": "RSA", "e": "AQAB", "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA", "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw" } ] }
```

El atacante aloja un Set equivalente con su clave pública, apunta `jku` ahí, y hace que
el `kid` del token coincida con el `kid` de su clave en el Set.

## Dos vulnerabilidades por el precio de una
Esta es la particularidad táctica. El control negativo —apuntar `jku` a un host propio
que no devuelve un Set válido— sirve para dos cosas. Si llega la petición saliente al
host del investigador, queda **probado que el servidor descarga URLs arbitrarias**,
aunque el token se rechace después. Eso es una SSRF reportable por sí misma, con su
propio impacto (alcance a metadata cloud, a servicios internos), independiente de que
la suplantación funcione.

Y cuando sí hay allowlist de dominios, el vector no muere: se transforma en un problema
de parseo de URL. La propia fuente remite a su material de SSRF para esquivar el filtro,
lo que conecta esta entrada con los writeups de confusión de parsers en `writeups/ssrf/`.

## Impacto
Suplantación total con firma válida, más SSRF desde el servidor de autenticación —
que suele estar en una posición de red privilegiada.

## Remediación
Cita literal de la fuente: *"Enforce a strict whitelist of permitted hosts for the `jku`
header."* `# [derivado]`: la allowlist debe aplicarse sobre la IP resuelta, no solo
sobre la cadena de la URL, porque si no reaparecen las discrepancias de parseo; y lo
más seguro es no descargar claves en tiempo de petición en absoluto, resolviéndolas
desde configuración.
