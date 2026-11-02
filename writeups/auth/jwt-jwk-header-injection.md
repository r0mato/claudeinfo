---
clase: auth
tech: jwt-jwk
cwe: CWE-347
cvss: 9.1 # [derivado] el atacante firma con su propia clave: suplantacion total
payload: |
  # Cabecera LITERAL de la fuente (clave publica del ATACANTE embebida en el token):
  { "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG", "typ": "JWT", "alg": "RS256", "jwk": { "kty": "RSA", "e": "AQAB", "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG", "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m" } }
  #
  # Flujo: el atacante genera su propio par RSA, pone su clave publica en 'jwk',
  # modifica los claims y firma el token con su clave PRIVADA. El servidor vulnerable
  # valida la firma con la clave que viene en el propio token: cuadra siempre.
  #
  # Herramienta nombrada por la fuente: extension Burp 'JWT Editor',
  # ataque 'Embedded JWK'.
precondicion: "El servidor usa CUALQUIER clave embebida en el parametro 'jwk' en lugar de una allowlist de claves publicas de confianza. Es el fallo de diseño: aceptar que el token aporte la clave con la que se le va a validar."
como_se_descubre: |
  Señal en recon: cabecera con alg RS256 (o cualquier asimetrico). La prueba, en
  palabras de la fuente, es directa: 'Send the request to test how the server
  responds.' Es decir, forjar el token con jwk propio y observar. La fuente no da
  una señal de deteccion previa, asi que la prueba ES la deteccion.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: token con 'jwk' propio y claims modificados, firmado con la clave privada propia
  #    -> aceptado = el servidor confia en la clave embebida
  # B: el mismo token con 'jwk' propio pero firmado con OTRA clave distinta
  #    -> debe ser rechazado
  # El par B es esencial: si B tambien se acepta, el servidor no verifica nada y el
  # hallazgo es 'firma no verificada', no inyeccion de jwk. Son fallos distintos con
  # remediaciones distintas, y confundirlos debilita el reporte.
mata: |
  - El servidor mantiene allowlist de claves publicas de confianza e ignora 'jwk' -> muere.
  - El token es HS256 (simetrico): este vector no aplica.
  - B tambien se acepta -> es otro fallo (firma no verificada).
fuente: "https://portswigger.net/web-security/jwt (seccion 'Injecting self-signed JWTs via the jwk parameter'). Cabecera JSON literal de la pagina. Herramienta: extension Burp 'JWT Editor' (ataque 'Embedded JWK')."
confianza: alta
fecha: 2026-11-02
---
# [AUTH] Inyección de clave propia en la cabecera `jwk` — el token trae su propia llave

## Principio
La especificación de JWS permite que un token lleve su clave pública dentro, en el
parámetro `jwk`. La idea tiene usos legítimos, pero si el servidor valida la firma con
esa clave, la verificación se vuelve circular: el atacante aporta el candado y la llave,
y el candado abre. La firma sigue siendo criptográficamente correcta — ahí está la
trampa, porque nada "falla" desde el punto de vista del verificador.

## Payload
Cabecera literal de la fuente, con la clave pública del atacante embebida:

```json
{ "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG", "typ": "JWT", "alg": "RS256", "jwk": { "kty": "RSA", "e": "AQAB", "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG", "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m" } }
```

El flujo es: generar un par RSA propio, poner la pública en `jwk`, modificar los claims
y firmar con la privada propia. La fuente nombra la extensión **JWT Editor** de Burp y
su ataque **Embedded JWK** para automatizarlo.

## Impacto
Suplantación total con firma válida. A diferencia del token sin firma, aquí el token es
criptográficamente íntegro, así que no dispara alertas basadas en "firma inválida": el
registro del servidor muestra una validación correcta. Eso lo hace más difícil de
detectar en retrospectiva que `alg: none`.

## Por qué el control negativo importa aquí
Si el servidor acepta el token forjado, hay dos explicaciones posibles: confía en la
clave embebida, o no verifica nada en absoluto. Firmar con una clave que **no**
corresponde al `jwk` declarado separa los dos casos. Es una petición extra y cambia qué
vulnerabilidad se reporta y qué corrección se pide, así que no conviene saltársela.

## Remediación
Mantener una allowlist de claves públicas de confianza e **ignorar por completo** los
parámetros de clave que vengan en el token. De la fuente: *"Make sure that you perform
robust signature verification on any JWTs that you receive, and account for edge-cases
such as JWTs signed using unexpected algorithms."* `# [derivado]`: la regla de diseño es
que la clave de verificación debe resolverse a partir de configuración del servidor,
nunca de contenido del token — lo que vale igual para `jwk`, `jku`, `kid` y `x5c`.
