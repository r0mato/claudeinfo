---
clase: auth
tech: jwt-nodejs
cwe: CWE-347
cvss: 9.1 # [derivado] suplantacion total de identidad sin credenciales
payload: |
  # Claims de ejemplo literales de la fuente:
  { "username": "carlos", "isAdmin": false }
  #
  # Ataque: modificar los claims y dejar la firma SIN TOCAR (o basura).
  # La aplicacion vulnerable solo llama a decode(), nunca a verify().
  { "username": "administrator", "isAdmin": true }
  #
  # No hace falta ninguna clave: la firma no se comprueba en absoluto.
precondicion: "La aplicacion pasa los tokens entrantes al metodo decode() de la libreria y NUNCA llama a verify(). Libreria citada en la fuente como ejemplo: jsonwebtoken de Node.js. Es un fallo de uso de API, no de criptografia."
como_se_descubre: |
  Prueba de coste minimo y primera que hay que hacer sobre cualquier JWT: cambiar UN
  caracter del payload sin recalcular la firma y reenviar. Si la aplicacion sigue
  aceptando la sesion, la firma no se verifica. Es la comprobacion mas barata de todo
  el arbol de JWT y conviene hacerla antes de cualquier ataque sofisticado: si pasa,
  los demas vectores son innecesarios.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: token con 'isAdmin' cambiado a true y la firma original intacta
  #    -> aceptado = la firma NO se verifica
  # B: token con 'isAdmin' cambiado a true y la firma alterada a basura
  #    -> si TAMBIEN se acepta, se confirma que no hay verificacion alguna
  # C: token completamente sin modificar
  #    -> control de que la sesion funciona de base
  # Si A se acepta pero B se rechaza, la firma SI se comprueba y lo que ha pasado es
  # otra cosa (p.ej. los claims no se usan para autorizar). Distinguirlo evita un
  # reporte erroneo.
mata: |
  - La aplicacion llama a verify() con la clave correcta -> muere.
  - Modificar la firma provoca rechazo (control B) -> hay verificacion.
  - Los claims del token no gobiernan la autorizacion (el servidor consulta la BD)
    -> aunque el token se acepte, no hay escalada.
fuente: "https://portswigger.net/web-security/jwt (seccion 'Exploiting flawed JWT signature verification' / 'Accepting arbitrary signatures')."
confianza: alta
fecha: 2026-11-02
---
# [AUTH] JWT con firma nunca verificada — `decode()` en lugar de `verify()`

## Principio
Las librerías de JWT exponen dos métodos que parecen intercambiables y no lo son:
`decode()` solo parsea el token, `verify()` comprueba la firma. Un desarrollador que
use `decode()` para leer los claims ha construido un sistema de autenticación donde el
cliente declara quién es y el servidor le cree. No hay fallo criptográfico: hay una
llamada a la API equivocada.

## Payload
Claims originales, literales de la fuente:

```json
{ "username": "carlos", "isAdmin": false }
```

El ataque consiste en reescribirlos y **no tocar la firma**:

```json
{ "username": "administrator", "isAdmin": true }
```

No se necesita clave, ni algoritmo, ni herramienta. Se reescribe el payload en base64url
y se reenvía con la firma original.

## Impacto
Suplantación completa de cualquier identidad, incluida la administrativa, sin credencial
alguna. Es el techo de impacto de la familia JWT y además el de menor coste de
explotación, lo que justifica probarlo primero.

## Orden de pruebas
Esta debe ser **la primera** comprobación sobre cualquier JWT, antes de intentar
confusión de algoritmos, `jku`, `kid` o fuerza bruta del secreto. Cuesta una petición.
Si pasa, todo lo demás es innecesario; si no pasa, el resultado ya informa sobre qué
hace la librería y orienta el resto del árbol.

## Remediación
Cita literal de la fuente: *"Make sure that you perform robust signature verification on
any JWTs that you receive, and account for edge-cases such as JWTs signed using
unexpected algorithms."* Y: *"Use an up-to-date library for handling JWTs and make sure
your developers fully understand how it works, along with any security implications.
Modern libraries make it more difficult for you to inadvertently implement them
insecurely, but this isn't foolproof due to the inherent flexibility of the related
specifications."*

`# [derivado]`: a nivel de revisión de código, buscar toda llamada a `decode()` sobre
datos que vengan del cliente es una regla de grep sencilla y de alto rendimiento.
