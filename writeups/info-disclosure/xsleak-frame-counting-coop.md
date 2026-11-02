---
clase: info-disclosure
tech: xs-leaks
cwe: CWE-203
cvss: 5.3 # [derivado] fuga de la presencia de un dato en la cuenta de la victima
payload: |
  # ADVERTENCIA DE PROCEDENCIA: la fuente NO proporciona codigo de ataque para esta
  # tecnica. Lo describe en prosa y lo ilustra con una imagen. El unico snippet
  # literal que da es el de la DEFENSA (abajo), que muestra el ataque por negacion.
  #
  # DEFENSA CON COOP - codigo LITERAL de la fuente. El comentario del error es de la
  # propia pagina y es lo que revela la mecanica del ataque:
  const win = window.open('https://example.com/admin/customers?search=john%40example.com'); console.log(win.frames.length) // Cannot read property 'length' of null
  #
  # Es decir, el ATAQUE es exactamente ese codigo SIN la cabecera COOP:
  #   1. window.open() a una URL de busqueda con el termino que se quiere comprobar
  #   2. leer win.frames.length
  #   3. si la cuenta es 1, el termino existe en la base de datos de la victima;
  #      si es 0, no existe.
  # (los pasos son reconstruccion mia a partir de la prosa de la fuente)
  #
  # Valores de COOP que da la fuente: unsafe-none, same-origin-allow-popups, same-origin
  # El ejemplo de la fuente usa la cabecera COOP 'same-origin'. La pagina NO muestra
  # una linea de cabecera completa.
precondicion: "La aplicacion carga los resultados en un frame SOLO cuando existen resultados, de modo que un conjunto vacio no produce ningun frame. El atacante abre una ventana a la URL de busqueda y cuenta los frames. Ejemplo de la fuente: si la cuenta es 1, el correo esta en la base de datos de la victima."
como_se_descubre: |
  Señal en recon: paginas de busqueda o listado cuya ESTRUCTURA cambia segun haya o no
  resultados. Concretamente, que los resultados se rendericen en iframes. La cuenta de
  frames es observable entre origenes a traves de window.frames.length aunque el
  contenido no lo sea.
  La pregunta de recon generalizable: ¿que propiedades de esta pagina son observables
  desde otro origen? Numero de frames, si redirige, cuanto tarda, si carga como
  recurso. Todas son canales de un bit independientes del contenido.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: window.open con un termino de busqueda que SE SABE que existe -> frames.length = 1
  # B: window.open con un termino que SE SABE que no existe          -> frames.length = 0
  # El par A/B calibra el oraculo con dos valores conocidos ANTES de usarlo para
  # inferir datos desconocidos. Sin esa calibracion, un 0 puede significar
  # 'no existe', 'no autenticado' o 'la pagina cambio de estructura'.
  # C: repetir A sin sesion en el objetivo -> debe dar 0; confirma que el oraculo
  #    mide el estado de la VICTIMA y no algo global.
mata: |
  - Cabecera Cross-Origin-Opener-Policy (la fuente usa 'same-origin') -> win es null y
    leer frames.length lanza excepcion. Es la defensa directa.
  - La pagina renderiza siempre el mismo numero de frames, con resultados o sin ellos.
  - Los resultados no se cargan en frames.
  - C devuelve 1 sin sesion -> el oraculo no depende de la victima; no hay fuga personal.
fuente: "https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html (seccion 'Frame counting attacks'). El snippet de defensa con COOP es literal; el codigo de ATAQUE no existe en la pagina (solo prosa e imagen) y los pasos son reconstruccion. Contenido CC BY-SA 4.0. La pagina NO menciona COEP (Cross-Origin-Embedder-Policy) en ningun sitio."
confianza: media
fecha: 2026-11-02
---
# [INFO-DISCLOSURE] Conteo de frames — `window.frames.length` como oráculo de existencia

## Principio
La política del mismo origen protege el **contenido** de una ventana de otro origen,
pero no toda su estructura. `window.frames.length` es legible entre orígenes. Si una
página crea un frame solo cuando hay resultados, contar frames responde a la pregunta
"¿existe este dato en la cuenta de la víctima?" sin leer nada.

## Payload
**Advertencia de procedencia:** la fuente no da código de ataque para esta técnica. Lo
describe en prosa y lo ilustra con una imagen. El único snippet literal es el de la
defensa — y es revelador, porque muestra el ataque por negación:

```javascript
const win = window.open('https://example.com/admin/customers?search=john%40example.com'); console.log(win.frames.length) // Cannot read property 'length' of null
```

Ese comentario de error es de la propia página: describe lo que ocurre **con** COOP. El
ataque es el mismo código **sin** la cabecera. Los pasos, reconstruidos de la prosa:

1. `window.open()` a la URL de búsqueda con el término a comprobar.
2. Leer `win.frames.length`.
3. Si la cuenta es 1, el término existe en la base de datos de la víctima; si es 0, no.

Como los pasos son reconstrucción y no cita, este writeup va con `confianza: media`.

## La pregunta de recon que generaliza
El valor de esta técnica no está en el conteo de frames, sino en el hábito que enseña:
**¿qué propiedades de esta página son observables desde otro origen?** El número de
frames, si redirige, cuánto tarda, si carga como recurso de un tipo concreto. Cada una
es un canal de un bit que no pasa por el contenido, y por tanto que la SOP no cubre.
Toda la familia XS-Leaks sale de hacerse esa pregunta sistemáticamente.

## Calibrar antes de inferir
Hay que probar el oráculo con un valor que exista y otro que no **antes** de usarlo para
inferir datos desconocidos. Un 0 sin calibrar puede significar "no existe", "no hay
sesión" o "la página cambió de estructura". Y conviene una tercera prueba sin sesión en
el objetivo: si el oráculo devuelve 1 igualmente, no mide nada de la víctima y no hay
fuga personal que reportar.

## Impacto
Determinar desde un sitio arbitrario si un dato concreto —un correo, un nombre, un
número de cliente— está presente en la cuenta de la víctima. Con un oráculo así se
consultan datos de uno en uno hasta reconstruir información sensible, sin leer ninguna
respuesta.

## Remediación
`Cross-Origin-Opener-Policy`, que la fuente usa con valor `same-origin`: la referencia
a la ventana queda desacoplada y `win` es `null`, así que leer `frames.length` lanza
excepción. Los valores que la fuente enumera son `unsafe-none`,
`same-origin-allow-popups` y `same-origin`.

`# [derivado]`: como medida independiente, mantener constante la estructura de la página
—mismo número de frames con resultados y sin ellos— elimina el oráculo en origen, lo
que es útil cuando COOP rompe integraciones legítimas.

Nota: la fuente **no menciona** `Cross-Origin-Embedder-Policy` en ningún punto, así que
no lo incluyo como defensa documentada aquí.
