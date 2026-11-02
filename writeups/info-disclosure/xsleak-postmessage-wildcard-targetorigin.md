---
clase: info-disclosure
tech: postmessage
cwe: CWE-346
cvss: 7.5 # [derivado] fuga directa de datos sensibles a un origen arbitrario
payload: |
  # CODIGO VULNERABLE - LITERAL de la fuente:
  // Origin: http://example.com const site = new URLSearchParams(window.location.search).get('site'); // https://evil.com const popup = window.open(site); popup.postMessage('secret message!', '*');  // Origin: https://evil.com window.addEventListener('message', e => {     alert(e.data) // secret message! - leak });
  #
  # CODIGO CORREGIDO - LITERAL de la fuente. La UNICA diferencia es el segundo
  # argumento de postMessage: '*' pasa a ser un origen exacto.
  // Origin: http://example.com const site = new URLSearchParams(window.location.search).get('site'); // https://evil.com const popup = window.open(site); popup.postMessage('secret message!', 'https://sub.example.com');  // Origin: https://evil.com window.addEventListener('message', e => {     alert(e.data) // no data! });
  #
  # Cita literal de la fuente sobre el comodin:
  #   el comodin '*' 'causes any origin to receive the message'
precondicion: "(1) El atacante consigue una referencia de ventana: en el ejemplo de la fuente, porque el propio sitio hace window.open() hacia una URL que viene de un parametro ('site'). (2) El emisor usa el comodin '*' como targetOrigin. Las DOS condiciones son necesarias: con '*' pero sin referencia de ventana no hay destinatario, y con referencia pero sin '*' el mensaje no se entrega."
como_se_descubre: |
  Revision de codigo de cliente: buscar `postMessage(` y mirar el SEGUNDO argumento.
  Un '*' es un hallazgo inmediato que no requiere ninguna prueba dinamica. Es una de
  las busquedas de mejor rendimiento sobre JS de cliente, junto con la de listeners sin
  comprobacion de origen.
  Señal complementaria: un parametro de URL que controle el destino de un window.open()
  (en el ejemplo, 'site'). Ese es el otro extremo del problema y suele ser el que
  convierte un '*' teorico en explotable.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: ?site=https://host-controlado  -> el listener del atacante recibe el mensaje
  # B: ?site=https://sub.example.com  -> comportamiento normal, entrega legitima
  # C: el mismo flujo con targetOrigin exacto en el emisor
  #    -> A NO recibe nada (es la correccion, y sirve para verificarla)
  # El control C es util en el informe: demuestra que la correccion propuesta
  # efectivamente cierra el caso, en lugar de solo afirmarlo.
mata: |
  - El emisor usa un targetOrigin exacto en lugar de '*' -> muere.
  - El destino de window.open() no es controlable por el atacante -> sin referencia.
  - El mensaje no contiene nada sensible (comprobar antes de reportar severidad alta).
mata_nota: |
  # El segundo punto de 'mata' es el que mas se olvida: un '*' sobre un mensaje sin
  # datos sensibles es una mala practica, no una vulnerabilidad. Conviene leer QUE se
  # envia antes de asignar severidad.
fuente: "https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html (seccion 'Attacks on postMessage communication'). Ambos bloques de codigo y la cita sobre el comodin son literales de la pagina. Contenido CC BY-SA 4.0. ADVERTENCIA: el render colapso los saltos de linea del codigo."
confianza: alta
fecha: 2026-11-02
---
# [INFO-DISCLOSURE] `postMessage` con `targetOrigin: '*'` — enviar un secreto a quien sea

## Principio
El segundo argumento de `postMessage` no es decorativo: declara **a qué origen** se
permite entregar el mensaje. Con `'*'` no hay restricción, y la fuente lo dice sin
rodeos: el comodín *"causes any origin to receive the message"*. Si además el atacante
puede influir en qué ventana se abre, tiene un canal directo por el que el propio sitio
le entrega sus datos.

## Payload
Vulnerable:

```javascript
// Origin: http://example.com const site = new URLSearchParams(window.location.search).get('site'); // https://evil.com const popup = window.open(site); popup.postMessage('secret message!', '*');  // Origin: https://evil.com window.addEventListener('message', e => {     alert(e.data) // secret message! - leak });
```

Corregido:

```javascript
// Origin: http://example.com const site = new URLSearchParams(window.location.search).get('site'); // https://evil.com const popup = window.open(site); popup.postMessage('secret message!', 'https://sub.example.com');  // Origin: https://evil.com window.addEventListener('message', e => {     alert(e.data) // no data! });
```

La única diferencia entre los dos bloques es el segundo argumento. Es un buen ejemplo de
corrección de un carácter con efecto binario.

## Dos condiciones, no una
El `'*'` por sí solo no es explotable: hace falta además que el atacante obtenga una
referencia de ventana. En el ejemplo de la fuente eso lo aporta el propio sitio, que
hace `window.open()` hacia una URL tomada de un parámetro (`site`). Conviene buscar las
dos piezas por separado, porque un `'*'` sin referencia alcanzable es una mala práctica
latente, y un parámetro que controla `window.open()` es un open redirect que además
habilita esto.

## Dónde buscarlo
`postMessage(` con `'*'` en el segundo argumento es un hallazgo de revisión estática
puro: no requiere ninguna prueba dinámica. Junto con la búsqueda de listeners sin
comprobación de origen, es una de las dos consultas de mayor rendimiento sobre
JavaScript de cliente.

## Antes de asignar severidad
Hay que leer **qué** se envía. Un `'*'` sobre un mensaje sin datos sensibles es una mala
práctica, no una vulnerabilidad, y reportarlo como fuga de datos sin comprobar el
contenido es el error que más credibilidad cuesta en esta clase.

## Impacto
Fuga directa de lo que viaje en el mensaje a un origen que elige el atacante. En los
casos reales esos mensajes suelen llevar tokens, identificadores de sesión o datos de
perfil, porque es justo para eso para lo que se usa `postMessage` entre componentes.

## Remediación
De la fuente: *"always specify the exact `targetOrigin` in postMessage."*

`# [derivado]`: y en el extremo receptor, comprobar `event.origin` por igualdad exacta.
Las dos mitades son necesarias — un emisor correcto no protege a un receptor permisivo,
y al contrario.
