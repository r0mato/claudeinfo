---
clase: race
tech: http2
cwe: CWE-362
cvss: 0.0 # [derivado] no es una vulnerabilidad: es la PRIMITIVA de explotacion. CVSS no aplica.
payload: |
  # No es un payload de red sino un procedimiento de envio. Pasos LITERALES de la fuente:
  #
  # 1) Pre-enviar el grueso de cada peticion:
  #    - Si la peticion NO tiene cuerpo: enviar todas las cabeceras, pero NO poner
  #      el flag END_STREAM. Retener un data frame vacio con END_STREAM puesto.
  #    - Si la peticion SI tiene cuerpo: enviar las cabeceras y todo el cuerpo
  #      EXCEPTO el ultimo byte. Retener un data frame con ese ultimo byte.
  #
  #    Advertencia literal de la fuente: no enviar el cuerpo completo confiando en
  #    omitir END_STREAM, porque algunas implementaciones HTTP/2 usan content-length
  #    para decidir que el mensaje esta completo en vez de esperar END_STREAM.
  #
  # 2) Preparar el envio de los frames finales:
  #    - Esperar 100ms para asegurar que los frames iniciales han salido.
  #    - Asegurar que TCP_NODELAY esta DESACTIVADO: es crucial que el algoritmo de
  #      Nagle agrupe los frames finales.
  #    - Enviar un ping para calentar la conexion local. Sin esto, la pila de red del
  #      SO pone el primer frame final en un paquete separado.
  #
  # 3) Enviar los frames retenidos. Verificable en Wireshark: deben ir en UN paquete.
  #
  # Implementacion de referencia: extension open-source Turbo Intruder (plantilla
  # 'single-packet-attack'); en Burp Repeater, la opcion 'Send group in parallel'.
precondicion: "El objetivo habla HTTP/2. La fuente lo explicita como novedad del protocolo: 'This is a novel possibility with HTTP/2 because it allows HTTP requests to be sent over a single connection concurrently, whereas in HTTP/1.1 they have to be sequential.' Si no hay HTTP/2, se recurre a last-byte sync (peor: 4ms de dispersion mediana frente a 1ms). La fuente indica que funciono en todos los endpoints DINAMICOS de todos los servidores probados, y que NO funciona para ficheros estaticos en ciertos servidores."
como_se_descubre: |
  No se descubre: se usa. Es la herramienta que hace detectables las demas clases de
  esta carpeta. El dato que justifica usarla es la medida de la propia fuente:
  20 peticiones enviadas 17.000 km de Melbourne a Dublin, con dispersion mediana de
  1ms y desviacion tipica de 0,3ms, frente a 4ms y 3ms del last-byte sync. Como la
  ventana de carrera tipica ronda 1ms, la diferencia es la que separa poder explotar
  de no poder.
control_negativo: |
  # [derivado] el 'control' aqui es el BENCHMARK, que la fuente exige explicitamente
  # A: enviar el lote de peticiones con varios segundos de separacion entre ellas
  #    -> comportamiento normal de referencia
  # B: enviar el MISMO lote con el single-packet attack
  #    -> cualquier desviacion respecto de A es la pista
  # Cita literal de la fuente sobre por que este orden es obligatorio:
  #   'Clues can be subtle and counterintuitive so if you skip the benchmark step,
  #    you'll miss vulnerabilities.'
  # Nota de la fuente: PHP bloquea por sessionid por defecto, asi que hay que usar
  # una sesion distinta por peticion del lote o se procesaran secuencialmente.
mata: |
  - El objetivo no soporta HTTP/2 -> usar last-byte sync, con menos resolucion.
  - Endpoint estatico en ciertos servidores -> la tecnica no aplica.
  - Tiempo de proceso MAS LARGO de lo esperado: puede indicar limites de recursos o
    que la aplicacion usa locking para evitar concurrencia (ver nota PHP).
  - Advertencia literal de la fuente sobre falsos positivos: 'it's important not to
    attribute inconsistent request timing to application behavior such as locking
    mechanisms that only allow a single thread to access a resource at once.'
fuente: "https://portswigger.net/research/smashing-the-state-machine (James Kettle, publicado 2023-08-09, actualizado 2023-09-18). Idea del paquete unico atribuida en el articulo a la charla USENIX 2020 'Timeless Timing Attacks' y a una tesis de Aalto University de 2020."
confianza: alta
fecha: 2026-11-02
---
# [RACE] El single-packet attack — eliminar el jitter de red para alcanzar ventanas de 1ms

## Principio
Una condición de carrera web vive en una ventana de alrededor de 1 ms. El jitter de red
es mayor que eso, así que con envío secuencial las peticiones no llegan juntas y la
ventana se pierde. La idea es desacoplar *enviar* de *completar*: se pre-envía casi
toda cada petición, se retiene un fragmento mínimo, y luego se completan 20-30
peticiones con **un solo paquete TCP**. Cita literal de la fuente: *"The use of a single
TCP packet completely eliminates the effect of network jitter"*.

Definición de la ventana, literal: *"A sub-state is a short-lived state that an
application transitions through while processing a single request, and exits before the
request completes. Sub-states are only occupied for a brief time window - often around
1ms (0.001s). I'll refer to this time window as the 'race window'."*

## Procedimiento
**Fase 1 — pre-enviar.** Si la petición no tiene cuerpo: enviar todas las cabeceras sin
poner el flag `END_STREAM`, y retener un data frame vacío con `END_STREAM` puesto. Si
tiene cuerpo: enviar las cabeceras y todo el cuerpo salvo el último byte, y retener un
data frame con ese byte.

La fuente advierte expresamente contra el atajo: *"You might be tempted to send the full
body and rely on not sending END_STREAM, but this will break on certain HTTP/2 server
implementations that use the content-length header to decide when a message is complete,
as opposed to waiting for END_STREAM."*

**Fase 2 — preparar.** Esperar 100 ms para que los frames iniciales hayan salido.
Asegurar que `TCP_NODELAY` está **desactivado**: hace falta que el algoritmo de Nagle
agrupe los frames finales. Enviar un ping para calentar la conexión local, porque sin
él el SO pone el primer frame final en un paquete aparte.

**Fase 3 — disparar.** Enviar los frames retenidos y verificar en Wireshark que
viajaron en un único paquete.

La elegancia del método está en que no necesita pila TCP ni TLS propia: según la fuente,
*"thanks to some creative abuse of Nagle's algorithm, it doesn't require a custom TCP or
TLS stack."*

## Impacto
No es una vulnerabilidad —de ahí el CVSS 0.0— sino lo que hace explotables a las demás.
Medición de la fuente, Melbourne→Dublín, 17.000 km, 20 peticiones:

| Técnica | Dispersión mediana | Desviación típica |
|---|---|---|
| Last-byte sync | 4 ms | 3 ms |
| Single-packet attack | 1 ms | 0,3 ms |

Con ventanas de ~1 ms, esa diferencia decide si la carrera se gana.

## Metodología asociada
La fuente estructura la caza en tres fases: *"Predict potential collisions"*, *"Probe for
clues"* y *"Prove the concept"*. Para predecir colisiones usa tres preguntas literales:
*"1) How is the state stored?"*, *"2) Are we editing or appending?"*, *"3) What's the
operation keyed on?"*

El paso que más se salta y más cuesta es el benchmark previo. La pista está en la
desviación respecto al comportamiento normal, no en el comportamiento en sí — y sin
línea base no hay desviación que ver. Un tiempo de proceso **más corto** de lo esperado
sugiere que los datos pasan a otro hilo, lo que aumenta mucho la probabilidad de
vulnerabilidad; **más largo** sugiere límites de recursos o locking.

Para probar el concepto, la fuente recomienda reducir: *"you'll want to eliminate all
unnecessary requests - two should be sufficient for exploiting most vulnerabilities."*

## Remediación
No aplica: es una técnica de prueba. Las defensas están en los writeups de cada clase.
