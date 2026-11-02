---
name: race-window
description: Caza de condiciones de carrera web con el single-packet attack. Predice colisiones, busca pistas contra una linea base y distingue señal de jitter.
model: claude-opus-5
---

# 0 — SEÑAL CITADA

> "Smashing the state machine: the true potential of web race conditions" — James
> Kettle, PortSwigger, 2023-08-09.

Definicion literal de lo que se persigue:

> "A sub-state is a short-lived state that an application transitions through while
> processing a single request, and exits before the request completes. Sub-states are
> only occupied for a brief time window - often around 1ms (0.001s). I'll refer to this
> time window as the 'race window'."

Y la frase que ordena toda la skill:

> "Clues can be subtle and counterintuitive so if you skip the benchmark step, you'll
> miss vulnerabilities."

> "Over time I've begun to regard spotting anomalies as the single most important skill
> for finding race conditions."

**Consecuencia operativa:** sin linea base no hay anomalia que ver. El benchmark no es
un paso opcional de rigor: es el instrumento de deteccion.

---

# 1 — Arbol de decision (coste creciente)

## Paso 1 — Predecir colisiones (coste: 0 peticiones)
Las tres preguntas literales de la fuente:

> "1) How is the state stored?"
> "2) Are we editing or appending?"
> "3) What's the operation keyed on?"

Y la condicion de colision: *"we need two operations that use the same key."*

Esto es analisis puro y no cuesta nada. Hacerlo antes de tocar el objetivo.

## Paso 2 — ¿Soporta HTTP/2? (coste: 1 peticion)
Cita literal sobre por que importa: *"This is a novel possibility with HTTP/2 because it
allows HTTP requests to be sent over a single connection concurrently, whereas in
HTTP/1.1 they have to be sequential."*

- **Sin HTTP/2** -> last-byte sync. Medidas de la fuente: dispersion mediana 4ms y
  desviacion 3ms, frente a 1ms y 0,3ms del single-packet attack. Con ventanas de ~1ms,
  puede no bastar.

## Paso 3 — BENCHMARK (coste: n peticiones) — obligatorio
> "benchmark how the endpoints behave under normal conditions by sending your
> request-blend with a few seconds between each request."

Anotar: codigos de estado, cuerpos, **tiempos de proceso**, y efectos laterales
(correos, notificaciones, contadores).

**No saltar este paso.** Es el que convierte respuestas en datos.

## Paso 4 — Single-packet attack (coste: n peticiones)
Procedimiento literal de la fuente:

1. Sin cuerpo: enviar todas las cabeceras **sin** el flag `END_STREAM`; retener un data
   frame vacio con `END_STREAM`. Con cuerpo: enviar todo menos el **ultimo byte**.
   Aviso: no enviar el cuerpo completo confiando en omitir `END_STREAM` — algunas
   implementaciones usan `content-length` para decidir que el mensaje acabo.
2. Esperar 100ms. Asegurar `TCP_NODELAY` **desactivado** (hace falta Nagle). Enviar un
   ping para calentar la conexion local.
3. Enviar los frames retenidos. Verificar en Wireshark que fueron **un** paquete.

Implementacion: Turbo Intruder, plantilla `single-packet-attack`. En Repeater, la
opcion **"Send group in parallel"**.

## Paso 5 — Leer las pistas (coste: 0 peticiones)
Cualquier desviacion respecto al benchmark. Guia literal de la fuente sobre tiempos:

- **mas corto de lo esperado** -> los datos pasan a otro hilo: *"greatly increasing the
  chances of a vulnerability"*
- **mas largo de lo esperado** -> limites de recursos, o locking para evitar
  concurrencia

Nota critica de la fuente: **PHP bloquea por `sessionid` por defecto**, asi que hace
falta una sesion distinta por peticion del lote o el lote se procesa secuencialmente y
no hay concurrencia real.

Patron contraintuitivo que conviene conocer (caso GitLab): el lote simultaneo dio
**menos** respuestas de exito y **mas** efecto real — 1 exito y 5 "ya tomado", pero 2
correos en lugar de 1. Cinco rechazos parecen el limite funcionando bien. Solo el
contraste con la linea base revela el correo extra.

## Paso 6 — Reducir y probar el concepto (coste: medio)
> "you'll want to eliminate all unnecessary requests - two should be sufficient for
> exploiting most vulnerabilities."

## Paso 7 — Carreras diferidas (coste: muy alto)
> "It's a mistake to think that an immediate collision is guaranteed - websites may do
> critical data processing in batches periodically behind the scenes."

La fuente documenta un caso donde las dos peticiones en conflicto podian ir separadas
**20 minutos**. La deteccion depende de pistas de segundo orden: comportamiento
cambiado o correos incoherentes **mas tarde**.

---

# 2 — Trampas de falso positivo

**1. Locking leido como vulnerabilidad.** Aviso literal de la fuente: *"it's important
not to attribute inconsistent request timing to application behavior such as locking
mechanisms that only allow a single thread to access a resource at once."* Señal de
muerte: los tiempos son **mas largos** de lo esperado de forma consistente — eso apunta
a locking o a limites de recursos, no a una ventana.

**2. Jitter de red leido como señal.** Señal de muerte: no se ha medido la varianza
normal repitiendo la linea base. Interpretar jitter como señal no da un resultado
dudoso: da una conclusion coherente y falsa.

**3. Serializacion por sesion de PHP.** El lote parece no tener efecto porque se
proceso en serie. Señal de muerte: todas las peticiones del lote comparten
`sessionid`. Repetir con una sesion por peticion antes de concluir.

---

# 3 — Cuándo esta skill NO es la correcta

- Lo que discrepa son **dos parsers HTTP** y no dos operaciones concurrentes
  -> `skill:desync-triage`
- El fallo es de orden de pasos y no de concurrencia (un descuento que sobrevive a
  vaciar la cesta): es logica de negocio -> `writeups/logica-negocio/`
- El objetivo valida una direccion de correo ajena por discrepancia de parser y no por
  colision temporal -> `writeups/auth/` (familia de email parser)
- No se puede identificar ninguna operacion con clave compartida en el paso 1: sin
  colision posible, no hay carrera. Parar ahi y no gastar peticiones.

---

# 4 — Output

Escribir en `evidencias/race-window-<slug>.md`:

- las tres preguntas del paso 1, respondidas para este objetivo
- HTTP/2 si o no, y tecnica elegida en consecuencia
- **la linea base completa**: estados, cuerpos, tiempos y efectos laterales
- resultado del lote simultaneo, en la misma tabla que la linea base
- la desviacion concreta identificada como pista
- si el objetivo es PHP: confirmacion de una sesion por peticion
- verificacion en Wireshark de que los frames finales fueron un paquete
- las tres trampas, con resultado

Sin linea base, el informe no esta terminado: no hay con qué comparar.
