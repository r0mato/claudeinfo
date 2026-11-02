---
name: desync-triage
description: Triaje de desincronizacion HTTP/1.1 (CL.TE, CL.0, 0.CL, Expect) sobre arquitecturas con front-end y back-end. Decide si existe discrepancia de parser y si es explotable.
model: claude-opus-5
---

# 0 — SEÑAL CITADA

> "HTTP/1.1 must die: the desync endgame" — James Kettle, PortSwigger, 2025-08-06.
> El articulo sostiene que el request smuggling es **un defecto fundamental del
> protocolo**, no un conjunto de bugs que parchear uno a uno.

Señal literal de deteccion de alto riesgo que da la fuente:

```
POST / HTTP/1.1\r\n Content-Length: 22\r\n A: B\r\n \nExpect: 100-continue\r\n
```

Y la afirmacion que justifica probar `Expect` siempre, aunque no haya nada raro:

> "Simply sending a valid Expect header causes a 0.CL desync on numerous different
> servers."

Precondicion estructural de TODA la clase: **dos parsers HTTP en el camino que
discrepan**. Sin dos capas, no hay desync. La fuente declara que todos sus casos se
probaron sobre objetivos con VDP y testeo autorizado.

---

# 1 — Arbol de decision (coste creciente)

## Paso 1 — ¿Hay dos capas? (coste: 1 peticion)
Mirar cabeceras de respuesta: `Via`, `Server`, `X-Cache`, `Cf-*`, `X-Akamai-*`,
`X-Nf-*`, `awselb/2.0`, `Microsoft-HTTPAPI`.

- **Una sola capa** -> PARAR. No hay desync posible.
- **Dos o mas capas** -> seguir.

## Paso 2 — ¿Se reutiliza la conexion upstream? (coste: 2 peticiones)
Sin reutilizacion entre clientes solo hay self-desync: no hay victima y el impacto
cae a casi nada. Comprobar `Connection: keep-alive` y si dos peticiones consecutivas
comparten conexion de salida.

- **Sin reutilizacion** -> reportable como discrepancia de parser, NO como robo de
  sesiones. Ajustar la severidad del informe aqui, no al final.

## Paso 3 — Sonda de discrepancia V-H / H-V (coste: 4 peticiones)
Enviar los cuatro pares que la fuente usa y comparar los codigos de estado:

```
Host: x/x      ->  ?
Xost: x/x      ->  ?
Host : foo/bar ->  ?
Xost : foo/bar ->  ?
```

Patron de la fuente que indica discrepancia (caso IIS tras ALB):
`Host: foo/bar` da 400 con `Server: Microsoft-HTTPAPI/2.0`, y `Xost: foo/bar` da 200
sin cabecera de servidor. Dos capas respondiendo = dos parsers.

- **Las cuatro respuestas identicas** -> sin discrepancia por esta via; ir al paso 4.

## Paso 4 — Sonda Expect, vanilla y ofuscada (coste: 4 peticiones)
Esta es la de mejor rendimiento y la que mas se olvida. Enviar `Content-Length`
declarado y NO enviar cuerpo:

```
Expect: 100-continue        # vanilla   (caso T-Mobile)
Expect: y 100-continue      # ofuscada  (caso GitLab)
```

Firma del 0.CL: el front-end responde **de inmediato** con un estado distinto de 100
en lugar de bloquearse esperando el cuerpo.

- **Responde 100 y espera** -> comportamiento correcto.
- **Responde != 100 sin esperar** -> 0.CL. Seguir al paso 5.
- **Vanilla no y ofuscada si** -> reportar la ofuscacion como causa; la remediacion es
  distinta (normalizar `Expect` en el borde).

## Paso 5 — ¿Hay gadget de respuesta temprana? (coste: 5-10 peticiones)
Un 0.CL sin gadget acaba en deadlock de la conexion upstream y no es explotable.
Definicion literal de la fuente: *"a way to make the back-end server respond to a
request without waiting for the body to arrive."*

Gadgets conocidos, de la fuente:
- `/con` en IIS
- redirecciones a nivel de servidor en otros servidores
- la fuente dice que **nunca encontro un gadget viable para Apache**

- **Sin gadget** -> PARAR y reportar el deadlock como discrepancia de parser.

## Paso 6 — Doble desync: convertir 0.CL en CL.0 (coste: alto, muchas peticiones)
Solo con gadget confirmado. Nota util de la fuente: *"Most servers insert headers at
the end of the header block, not at the start."*

## Paso 7 — Response Queue Poisoning (coste: muy alto)
La fuente advierte que RQP *"is tricky on low-traffic targets due to an inherent race
condition"*: su equipo envio del orden de **27.000 peticiones**.

- **Objetivo de poco trafico** -> NO insistir. Reportar la discrepancia, no la
  explotacion. Un desync confirmado sin ventana practica sigue siendo el mismo fallo.

---

# 2 — Trampas de falso positivo

**1. Timeout leido como desync.** Un 504 tras una sonda 0.CL parece exito y suele ser
el deadlock del paso 5, no una explotacion. Señal de muerte: el 504 llega **siempre**,
tambien sin la segunda peticion embebida.

**2. Caché leida como envenenamiento.** Una respuesta ajena puede venir de la caché y
no de la cola de respuestas. Señal de muerte: la respuesta se repite en una **conexion
nueva** con `Cache-Control: no-cache`. Si persiste, es caché.

**3. Reconstruccion de CRLF tomada por literal.** El render HTML de las fuentes
colapsa los saltos de linea en los bloques de codigo. Un payload copiado de un render
**no es byte-exacto** y su fallo no prueba nada sobre el objetivo. Señal de muerte: el
payload falla y no se ha verificado la estructura de lineas contra la fuente original.

---

# 3 — Cuándo esta skill NO es la correcta

- El objetivo habla **HTTP/2 extremo a extremo** sin degradacion: la clase no aplica.
  La recomendacion de la propia fuente es justamente migrar a HTTP/2 upstream.
- Lo que se busca es una **condicion de carrera** y no una discrepancia de parser
  -> `skill:race-window`
- La sonda `Expect` devuelve cabeceras internas en lugar de desincronizar: es fuga de
  informacion -> ver `writeups/protocolo/` (caso Netlify) y `skill:ssrf-escalation`
  si esas cabeceras revelan infraestructura interna.
- Hay una sola capa HTTP: no hay dos parsers que discrepen. Parar en el paso 1.

---

# 4 — Output

Escribir en `evidencias/desync-triage-<slug>.md`:

- paso del arbol alcanzado y por que se paro ahi
- las cuatro respuestas de la sonda V-H/H-V, literales
- resultado de la sonda `Expect` vanilla y ofuscada
- gadget encontrado, o constancia de que no hay
- si hay o no reutilizacion de conexion upstream (decide la severidad)
- los tres controles de falso positivo, con su resultado

Sin el apartado de falsos positivos, el informe no esta terminado.
