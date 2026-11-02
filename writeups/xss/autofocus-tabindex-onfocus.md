---
clase: xss
tech: html-focus
cwe: CWE-79
cvss: 6.1 # [derivado] reflejado en contexto HTML
payload: |
  # El navegador enfoca el elemento automaticamente: no hay interaccion.
  # Chrome/Firefox/Safari: SI.
  <xss onfocus=alert(1) autofocus tabindex=1>

  # Variante sobre <a>, requiere tabindex para ser enfocable.
  # Chrome/Firefox/Safari: SI.
  <a id=x tabindex=1 onfocus=alert(1)></a>

  # onfocusin, misma mecanica, handler distinto (util si 'onfocus' esta en lista negra).
  # Chrome/Firefox/Safari: SI.
  <a id=x tabindex=1 onfocusin=alert(1)></a>
precondicion: "Inyeccion de etiqueta HTML con atributos arbitrarios. Para la ejecucion automatica hacen falta LOS DOS atributos: 'autofocus' (pide el foco al cargar) y 'tabindex' (hace el elemento enfocable). Un elemento no enfocable ignora autofocus. No requiere que la etiqueta sea de formulario: funciona sobre etiquetas inventadas."
como_se_descubre: |
  Señal en recon: el filtro permite atributos pero bloquea los handlers de raton
  (`onclick`, `onmouseover`) asumiendo que sin interaccion no hay riesgo. `autofocus`
  rompe esa suposicion. Prueba barata: inyectar `<xss autofocus tabindex=1>` y
  comprobar en el DOM si ambos atributos sobreviven; si lo hacen, solo falta el handler.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: <xss onfocus=alert(1) autofocus tabindex=1>   -> ejecuta solo al cargar
  # B: <xss onfocus=alert(1) autofocus>              (SIN tabindex)
  #    -> NO ejecuta: el elemento no es enfocable, autofocus se ignora
  # El par demuestra que tabindex es la pieza necesaria, no un adorno. Si B ejecuta,
  # la etiqueta ya era enfocable por si misma (input, a[href], button) y el hallazgo
  # se clasifica distinto.
mata: |
  - El sink codifica `<` y `>` -> muere.
  - El sanitizador elimina `autofocus` o `tabindex` -> queda XSS que requiere interaccion
    (degrada el impacto, no lo elimina).
  - CSP sin 'unsafe-inline'.
  - Ya hay otro elemento con autofocus antes en el DOM: solo el primero gana el foco.
fuente: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet (PortSwigger XSS cheat sheet; pagina actualizada 2026-10-21). Descripcion literal de la pagina para onfocus(autofocus): 'Fires when a element has focus and the autofocus attribute is used to focus automatically.'"
confianza: alta
fecha: 2026-11-02
---
# [XSS] `autofocus` + `tabindex` convierte un handler de interacción en ejecución automática

## Principio
Muchos filtros tratan los handlers de foco como de bajo riesgo porque "necesitan que
el usuario haga algo". `autofocus` elimina ese requisito: le pide al navegador que
enfoque el elemento en cuanto se carga. El detalle que suele faltar es que `autofocus`
solo surte efecto sobre un elemento **enfocable**, y una etiqueta inventada no lo es
por defecto — de ahí que haga falta `tabindex`.

## Payload
```html
<xss onfocus=alert(1) autofocus tabindex=1>
```

Los tres atributos cumplen un papel distinto y ninguno es prescindible: `onfocus` es
el sink, `autofocus` quita la interacción y `tabindex` hace que el elemento pueda
recibir foco. Quitar `tabindex` desactiva el vector (ver control negativo).

Sobre una etiqueta real, por si `<xss>` no sobrevive al sanitizador:

```html
<a id=x tabindex=1 onfocus=alert(1)></a>
```

Si `onfocus` está en lista negra, `onfocusin` tiene la misma mecánica y suele faltar
en las listas:

```html
<a id=x tabindex=1 onfocusin=alert(1)></a>
```

## Impacto
Convierte un XSS que un triador podría cerrar como "requiere interacción del usuario"
en uno que dispara con solo cargar la página — lo que cambia la severidad reportable,
no solo la comodidad del exploit. Sobre un sink almacenado, afecta a todo visitante
sin cebo alguno.

## Remediación
Codificar `<` y `>` en salida HTML. `# [derivado]`: si el sanitizador mantiene
allowlist de atributos, `autofocus` y `tabindex` deben estar fuera de ella aun cuando
se consideren inocuos por separado — su valor para el atacante está en la combinación.
Eliminar todo atributo `on*` sigue siendo la regla principal.

## Nota de triaje
`onfocusin` y `onfocus` se reportan por separado cuando la lista negra solo contiene
uno: la existencia de un alias no bloqueado es en sí misma la debilidad del filtro, y
conviene decirlo en el reporte para que la corrección no se limite al nombre que se
demostró.
