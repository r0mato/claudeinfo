---
clase: xss
tech: html-hidden-until-found
cwe: CWE-79
cvss: 6.1 # [derivado] reflejado; solo Firefox segun la fuente
payload: |
  # Firefox: SI. Chrome: NO. Safari: NO. (segun los iconos de la pagina fuente)
  # Ejecuta sobre un input OCULTO: el handler no necesita elemento visible.
  <input type=hidden id=x onbeforematch=alert(1) hidden=until-found>
precondicion: "Inyeccion de etiqueta HTML con atributos arbitrarios. El valor de atributo 'hidden=until-found' es la pieza clave: marca el elemento como oculto-pero-buscable, de modo que el navegador lo revela (y emite 'beforematch') al encontrarlo. Segun la fuente solo funciona en Firefox. No requiere interaccion mas alla de la navegacion normal."
como_se_descubre: |
  Señal en recon: sinks que escriben en campos `type=hidden`. Es un sitio donde los
  revisores suelen asumir que no hay riesgo porque "el elemento no se ve", y por eso
  el escapado a veces es mas laxo ahi que en el cuerpo visible. Prueba barata:
  inyectar `hidden=until-found` en un input oculto y comprobar si el atributo
  sobrevive al sanitizador.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: <input type=hidden id=x onbeforematch=alert(1) hidden=until-found>  -> ejecuta en Firefox
  # B: <input type=hidden id=x onbeforematch=alert(1)>   (sin hidden=until-found)
  #    -> NO ejecuta: sin el modo until-found el evento beforematch nunca se emite
  # Control de navegador obligatorio ademas del A/B: repetir A en Chrome.
  # Si tambien ejecuta en Chrome, NO es este vector: hay otro sink en juego.
mata: |
  - El sink codifica `<` y `>` -> muere.
  - Victima en Chrome o Safari -> no ejecuta (limitacion de motor, no del filtro).
  - El sanitizador normaliza o elimina el atributo 'hidden'.
  - CSP sin 'unsafe-inline'.
fuente: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet (PortSwigger XSS cheat sheet; pagina actualizada 2026-10-21). Bajo 'Event handlers that do not require user interaction'."
confianza: alta
fecha: 2026-11-02
---
# [XSS] `onbeforematch` + `hidden=until-found` — ejecución desde un campo oculto (solo Firefox)

## Principio
`hidden=until-found` es un valor de `hidden` que mantiene el elemento oculto pero
localizable por la búsqueda del navegador y por navegación a fragmento. Cuando el
navegador lo revela, emite `beforematch`. El resultado rompe una suposición común: un
elemento **oculto** puede ser un sink de ejecución, así que `type=hidden` no es una
zona segura.

## Payload
```html
<input type=hidden id=x onbeforematch=alert(1) hidden=until-found>
```

Según la fuente, funciona en **Firefox** y no en Chrome ni Safari. Eso lo convierte en
un vector situacional, no de primera elección — pero sigue siendo el que hay que
probar cuando el sink es un campo oculto y los demás fallan.

## Impacto
XSS en el origen, con la particularidad de alcanzar sinks que un escaneo automático y
una revisión manual suelen pasar por alto. El valor real para un hunter es el sitio
donde vive: los campos `hidden` acumulan datos reflejados (tokens de retorno, IDs de
formulario, URLs previas) y a menudo tienen un escapado más débil que el cuerpo
visible porque nadie espera ejecución desde ahí.

## Remediación
Codificar `<` y `>` en salida HTML en **todos** los contextos, incluidos los valores de
atributos de campos ocultos. `# [derivado]`: la lección de diseño es que la política
de escapado no debe depender de si el elemento se ve; la visibilidad no es un control
de seguridad. Allowlist de atributos que excluya `hidden` con valor arbitrario y todo
`on*`.
