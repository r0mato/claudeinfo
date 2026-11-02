---
clase: xss
tech: html-body
cwe: CWE-79
cvss: 6.1 # [derivado] reflejado en contexto HTML
payload: |
  # onload - el clasico. Chrome/Firefox/Safari: SI.
  <body onload=alert(1)>

  # onhashchange - dispara al cambiar el fragmento. Chrome/Firefox/Safari: SI.
  <body onhashchange="print()">

  # onbeforeprint - Chrome: SI. Firefox: SI. Safari: NO.
  <body onbeforeprint=console.log(1)>

  # onmessage - dispara al recibir un postMessage. Chrome: SI. Firefox: SI.
  <body onmessage=print()>
precondicion: "El sink permite inyectar una etiqueta <body>, o bien la inyeccion ocurre antes de que el parser abra el body (los handlers de <body> se aplican aunque la etiqueta aparezca duplicada: el parser fusiona los atributos en el body existente). 'onhashchange' requiere ademas que algo cambie el fragmento; 'onmessage' requiere que llegue un postMessage."
como_se_descubre: |
  Señal en recon: inyeccion en una zona temprana del documento (titulo, meta, bloque
  de cabecera) donde `<body onload=...>` se fusiona con el body real. Para
  `onhashchange` la señal es una aplicacion que ya usa el fragmento para navegar
  (SPA, anclas): el disparador llega gratis con la navegacion normal del usuario.
  Para `onmessage`, la señal es una pagina que ya recibe postMessage de un iframe
  propio.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: <body onhashchange="print()">  y luego navegar a  #cualquiercosa  -> ejecuta
  # B: <body onhashchange="print()">  sin cambiar nunca el fragmento      -> NO ejecuta
  # El par confirma que el disparador es el cambio de hash y no la carga.
  # Importante al reportar: con onload el PoC es autonomo; con onhashchange hay que
  # incluir el cambio de fragmento en el enlace del PoC o el triador vera 'no ejecuta'.
mata: |
  - El sink codifica `<` y `>` -> muere.
  - Sanitizador que elimine atributos on* -> muere.
  - CSP sin 'unsafe-inline'.
  - Para onhashchange/onmessage: no existe el disparador en el flujo real de la app
    -> el PoC necesita que la victima haga algo, lo que baja la severidad.
fuente: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet (PortSwigger XSS cheat sheet; pagina actualizada 2026-10-21). Bajo 'Event handlers that do not require user interaction'."
confianza: alta
fecha: 2026-11-02
---
# [XSS] Handlers globales en `<body>` — `onload`, `onhashchange`, `onbeforeprint`, `onmessage`

## Principio
`<body>` concentra los eventos de ciclo de vida del documento. Lo que hace a esta
familia útil no es la novedad —`onload` es el vector más antiguo del catálogo— sino que
los atributos de un `<body>` inyectado **se fusionan con el body real** en vez de
crear un segundo body. Eso permite colocar el handler desde una inyección situada
antes del cuerpo del documento.

## Payload
```html
<body onload=alert(1)>
```

Tres variantes con disparadores distintos, útiles cuando `onload` está en lista negra:

```html
<body onhashchange="print()">
```

```html
<body onbeforeprint=console.log(1)>
```

```html
<body onmessage=print()>
```

Según la fuente, `onbeforeprint` no funciona en Safari; `onload` y `onhashchange`
funcionan en los tres motores.

## Impacto
XSS estándar en el origen. La distinción operativa está en la autonomía del PoC:
`onload` ejecuta solo con cargar la URL, mientras `onhashchange` y `onmessage`
necesitan un disparador adicional. Eso **cambia cómo hay que escribir el reporte**: si
el PoC de `onhashchange` no incluye el cambio de fragmento en el propio enlace, el
triador probará la URL, no verá nada y cerrará el informe.

## Remediación
Codificar `<` y `>` en salida HTML. `# [derivado]`: eliminar todo atributo `on*` con
independencia de la etiqueta, y no asumir que una inyección fuera del `<body>` es
inocua — el parser fusiona atributos de `<body>` duplicados, así que la posición en el
documento no limita el alcance. CSP sin `unsafe-inline` como segunda capa.
