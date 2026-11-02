---
clase: xss
tech: webvtt-track
cwe: CWE-79
cvss: 6.1 # [derivado] reflejado; solo Chrome segun la fuente
payload: |
  # Chrome: SI. Firefox: NO. Safari: NO. (segun los iconos de la pagina fuente)
  # El subtitulo se entrega como data: URI, asi que no hace falta alojar un .vtt.
  # ADVERTENCIA DE FIDELIDAD: la pagina fuente muestra ESPACIOS dentro del data URI,
  # pero el enlace de PoC de la propia pagina codifica saltos de linea como %0A.
  # El formato WebVTT REQUIERE saltos de linea reales. Verificar contra la fuente
  # antes de usar: lo de abajo es lo que muestra el render, no necesariamente los bytes.
  <video controls><source src=validvideo.mp4 type=video/mp4><track default oncuechange=alert(1) src="data:text/vtt,WEBVTT FILE 1 00:00:00.000 --> 00:00:05.000 <b>XSS</b> "></video>
precondicion: "Inyeccion de HTML que admita <video> y <track>. Requiere un video reproducible alcanzable (el <source> debe cargar) para que la pista de subtitulos llegue a activarse. Solo Chrome. El 'default' en <track> es necesario para que la pista se active sin que el usuario la elija."
como_se_descubre: |
  Señal en recon: aplicaciones que renderizan video embebido con subtitulos a partir
  de datos del usuario (plataformas de contenido, LMS, herramientas de soporte que
  incrustan grabaciones). Es un vector de nicho: solo merece la pena cuando el
  objetivo ya maneja `<video>` y el filtro cubre los sinks comunes.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: <track default oncuechange=...> con <source> VALIDO      -> ejecuta en Chrome
  # B: el mismo <track> sin <source> valido (el video no carga) -> NO ejecuta
  # El par confirma que la dependencia es la reproduccion real del medio.
  # Control de navegador obligatorio: repetir A en Firefox (no debe ejecutar).
mata: |
  - El sink codifica `<` y `>` -> muere.
  - Victima en Firefox o Safari -> no ejecuta.
  - No hay video reproducible alcanzable -> el evento nunca llega.
  - Sanitizador con allowlist que excluya <track> (comun, por ser etiqueta poco usada).
  - CSP sin 'unsafe-inline'; ademas, una CSP con media-src/default-src restrictivo
    puede bloquear el data: URI del subtitulo.
fuente: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet (PortSwigger XSS cheat sheet; pagina actualizada 2026-10-21). Bajo 'Event handlers that do not require user interaction'."
confianza: media
fecha: 2026-11-02
---
# [XSS] `oncuechange` en pista WebVTT entregada como `data:` URI (solo Chrome)

## Principio
Un elemento `<track>` carga subtítulos, y cada cambio de cue emite un evento. Lo
interesante es que la pista puede entregarse **inline como `data:` URI**, así que el
vector no necesita alojar ningún fichero externo: todo el payload viaja en el atributo.

## Payload
```html
<video controls><source src=validvideo.mp4 type=video/mp4><track default oncuechange=alert(1) src="data:text/vtt,WEBVTT FILE 1 00:00:00.000 --> 00:00:05.000 <b>XSS</b> "></video>
```

`default` en `<track>` es lo que activa la pista sin que el usuario la seleccione.

## Advertencia de fidelidad
Este es el único vector del conjunto donde **no puedo garantizar los bytes exactos**.
El render de la página fuente muestra espacios dentro del `data:` URI, pero el enlace
de prueba de la propia página codifica saltos de línea como `%0A` — y el formato WebVTT
exige saltos de línea reales entre la cabecera, el número de cue y la marca de tiempo.
Con espacios en lugar de saltos, es probable que la pista no parsee. Hay que
verificarlo contra la fuente antes de usarlo. Por eso `confianza: media` mientras los
demás vectores de este lote van como `alta`.

## Impacto
XSS en el origen, limitado a Chrome y a objetivos que ya reproduzcan vídeo. Es un
vector de último recurso: se prueba cuando el objetivo maneja `<video>` y los sinks
comunes están cubiertos.

## Remediación
Codificar `<` y `>` en salida HTML. `# [derivado]`: incluir `<track>` en el conjunto de
etiquetas que el sanitizador elimina —suele faltar en las allowlist por ser poco
usada— y restringir `media-src` en la CSP para que un `data:` URI no pueda aportar la
pista. Eliminar todo atributo `on*`.
