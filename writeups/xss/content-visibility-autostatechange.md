---
clase: xss
tech: css-content-visibility
cwe: CWE-79
cvss: 6.1 # [derivado] reflejado en contexto HTML
payload: |
  # Sobre etiqueta inventada. Chrome/Firefox/Safari: SI.
  <xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:auto>

  # Sobre un input OCULTO. Chrome/Firefox/Safari: SI.
  # Notese que aqui NO hace falta display:block.
  <input type=hidden oncontentvisibilityautostatechange=alert(1) style=content-visibility:auto>
precondicion: "Inyeccion de etiqueta con atributo 'style' superviviente. 'content-visibility:auto' delega al navegador la decision de renderizar el contenido, y cada cambio de ese estado emite el evento. En la variante sobre etiqueta inventada hace falta ademas 'display:block' para que el elemento genere caja; en la variante sobre input type=hidden no."
como_se_descubre: |
  Señal en recon: el mismo perfil que los eventos de animacion — filtro que deja pasar
  `style` y no conoce los nombres de handler modernos. El nombre del atributo es muy
  largo (`oncontentvisibilityautostatechange`), asi que es un buen test de si el
  filtro usa una lista negra de nombres concretos o un patron `^on`: si bloquea
  `onerror` pero deja pasar este, la lista es enumerada y habra mas huecos.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: <xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:auto>
  #    -> ejecuta
  # B: mismo payload con style=display:block  (SIN content-visibility:auto)
  #    -> NO ejecuta: sin el modo auto no hay cambio de estado que notificar
  # El par demuestra que la propiedad CSS es la condicion, no el handler.
mata: |
  - El sink codifica `<` y `>` -> muere.
  - El sanitizador elimina el atributo 'style' -> muere (es la dependencia real).
  - CSP sin 'unsafe-inline'.
  - Filtro que bloquee por patron `^on` en lugar de lista negra enumerada.
fuente: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet (PortSwigger XSS cheat sheet; pagina actualizada 2026-10-21). Bajo 'Event handlers that do not require user interaction'."
confianza: alta
fecha: 2026-11-02
---
# [XSS] `oncontentvisibilityautostatechange` — el renderizado perezoso del navegador como disparador

## Principio
`content-visibility: auto` le dice al navegador que decida por su cuenta si renderiza
el contenido de un elemento, según entre o salga del área relevante. Cada vez que esa
decisión cambia, se emite un evento con handler inline. Es decir: una optimización de
rendimiento es también un sink de ejecución, y uno que las listas negras heredadas
raramente contemplan por su nombre.

## Payload
```html
<xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:auto>
```

La variante sobre un campo oculto, que no necesita `display:block`:

```html
<input type=hidden oncontentvisibilityautostatechange=alert(1) style=content-visibility:auto>
```

Las dos funcionan en Chrome, Firefox y Safari según la fuente.

## Impacto
XSS en el origen sin interacción. Su utilidad táctica es doble: funciona en los tres
motores, y su nombre de evento es lo bastante reciente y largo como para faltar en
cualquier lista negra escrita a mano. La variante sobre `input type=hidden` repite la
lección del vector `onbeforematch`: los campos ocultos ejecutan.

## Remediación
Codificar `<` y `>` en salida HTML. `# [derivado]`: la conclusión de diseño que vale
más que el vector concreto es que **las listas negras de nombres de evento son
insostenibles** — la plataforma web añade eventos nuevos continuamente y cada uno es
un hueco. Hay que filtrar por patrón (`^on` sobre cualquier atributo) o, mejor, usar
allowlist de atributos. CSP sin `unsafe-inline` como segunda capa.
