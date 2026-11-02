---
clase: info-disclosure
tech: performance-api
cwe: CWE-208
cvss: 5.3 # [derivado] inferencia del rol o del historial de la victima
payload: |
  # CODIGO LITERAL de la fuente, reproducido TAL CUAL. Notese que los backticks del
  # principio y del final estan en el original, y que THRESHOLD NUNCA recibe valor:
      `// Illustrative timing threshold for this measurement context     // const THRESHOLD = ...      const adminImagePerfEntry = window.performance         .getEntriesByType('resource')         .find((entry) => entry.name.endsWith('admin.svg'));      if (adminImagePerfEntry && adminImagePerfEntry.duration < THRESHOLD) {         console.log('Possible cache hit (timing heuristic)');     }`
  #
  # ADVERTENCIA: el snippet NO es ejecutable como esta. 'THRESHOLD' se deja sin
  # asignar en la propia fuente y la pagina admite en prosa que una duracion corta
  # por si sola NO prueba un acierto de cache. Lo reproduzco literal, con el defecto
  # incluido, en lugar de inventar un valor.
  #
  # DEFENSA 1 - token impredecible, URL LITERAL de la fuente:
  /avatars/admin.svg?token=be930b8cfb5011eb9a030242ac130003
  # La fuente dice que los tokens deben ser 'unique in context of each user'.
  #
  # DEFENSA 2 - cabecera LITERAL de la fuente (la unica linea de cabecera completa
  # que aparece en toda la pagina):
  Cache-Control: no-store
precondicion: "El atacante puede incrustar un recurso que solo un administrador puede ver (el ejemplo de la fuente es 'admin.svg'), y ese recurso debe estar CACHEADO para que su tiempo de carga difiera del de una descarga del servidor. La inferencia es: si esta en cache, la victima lo ha visto antes, luego la victima es administradora."
como_se_descubre: |
  Señal en recon: recursos estaticos cuya URL es PREDECIBLE y cuya visibilidad depende
  del rol (iconos, avatares, hojas de estilo o imagenes exclusivas del panel de
  administracion). La combinacion 'URL adivinable + visible solo para un rol' es la
  precondicion completa.
  El canal es la Performance API, que expone el tiempo de carga de recursos del propio
  documento del atacante, incluidos los de otros origenes.
control_negativo: |
  # [derivado] el control es OBLIGATORIO aqui, porque la propia fuente advierte de que
  # una duracion corta no prueba nada por si sola.
  # A: medir el recurso tras forzar que este en cache (visitarlo primero)
  #    -> duracion de referencia para 'acierto de cache'
  # B: medir el mismo recurso con la cache limpia
  #    -> duracion de referencia para 'fallo de cache'
  # C: repetir A y B varias veces y comparar las DISTRIBUCIONES, no valores sueltos
  # Solo si A y B dan distribuciones separadas existe el oraculo, y solo entonces
  # tiene sentido elegir un THRESHOLD, que debe salir de esas medidas y no de una
  # constante inventada.
mata: |
  - 'Cache-Control: no-store' en el recurso -> no hay cache que sondear.
  - Token impredecible y por usuario en la URL -> el atacante no puede nombrar el recurso.
  - Las distribuciones de A y B se solapan (ver control C) -> sin oraculo fiable.
  - El recurso lo ven todos los roles -> la inferencia no distingue nada.
fuente: "https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html (seccion 'Attacks using browser cache'). Snippet, URL con token y la cabecera Cache-Control son literales de la pagina, incluidos los backticks sobrantes y el THRESHOLD sin asignar. Contenido CC BY-SA 4.0."
confianza: media
fecha: 2026-11-02
---
# [INFO-DISCLOSURE] Sondeo de caché con la Performance API — inferir el rol por el tiempo de carga

## Principio
Si un recurso solo lo ve un administrador, el hecho de que esté en la caché del
navegador de la víctima dice que la víctima es administradora. No hace falta leer el
recurso: basta medir cuánto tarda en cargar, porque un acierto de caché es más rápido
que una descarga. La Performance API expone esa duración, incluso para recursos de otro
origen.

## Payload
Reproducido literal de la fuente, con sus defectos incluidos:

```javascript
    `// Illustrative timing threshold for this measurement context     // const THRESHOLD = ...      const adminImagePerfEntry = window.performance         .getEntriesByType('resource')         .find((entry) => entry.name.endsWith('admin.svg'));      if (adminImagePerfEntry && adminImagePerfEntry.duration < THRESHOLD) {         console.log('Possible cache hit (timing heuristic)');     }`
```

## Advertencia honesta sobre este snippet
No es ejecutable tal como está. Los backticks del principio y del final están en el
original, y `THRESHOLD` **nunca recibe valor** — la propia fuente lo deja como comentario
sin asignar. Y la página admite en prosa que una duración corta, por sí sola, no prueba
un acierto de caché.

Lo reproduzco con el defecto incluido en lugar de inventar un umbral, porque un umbral
inventado sería peor que ninguno: daría la apariencia de un payload calibrado cuando el
valor correcto depende por completo del objetivo, de la red y del momento. Es la razón
de `confianza: media`.

## El umbral hay que medirlo, no elegirlo
Aquí el control negativo no es una comprobación opcional: es **el procedimiento de
calibración**. Hay que medir el recurso con caché caliente y con caché limpia, varias
veces, y comparar las distribuciones, no valores sueltos. Si se solapan, no hay oráculo
y da igual el umbral que se ponga. Si se separan, el umbral sale de esas medidas.

Un umbral tomado de un ejemplo ajeno produce exactamente el fallo del writeup de
retardos SQL: una inferencia que parece coherente y es ruido.

## Impacto
Determinar desde un sitio arbitrario el rol de quien lo visita, o si ha visitado antes
ciertas páginas de otro servicio. Es desanonimización y perfilado entre orígenes, y
funciona sin ninguna interacción más allá de cargar la página del atacante.

## Remediación
La única línea de cabecera completa que aparece en toda la página fuente:

```
Cache-Control: no-store
```

La fuente dice explícitamente *"set the response header `Cache-Control: no-store`"*.

Y la alternativa, cuando se quiere conservar el cacheo: token impredecible en la URL,
que la fuente indica debe ser *"unique in context of each user"*:

```
/avatars/admin.svg?token=be930b8cfb5011eb9a030242ac130003
```

`# [derivado]`: la condición que de verdad habilita el ataque es que el atacante pueda
**nombrar** el recurso. Un token por usuario la elimina sin renunciar a la caché, lo que
suele ser preferible a `no-store` en recursos estáticos grandes.
