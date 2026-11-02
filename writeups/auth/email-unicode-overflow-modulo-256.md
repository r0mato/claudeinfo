---
clase: auth
tech: php-chr-unicode
cwe: CWE-20
cvss: 5.3 # [derivado] la fuente indica que por si solo NO permitio partir la direccion
payload: |
  # Mecanica LITERAL de la fuente (codigo JS que ilustra la equivalencia):
  String.fromCodePoint(0x100 + 0x40)    // ŀ -> @
  String.fromCodePoint(0x1000 + 0x40)   // ၀ -> @
  String.fromCodePoint(0x10000 + 0x40)  // 𐁀 -> @
  # Limite superior citado: 0x10ffff
  #
  # Equivalencias LITERALES que da la fuente:
  '✨' === '('
  '✩' === ')'
  '✻' === ';'
  '✼' === '<'
  '✽' === '='
  '✾' === '>'
  '❀' === '@'
  #
  # La comprobacion que explica el porque, LITERAL:
  '❀'.codePointAt(0) % 256 === 0x40
  #
  # Causa: el punto de codigo se reduce modulo 256, asi que puntos de codigo altos
  # producen caracteres ASCII. La fuente cita chr() de PHP como el mecanismo.
  #
  # Plantillas de Hackvertor para generar las variantes, LITERALES:
  <@_unicode_overflow(0x100,'...')>@</@_unicode_overflow>
  <@_unicode_overflow_variations(0xfff,'...')>@</@_unicode_overflow_variations>
  # ('...' es texto de marcador literal en la fuente)
precondicion: "La aplicacion reduce puntos de codigo Unicode modulo 256 al convertirlos a bytes (la fuente cita chr() de PHP). Entonces un caracter Unicode alto se convierte en el ASCII correspondiente. LIMITACION IMPORTANTE, declarada por la fuente: sobre el objetivo (no nombrado) esto por si solo NO permitio partir la direccion."
como_se_descubre: |
  Señal: un validador que acepta caracteres Unicode en la direccion y una capa
  posterior que los convierte a bytes. La sonda es enviar '❀' donde se espera una '@'
  y observar si el sistema lo trata como '@'.
  Herramienta: Hackvertor (extension gratuita de Burp del propio autor). Requiere
  activar 'Allow code execution tags' e instalar las etiquetas desde el Tag Store.
  Las plantillas '_unicode_overflow' y '_unicode_overflow_variations' generan el
  conjunto de candidatos automaticamente, lo que convierte una exploracion tediosa
  en una sola peticion.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: direccion con '❀' en lugar de '@'  -> el sistema la trata como '@'
  # B: direccion con '@' normal           -> comportamiento de referencia
  # C: direccion con otro caracter Unicode alto cuyo modulo 256 NO sea 0x40
  #    -> debe ser rechazado o tratado como caracter literal
  # El par A/C confirma que el mecanismo es la reduccion modulo 256 y no una
  # normalizacion Unicode generica (NFKC), que es la explicacion alternativa y
  # tiene otra remediacion.
mata: |
  - La conversion a bytes rechaza puntos de codigo fuera de ASCII en lugar de reducirlos.
  - El validador normaliza o rechaza Unicode no ASCII en direcciones.
  - DECLARADO POR LA FUENTE: por si solo no basta para partir la direccion. Hay que
    encadenarlo con otra tecnica (encoded-word, UUCP, comentarios) para llegar a
    impacto de control de acceso.
fuente: "https://portswigger.net/research/splitting-the-email-atom (Gareth Heyes, 2024-08-07, act. 2025-06-27). Codigo, equivalencias y plantillas de Hackvertor literales de la pagina. El objetivo afectado no se nombra y no hay CVE ni recompensa indicados."
confianza: media
fecha: 2026-11-02
---
# [AUTH] Desbordamiento Unicode por módulo 256 — `'❀'` se convierte en `'@'`

## Principio
Cuando una capa convierte un punto de código Unicode a un byte reduciéndolo módulo 256
—la fuente cita `chr()` de PHP— cualquier punto de código alto colapsa en un ASCII.
`0x100 + 0x40` y `0x40` producen el mismo byte. Así que un carácter que ningún
validador reconoce como peligroso se transforma, una capa más abajo, en el carácter
estructural que delimita el dominio.

## Payload
La mecánica, en el código que da la fuente:

```javascript
String.fromCodePoint(0x100 + 0x40)    // ŀ -> @
String.fromCodePoint(0x1000 + 0x40)   // ၀ -> @
String.fromCodePoint(0x10000 + 0x40)  // 𐁀 -> @
```

El alfabeto resultante, literal:

```javascript
'✨' === '('
'✩' === ')'
'✻' === ';'
'✼' === '<'
'✽' === '='
'✾' === '>'
'❀' === '@'
```

Y la comprobación que lo explica:

```javascript
'❀'.codePointAt(0) % 256 === 0x40
```

Para generar las variantes, las plantillas de **Hackvertor** (extensión gratuita de Burp
del propio autor; requiere activar *Allow code execution tags*):

```
<@_unicode_overflow(0x100,'...')>@</@_unicode_overflow>
<@_unicode_overflow_variations(0xfff,'...')>@</@_unicode_overflow_variations>
```

## Limitación declarada
La fuente es explícita en que esta técnica, **por sí sola, no permitió partir la
dirección** en el objetivo que probó. La incluyo con esa limitación por delante porque
su valor real es como **primitiva de encadenamiento**: aporta un `@`, un `<` o un `=`
allí donde el validador los filtra, y son las otras técnicas de esta carpeta
(encoded-word, UUCP, comentarios RFC) las que convierten ese carácter en un bypass. De
ahí el CVSS bajo: es una pieza, no un exploit.

## Impacto
Por sí mismo, inyección de un carácter estructural que el validador creía bloqueado.
Encadenado, el mismo impacto que el resto de la familia. El interés conceptual es que
muestra dónde viven estos fallos: no en la validación ni en la conversión, sino en que
las dos operan sobre representaciones distintas del mismo dato.

## Remediación
`# [derivado]`: rechazar puntos de código fuera de ASCII en la conversión a bytes en vez
de reducirlos — un truncamiento silencioso módulo 256 es una pérdida de información que
siempre favorece al atacante. Validar y convertir en la misma representación, y hacer
que la validación opere sobre los **bytes finales**, no sobre la cadena de entrada.
