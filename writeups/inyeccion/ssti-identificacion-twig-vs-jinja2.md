---
clase: inyeccion
tech: twig-jinja2
cwe: CWE-1336
cvss: 0.0 # [derivado] paso de identificacion
payload: |
  # SONDA DE IDENTIFICACION - LITERAL de la fuente. Una sola peticion separa los dos
  # motores que comparten la sintaxis {{ }}:
  {{7*'7'}}
  #
  # Resultados LITERALES de la fuente:
  #   Twig    -> 49
  #   Jinja2  -> 7777777
  #
  # Mecanica: Twig convierte '7' a numero y multiplica (49). Jinja2, siguiendo la
  # semantica de Python, REPITE la cadena siete veces (7777777). La misma expresion
  # distingue los motores porque sus lenguajes base difieren.
  #
  # OTRAS SONDAS DE IDENTIFICACION literales de la fuente:
  #
  # ERB (Ruby) - el ERROR identifica el motor:
  <%=foobar%>
  # Mensaje literal que devuelve:
  #   (erb):1:in `<main>': undefined local variable or method `foobar' for main:Object (NameError) from /usr/lib/ruby/2.5.0/erb.rb:876:in `eval' from /usr/lib/ruby/2.5.0/erb.rb:876:in `result' from -e:4:in `<main>'
  #
  # Jade:
  = 7*7      ->  49
  = root     ->  [object global]
  #
  # Twig, confirmacion por error (del paper):
  custom_email={{7*7}}     ->  49
  custom_email={{self}}    ->  Object of class __TwigTemplate_7ae62e582f8a35e5ea6cc639800ecf15b96c0d6f78db3538221c1145580ca4a5 could not be converted to string
  #
  # NO hay sonda en la fuente para: Velocity, Mako, Handlebars, Django, Tornado, Flask
  # ni Pug. No las invento.
precondicion: "SSTI ya confirmada (ver ssti-deteccion-contexto-plano-y-codigo). Este paso identifica el motor, que es lo que decide el payload de explotacion: la sintaxis de escape de sandbox es distinta en cada uno y usar la equivocada produce un error que se lee como 'no explotable'."
como_se_descubre: |
  Segunda fase de la metodologia de la fuente ('Identify'). La fuente la describe como
  un 'decision tree of language-specific payloads' — pero ese arbol es una IMAGEN en la
  pagina, asi que lo que queda utilizable son las sondas sueltas de arriba.
  El valor de {{7*'7'}} es que resuelve en UNA peticion la ambiguedad mas comun: Twig
  y Jinja2 comparten los delimitadores {{ }}, asi que una deteccion con {{7*7}} no
  distingue cual es. Y sus cadenas de explotacion no tienen nada en comun.
  Para ERB la señal es el ERROR, no el resultado: el mensaje nombra erb.rb y la version
  de Ruby, lo que identifica motor y entorno a la vez.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: {{7*'7'}}  -> 49 (Twig) o 7777777 (Jinja2)
  # B: {{7*7}}    -> 49 en AMBOS
  # El par demuestra por que hace falta A: B no discrimina. Si solo se envia B y se ve
  # 49, se asume Twig y se pierde el tiempo con payloads de Twig sobre un Jinja2.
  # C: '7*7' como texto plano -> no debe evaluarse
mata: |
  - Ninguna sonda evalua -> revisar primero la deteccion: puede no haber motor.
  - El motor no esta en la lista de la fuente -> no hay sonda documentada; no inventarla.
  - Motor logic-less -> no evalua expresiones por diseño.
fuente: "https://portswigger.net/research/server-side-template-injection (James Kettle, 2015-08-05, act. 2025-09-03) y https://portswigger.net/web-security/server-side-template-injection. Sondas, resultados y el mensaje de error de ERB literales de la pagina. El arbol de decision por motor es una imagen y NO se reconstruye."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Identificación del motor de plantillas — `{{7*'7'}}` separa Twig de Jinja2

## Principio
`{{7*7}}` confirma que hay un motor pero no dice cuál, y Twig y Jinja2 comparten los
delimitadores `{{ }}`. Como sus cadenas de explotación no tienen nada en común, elegir
mal el motor produce una secuencia de errores de sintaxis que se interpreta como "no
explotable". La sonda de desambiguación cuesta una petición.

## Payload
```
{{7*'7'}}
```

| Motor | Resultado |
|---|---|
| Twig | `49` |
| Jinja2 | `7777777` |

El mecanismo es elegante: Twig convierte `'7'` a número y multiplica. Jinja2, con
semántica de Python, **repite la cadena** siete veces. La misma expresión distingue los
motores porque sus lenguajes base difieren.

Otras sondas literales de la fuente:

```
<%=foobar%>        # ERB: identifica por el ERROR
= 7*7              # Jade -> 49
= root             # Jade -> [object global]
{{self}}           # Twig -> nombre de clase __TwigTemplate_...
```

Para **ERB** la señal es el mensaje de error, que nombra `erb.rb` y la versión de Ruby,
identificando motor y entorno de una vez:

```
(erb):1:in `<main>': undefined local variable or method `foobar' for main:Object (NameError) from /usr/lib/ruby/2.5.0/erb.rb:876:in `eval' from /usr/lib/ruby/2.5.0/erb.rb:876:in `result' from -e:4:in `<main>'
```

## Nota de procedencia
La fuente describe la fase de identificación como un *"decision tree of language-specific
payloads"*, pero **ese árbol es una imagen** en la página. Lo que queda utilizable son
las sondas sueltas de arriba. Y no hay sonda documentada para Velocity, Mako,
Handlebars, Django, Tornado, Flask ni Pug — así que no las incluyo.

## Impacto
Ninguno directo. Es la bifurcación de la que depende el resto del árbol, igual que el
fingerprint de motor SQL en `sqli-fingerprint-version-por-dbms.md`. El patrón se repite:
en toda familia multi-implementación, identificar primero ahorra más tiempo que
cualquier otra optimización.

## Remediación
La de la inyección subyacente. Ocultar la identidad del motor es ofuscación: como
muestra este writeup, se infiere de la semántica de una multiplicación.
