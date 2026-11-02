---
clase: inyeccion
tech: template-engines
cwe: CWE-1336
cvss: 0.0 # [derivado] es el paso de deteccion; el impacto lo aportan los writeups de explotacion
payload: |
  # CADENA DE FUZZING GENERICA - LITERAL de la fuente. Termina en UNA barra invertida:
  ${{<%[%'"}}%\
  #
  # Mecanica: concentra los delimitadores de VARIOS motores a la vez, asi que
  # provoca un error en casi cualquiera. Un error es mas facil de detectar que una
  # evaluacion correcta.
  #
  # ---- CONTEXTO PLANO (la entrada se interpola en una plantilla ya existente) ----
  # Pares LITERALES de la fuente (entrada -> salida):
  smarty=Hello {user.name}    ->  Hello user1
  freemarker=Hello ${username}  ->  Hello newuser
  any=<b>Hello</b>            ->  <b>Hello<b>
  smarty=Hello ${7*7}         ->  Hello 49
  freemarker=Hello ${7*7}     ->  Hello 49
  # (el '<b>Hello<b>' sin barra en el cierre es como lo imprime la fuente)
  #
  # Sonda de la Academy:
  http://vulnerable-website.com/?username=${7*7}     # se espera "Hello 49"
  #
  # ---- CONTEXTO DE CODIGO (la entrada ES una expresion de la plantilla) ----
  # Pares LITERALES de la fuente:
  personal_greeting=username          ->  Hello user01
  personal_greeting=username<tag>     ->  Hello            (salida VACIA)
  personal_greeting=username}}<tag>   ->  Hello user01 <tag>
  #
  # Sondas de la Academy:
  http://vulnerable-website.com/?greeting=data.username<tag>
  http://vulnerable-website.com/?greeting=data.username}}<tag>   # se espera "Hello Carlos<tag>"
  #
  # NOTA: '<%= 7*7 %>' y '#{7*7}' NO aparecen en la fuente. Solo '<%=foobar%>' (ERB)
  # y '#{prop}' (Jade). No los incluyo como literales de PortSwigger.
precondicion: "La entrada del usuario llega a un motor de plantillas. La distincion entre los dos contextos es la decision central: en CONTEXTO PLANO la entrada se interpola en una plantilla existente y basta inyectar sintaxis de plantilla; en CONTEXTO DE CODIGO la entrada YA es una expresion, asi que primero hay que CERRAR la expresion (el '}}' del tercer par) antes de inyectar nada."
como_se_descubre: |
  Metodologia LITERAL de la fuente, en tres fases: 'Detect', 'Identify', 'Exploit'.
  La fase de deteccion se bifurca por contexto, y distinguirlos es lo que decide el
  payload:
  - CONTEXTO PLANO: inyectar ${7*7} o {{7*7}} y buscar '49' en la salida.
  - CONTEXTO DE CODIGO: el par de sondas con <tag> es el diagnostico. Si
    'username<tag>' produce salida VACIA, la expresion se rompio (hay motor); si
    'username}}<tag>' devuelve el valor Y la etiqueta, se ha cerrado la expresion con
    exito y se puede inyectar.
  La salida vacia es la señal mas facil de pasar por alto, porque parece un fallo de
  la aplicacion y no una pista.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: ${7*7}      -> aparece '49' = se evalua
  # B: ${7*8}      -> aparece '56' = es ARITMETICA real, no la cadena '49' reflejada
  # El par A/B es imprescindible: '49' puede estar en la pagina por casualidad. Solo
  # un segundo calculo distinto prueba evaluacion.
  # C: literal '49' enviado como texto -> confirma que no se refleja tal cual
mata: |
  - Ni la cadena de fuzzing ni las sondas aritmeticas producen cambio -> no hay motor
    de plantillas en ese sink.
  - La entrada se escapa antes de llegar al motor (lo correcto).
  - B no evalua -> lo de A era reflejo de la cadena '49', no evaluacion (falso positivo).
  - Motor logic-less (Mustache, Template de Python): no evalua expresiones por diseño.
fuente: "https://portswigger.net/research/server-side-template-injection (James Kettle, publicado 2015-08-05, actualizado 2025-09-03) y https://portswigger.net/web-security/server-side-template-injection. Cadena de fuzzing, pares entrada/salida y metodologia literales. ADVERTENCIA: el render colapso los saltos de linea; los arboles de decision por motor de la fuente son IMAGENES y no se reconstruyen."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Detección de SSTI — contexto plano frente a contexto de código

## Principio
SSTI tiene dos formas que requieren payloads distintos, y confundirlas es la causa más
común de concluir "no es vulnerable". En **contexto plano** la entrada se interpola en
una plantilla que ya existe, así que basta inyectar sintaxis de plantilla. En **contexto
de código** la entrada ya *es* una expresión de la plantilla — y entonces inyectar
sintaxis no hace nada: primero hay que **cerrar** la expresión.

## Payload
Cadena de fuzzing genérica, literal de la fuente (termina en una barra invertida):

```
${{<%[%'"}}%\
```

Concentra los delimitadores de varios motores a la vez, así que provoca un error en
casi cualquiera — y un error es más fácil de detectar que una evaluación correcta.

**Contexto plano**, pares literales de la fuente:

```
smarty=Hello ${7*7}         ->  Hello 49
freemarker=Hello ${7*7}     ->  Hello 49
```

**Contexto de código**, el par que diagnostica:

```
personal_greeting=username          ->  Hello user01
personal_greeting=username<tag>     ->  Hello            (salida VACIA)
personal_greeting=username}}<tag>   ->  Hello user01 <tag>
```

## La señal que se pasa por alto
La **salida vacía** del segundo par. Parece un fallo de la aplicación, no una pista, y
por eso se descarta. Pero significa que la expresión de la plantilla se rompió, que es
exactamente la confirmación de que hay un motor evaluando. El tercer par cierra la
expresión con `}}` y devuelve el valor *más* la etiqueta: ahí ya se puede inyectar.

## El control aritmético con dos operaciones
`49` puede aparecer en una página por casualidad, o la aplicación puede estar reflejando
la cadena sin evaluarla. Un segundo cálculo con resultado distinto (`${7*8}` → `56`) es
lo único que prueba evaluación real. Es una petición y evita el falso positivo más
embarazoso de esta clase.

## Nota de procedencia
`<%= 7*7 %>` y `#{7*7}` circulan mucho en material de terceros pero **no aparecen en
esta fuente**: solo `<%=foobar%>` (ERB) y `#{prop}` (Jade). No los presento como
literales de PortSwigger. Los árboles de decisión por motor de la fuente son **imágenes**
y no los reconstruyo.

## Impacto
Ninguno directo — CVSS 0.0. Habilita los writeups de explotación por motor de esta
carpeta, donde el techo es ejecución remota de código.

## Remediación
Cita literal de la Academy: *"The best way to prevent server-side template injection is
to not allow any users to modify or submit new templates."* Y del paper: *"regexes are
not an effective defense, and parser-level sandboxes are error prone."* El enfoque de
menor riesgo que recomienda es *"a trivial template engine such as Mustache, or Python's
Template"*.
