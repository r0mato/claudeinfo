---
clase: inyeccion
tech: java
cwe: CWE-88
cvss: 8.8 # [derivado] inyeccion de argumentos; sin shell, no hay metacaracteres
payload: |
  # USO INCORRECTO - LITERAL de la fuente (etiquetado 'Incorrect usage'):
  ProcessBuilder b = new ProcessBuilder("C:\\DoStuff.exe -arg1 -arg2");
  # La fuente explica: esto crea UN solo elemento en la lista de comando, no un
  # programa seguido de dos argumentos.
  #
  # USO CORRECTO - LITERAL de la fuente (etiquetado 'Correct Usage'):
  ProcessBuilder pb = new ProcessBuilder("TrustedCmd", "TrustedArg1", "TrustedArg2");  Map<String, String> env = pb.environment();  pb.directory(new File("TrustedDir"));  Process p = pb.start();
  #
  # SEPARADORES PROBADOS por la fuente y su payload - LITERALES:
  &   &&   |   ||
  cmd /c whoami
  # Plantilla de prueba usada: "java -version %s " + payload
  #
  # ARNES DE PRUEBA - LITERAL de la fuente (saltos de linea colapsados en el render):
  String[] specialChars = new String[]{"&", "&&", "|", "||"}; String payload = "cmd /c whoami"; String cmdTemplate = "java -version %s " + payload; String cmd; Process p; int returnCode; for (String specialChar : specialChars) {     cmd = String.format(cmdTemplate, specialChar);     System.out.printf("#### TEST CMD: %s\n", cmd);     p = Runtime.getRuntime().exec(cmd);     returnCode = p.waitFor();     System.out.printf("RC    : %s\n", returnCode); }
  #
  # HECHO CLAVE - cita literal de la fuente:
  #   'Runtime.exec(String) does NOT try to invoke the shell at any point and does
  #    not support shell metacharacters.'
precondicion: "El codigo usa Runtime.exec(String) con una cadena construida a partir de entrada del usuario. Mecanica LITERAL de la fuente: 'it splits the command String into tokens on whitespace only, so an argument that contains a space is broken into several tokens, which is how untrusted input can add extra arguments'. Deprecado desde Java 18 por ser propenso a errores."
como_se_descubre: |
  Revision de codigo: buscar 'Runtime.getRuntime().exec(' con un argumento String
  (no String[]). Es un patron de grep de una linea y alto rendimiento.
  El punto que cambia el marco mental: Runtime.exec(String) NO invoca una shell, asi
  que los metacaracteres (; | &) NO funcionan. Un tester que pruebe solo
  metacaracteres concluira 'no vulnerable' cuando el objetivo SI lo es por otra via.
  Lo que funciona es el ESPACIO: parte la cadena en tokens y cada token extra es un
  argumento nuevo para el programa invocado.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: entrada con un ESPACIO que añada un argumento al programa invocado
  #    -> el programa recibe un argumento extra = vulnerable
  # B: entrada con metacaracteres de shell (; && | $)
  #    -> NO deben tener efecto, porque no hay shell
  # El par A/B es el nucleo del writeup: B negativo y A positivo es exactamente la
  # firma de esta clase. Si B funciona, hay una shell en medio (p.ej. 'sh -c') y el
  # hallazgo es inyeccion de comandos clasica, que es otra cosa.
mata: |
  - Se usa ProcessBuilder o Runtime.exec(String[]) con programa y argumentos separados.
  - La entrada se valida contra una allowlist de opciones y operandos permitidos.
  - Cita literal de la fuente, que conviene no olvidar: 'Separating the arguments does
    not replace validating them.' Separar argumentos impide AÑADIR argumentos, no
    impide que un argumento legitimo tenga un valor peligroso.
fuente: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html (seccion Java). Codigo correcto/incorrecto, arnes de prueba, separadores y las citas son literales de la pagina. ADVERTENCIA: el render colapso los saltos de linea del codigo Java."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] `Runtime.exec(String)` en Java — inyección de argumentos sin shell y sin metacaracteres

## Principio
`Runtime.exec(String)` no lanza una shell. Cita literal: *"`Runtime.exec(String)` does
NOT try to invoke the shell at any point and does not support shell metacharacters."* Eso
suena a protección y produce justo el efecto contrario en la práctica, porque un tester
que pruebe `;`, `&&` y `|` no verá nada y archivará el objetivo como no vulnerable.

El vector real es el **espacio**. La fuente lo describe así: *"it splits the command
String into tokens on whitespace only, so an argument that contains a space is broken
into several tokens, which is how untrusted input can add extra arguments"*. Cada token
extra es un argumento más para el programa invocado.

## Payload
Uso incorrecto, literal de la fuente:

```java
ProcessBuilder b = new ProcessBuilder("C:\\DoStuff.exe -arg1 -arg2");
```

La fuente explica el error: esto crea **un** solo elemento en la lista de comando, no un
programa con dos argumentos.

Uso correcto:

```java
ProcessBuilder pb = new ProcessBuilder("TrustedCmd", "TrustedArg1", "TrustedArg2");  Map<String, String> env = pb.environment();  pb.directory(new File("TrustedDir"));  Process p = pb.start();
```

El arnés con el que la fuente comprueba que los metacaracteres no funcionan:

```java
String[] specialChars = new String[]{"&", "&&", "|", "||"}; String payload = "cmd /c whoami"; String cmdTemplate = "java -version %s " + payload;
```

## La firma de la clase
Un control negativo con metacaracteres que **falla** y un control con espacio que
**funciona** es exactamente la huella de esta vulnerabilidad. Y la inferencia inversa
también es útil: si los metacaracteres sí funcionan, hay una shell en medio (`sh -c`,
`cmd /c`) y lo que se tiene es inyección de comandos clásica — otra clase, otra
remediación, otro CVSS.

## Impacto
Control sobre los argumentos del programa invocado. El techo depende del programa: con
una utilidad de red es SSRF o exfiltración; con una que escriba ficheros, escritura
arbitraria; con un intérprete, ejecución de código.

## Remediación
De la fuente: *"In Java, use ProcessBuilder and the command must be separated from its
arguments."* Y: *"`Runtime.exec(String)` is deprecated since Java 18 as error-prone...
Use `ProcessBuilder` or `Runtime.exec(String[])` instead, passing the program and each
argument as separate elements."*

Con el matiz que la propia fuente añade y que conviene citar en cualquier informe de
esta clase: *"Separating the arguments does not replace validating them."* Separar
argumentos impide **añadir** argumentos; no impide que un argumento legítimo lleve un
valor peligroso. Son dos controles y hacen falta los dos.
