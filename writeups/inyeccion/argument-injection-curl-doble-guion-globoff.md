---
clase: inyeccion
tech: curl
cwe: CWE-88
cvss: 7.5 # [derivado] SSRF y transferencias adicionales no previstas
payload: |
  # Ilustracion de la clase - LITERAL de la fuente:
  system("curl " . escape($url));
  system("curl " . escape("--help"))
  #
  # ADVERTENCIA CRITICA DE LA FUENTE sobre el '--' (cita literal):
  #   'For commands that support it, use -- to end option parsing. In curl, later
  #    arguments are still URL operands: -- does not prevent additional transfers.'
  #
  # Es decir: el truco habitual de cerrar el parseo de opciones con '--' NO funciona
  # con curl. Tras el '--', los argumentos siguientes se tratan como URLs y curl
  # realiza transferencias ADICIONALES.
  #
  # Defensa LITERAL de la fuente:
  #   'Pass exactly one validated URL as one argument using a process API, and disable
  #    curl's URL globbing with --globoff.'
  #
  # Lista de metacaracteres (Nota A) - LITERAL de la fuente.
  # Atencion: hay DOS espacios entre '|' y ';' en el original:
  & |  ; $ > < ` \ ! ' " ( )
  #
  # Regex de allowlist que da la fuente como ejemplo (solo minusculas y digitos,
  # longitud 3-10) - LITERAL:
  ^[a-z0-9]{3,10}$
precondicion: "El codigo invoca curl con una URL que viene del usuario, como parte de una linea de comando. La vulnerabilidad NO necesita metacaracteres de shell: basta que el usuario pueda aportar un argumento mas, ya sea una opcion o una segunda URL."
como_se_descubre: |
  Señal en recon: funcionalidad que recupera una URL (webhooks, importadores,
  validadores de enlaces, generadores de miniaturas, previsualizacion de enlaces).
  Sonda de dos pasos:
  1. Enviar un valor que empiece por '-' y observar si el comportamiento cambia.
  2. Enviar DOS URLs separadas por espacio y observar si llegan DOS peticiones al host
     controlado. Si llegan dos, se confirma que se pueden añadir operandos de URL, que
     es el nucleo de esta clase y lo que el '--' no impide.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: url='http://host-controlado/a http://host-controlado/b'
  #    -> llegan DOS peticiones = se pueden añadir operandos de URL
  # B: url='http://host-controlado/a'
  #    -> llega UNA peticion (comportamiento previsto)
  # C: url='-- http://host-controlado/c'
  #    -> si TAMBIEN llega la peticion, se confirma la advertencia de la fuente:
  #       el '--' no evita transferencias adicionales en curl
  # El control C es el valioso: documenta que la mitigacion que la mayoria aplicaria
  # (cerrar el parseo con '--') NO es suficiente aqui.
mata: |
  - La URL se pasa como UN argumento mediante una API de proceso con lista de
    argumentos, no como linea de shell -> muere.
  - La URL se valida contra una allowlist antes de usarse.
  - Se usa --globoff y se pasa exactamente una URL validada.
  - El binario invocado no es curl y no trata los argumentos sobrantes como operandos.
fuente: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html. La advertencia sobre '--' en curl, la defensa con --globoff, la lista de metacaracteres de la Nota A y el regex de allowlist son literales de la pagina."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Argument injection en curl — por qué `--` no cierra la puerta

## Principio
El consejo estándar para contener la inyección de argumentos es terminar el parseo de
opciones con `--`: lo que venga después se trata como operando, no como opción. Con
curl ese consejo **es insuficiente**, y la fuente lo dice sin ambigüedad:

> *"For commands that support it, use `--` to end option parsing. In curl, later
> arguments are still URL operands: `--` does not prevent additional transfers."*

Los operandos de curl **son URLs**. Así que cerrar el parseo de opciones no cierra nada:
simplemente garantiza que lo siguiente se interprete como una dirección que curl va a
buscar.

## Payload
La forma de la clase, literal de la fuente:

```php
system("curl " . escape($url));
system("curl " . escape("--help"))
```

La lista de metacaracteres que la fuente llama Nota A (con los dos espacios entre `|` y
`;` del original):

```
& |  ; $ > < ` \ ! ' " ( )
```

Y el regex de allowlist que propone como ejemplo, minúsculas y dígitos, longitud 3-10:

```
^[a-z0-9]{3,10}$
```

## Por qué esta entrada existe aparte
Porque documenta el fallo de una **mitigación**, no de un código. Un revisor que vea
`--` en la línea de comando puede dar el problema por cerrado. El control negativo con
`-- http://host-controlado/c` es lo que demuestra que no lo está, y es información que
no se deduce leyendo el código: hay que conocer el comportamiento concreto de curl con
sus operandos.

## Impacto
Transferencias adicionales a destinos que elige el atacante, es decir SSRF desde el
servidor, con el alcance de red que ese servidor tenga. Y la fuente añade un recordatorio
que conviene no perder: *"Argument separation does not validate the destination; apply
SSRF protections."* Separar los argumentos evita la inyección de opciones, pero no
responde a la pregunta de **a dónde** se permite conectar.

## Remediación
Cita literal: *"Pass exactly one validated URL as one argument using a process API, and
disable curl's URL globbing with `--globoff`. Do not interpolate an unquoted value into
a shell command."*

Las tres piezas son necesarias y distintas: una API de proceso con lista de argumentos
impide inyectar argumentos; `--globoff` desactiva la expansión de patrones en la URL; y
la validación de la URL contra una allowlist responde a la pregunta del destino. Ninguna
de las tres sustituye a las otras dos.
