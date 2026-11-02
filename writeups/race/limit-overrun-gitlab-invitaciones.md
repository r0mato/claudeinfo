---
clase: race
tech: gitlab-api
cwe: CWE-362
cvss: 3.7 # [derivado] la propia fuente lo califica de 'low-severity exploit'
payload: |
  # ADVERTENCIA DE PROCEDENCIA: la fuente abrevia la ruta de la API con '…' (es su
  # propia redaccion, no una elipsis mia). Se reproduce tal cual. El dominio
  # psres.net es el de laboratorio de PortSwigger, literal de la fuente.
  POST /api/…/invitations HTTP/2
  ...
  {"email":"x@psres.net"}
  #
  # Enviar 6 copias simultaneas con el single-packet attack.
  #
  # BASELINE (peticiones separadas en el tiempo):
  #   6 x {"status":"success"}  y UN correo de invitacion
  #
  # LOTE SIMULTANEO (el hallazgo):
  #   1 x {"status":"success"}
  #   5 x {"message":"The member's email address has already been taken"}
  #   y DOS correos
precondicion: "El endpoint aplica un limite (una invitacion por direccion) comprobandolo antes de actuar. La vulnerabilidad vive en el hueco entre comprobacion y accion. Cita literal de la fuente sobre la causa comun de toda la clase: 'they all exploit the time-gap between the security check and the protected action.' Requiere HTTP/2 para el single-packet attack."
como_se_descubre: |
  Metodologia literal de la fuente para esta clase: 'Classic limit-overrun
  vulnerabilities can be discovered using a trivial methodology: identify a limit, and
  try to overrun it.' La pista concreta en este caso, en palabras de la fuente:
  'Receiving two emails from six requests is a clear clue that I've hit a sub-state,
  and further testing is warranted.'
  Lo importante es el patron invertido: el lote simultaneo produjo MENOS respuestas de
  exito (1 en vez de 6) pero MAS correos (2 en vez de 1). Esa inversion —menos exito
  aparente, mas efecto real— es la firma del sub-estado.
control_negativo: |
  # Control LITERAL de la fuente (no derivado): la fuente ejecuta el benchmark primero
  # A: 6 peticiones con segundos de separacion
  #    -> 6 x {"status":"success"}, 1 correo
  # B: las mismas 6 con single-packet attack
  #    -> 1 x success, 5 x "already been taken", 2 correos
  # Sin A no hay pista: 'ya tomado' leido en frio parece el comportamiento CORRECTO
  # del limite. Solo el contraste revela que se colo un correo extra.
mata: |
  - Los contadores se aplican con transaccion atomica o restriccion de unicidad en BD.
  - El objetivo no soporta HTTP/2 y last-byte sync no da resolucion suficiente.
  - El numero de correos coincide en A y en B -> no hay sub-estado.
  - Nota de la fuente: PHP bloquea por sessionid por defecto; si el objetivo serializa
    el lote, hace falta una sesion distinta por peticion o no habra concurrencia real.
fuente: "https://portswigger.net/research/smashing-the-state-machine (James Kettle, 2023-08-09). Caso 'object masking' sobre Gitlab. El articulo no indica recompensa ni CVE para este caso concreto, y califica el resultado como 'a low-severity exploit'."
confianza: media
fecha: 2026-11-02
---
# [RACE] Limit-overrun en el endpoint de invitaciones de GitLab — seis peticiones, dos correos

## Principio
Un límite comprobado antes de actuar deja un hueco entre la comprobación y la acción.
Si varias peticiones entran en ese hueco a la vez, todas pasan la comprobación y todas
actúan. Es la forma más simple de la clase, y la fuente la resume así: *"they all exploit
the time-gap between the security check and the protected action."*

## Payload
```http
POST /api/…/invitations HTTP/2
...
{"email":"x@psres.net"}
```

El `…` de la ruta y los `...` de las cabeceras son la abreviatura de la propia fuente,
no una elisión mía. Se envían **seis copias simultáneas** con el single-packet attack.

## El contraste que importa
| | Respuestas | Correos |
|---|---|---|
| Baseline (separadas) | 6 × `{"status":"success"}` | 1 |
| Lote simultáneo | 1 × `success` + 5 × `{"message":"The member's email address has already been taken"}` | **2** |

Lo valioso aquí es metodológico: el lote simultáneo devolvió **menos** éxitos aparentes
y **más** efecto real. Leídas en frío, cinco respuestas de "ya está tomado" parecen el
límite funcionando bien — exactamente lo contrario de una pista. Solo el contraste con
el baseline revela el correo extra. Este caso es el argumento práctico de por qué la
fuente insiste en que saltarse el benchmark hace perder vulnerabilidades.

## Impacto
La fuente es explícita en que el resultado fue limitado: *"After some more digging, I was
able to arrive at a low-severity exploit."* Lo incluyo precisamente por eso: es un
ejemplo honesto de que confirmar un sub-estado no equivale a un impacto alto, y de que
la pista (dos correos de seis peticiones) vale aunque el exploit final sea modesto. La
señal justifica seguir investigando: *"further testing is warranted."*

## Remediación
De la fuente: hacer atómicos los cambios de estado usando las funciones de concurrencia
del almacén de datos, y como defensa en profundidad aprovechar restricciones de
unicidad e integridad. Literal: *"As a defence in depth measure, take advantage of
datastore integrity/consistency features like uniqueness constraints."* Y, para este
patrón concreto: *"Don't attempt to use one data storage layer to secure another. For
example, sessions aren't suitable for preventing limit-overrun attacks on databases."*
