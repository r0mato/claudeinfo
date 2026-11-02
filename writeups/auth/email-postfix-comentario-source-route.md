---
clase: auth
tech: postfix
cwe: CWE-290
cvss: 7.5 # [derivado] sin CVE; redirige la entrega
payload: |
  # Postfix 3.6.4 - LITERAL de la fuente:
  collab%psres.net(@example.com
  # El parentesis COMENTA el dominio. La parte local se usa entonces como
  # source route, y la entrega acaba en psres.net.
  #
  # Percent hack (la fuente no nombra mailer para este caso) - LITERAL:
  foo%psres.net@example.com
  # -> enviado a example.com, el '%' se convierte en '@' y el correo se
  #    reenvia a foo@psres.net
  #
  # Variante con sintaxis de corchetes que la fuente marca como NO utilizable
  # para bypass de control de acceso - LITERAL:
  collab%psres.net@[127.0.0.1]
  # -> resulta en correo a collab@psres.net
  #
  # Sintaxis RFC 2822 valida que la fuente muestra en la introduccion - LITERAL:
  "@"@example.com
  "\""@example.com
  (foo)user@(bar)example.com
precondicion: "El parser acepta comentarios entre parentesis dentro de la direccion (sintaxis valida de RFC 2822) y el mailer trata la parte local como source route. Mailer confirmado: Postfix 3.6.4. El 'percent hack' requiere que el servidor receptor convierta '%' en '@' y reenvie."
como_se_descubre: |
  Señal: objetivo con Postfix. La clave conceptual es que los comentarios entre
  parentesis son sintaxis LEGITIMA de RFC 2822: '(foo)user@(bar)example.com' es una
  direccion valida. Un validador que implemente el RFC correctamente los acepta, y eso
  es justo lo que abre la puerta. No es un parser roto: es un parser CONFORME.
  Sonda: registrar con '(' antes de la '@' y un dominio Collaborator, y observar si
  llega interaccion SMTP.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: collab%psres.net(@example.com  -> entrega a psres.net (dominio del atacante)
  # B: collab%psres.net@example.com   (SIN el parentesis)
  #    -> comportamiento distinto: aqui actua el percent hack, no el comentario
  # C: collab@example.com             -> entrega normal
  # El par A/B es sutil pero importante: AMBOS pueden redirigir, por mecanismos
  # DISTINTOS (comentario vs percent hack). Distinguirlos cambia la remediacion
  # que se pide, asi que conviene reportarlos por separado.
mata: |
  - El validador rechaza parentesis en la direccion (aunque sean validos por RFC).
  - El mailer no trata la parte local como source route.
  - El servidor receptor no convierte '%' en '@' (mata el percent hack).
  - El control de acceso no depende del dominio del correo.
fuente: "https://portswigger.net/research/splitting-the-email-atom (Gareth Heyes, 2024-08-07, act. 2025-06-27). Payloads literales de la pagina. Sin CVE ni recompensa indicados para estos casos."
confianza: media
fecha: 2026-11-02
---
# [AUTH] Comentarios RFC 2822 y *percent hack* en Postfix — cuando cumplir el estándar es el fallo

## Principio
RFC 2822 permite comentarios entre paréntesis dentro de una dirección de correo. Esto
es una dirección **válida**:

```
(foo)user@(bar)example.com
```

Ahí está lo interesante de esta familia. El validador no está roto: está cumpliendo la
especificación. Pero si un paréntesis puede comentar el dominio, la dirección que la
aplicación cree estar validando y la que el mailer entrega dejan de coincidir — y la
discrepancia nace de la conformidad, no del incumplimiento. Por eso no se arregla
"validando mejor".

## Payload
Postfix 3.6.4, literal de la fuente:

```
collab%psres.net(@example.com
```

El paréntesis comenta el dominio; la parte local se usa entonces como *source route* y
la entrega acaba en `psres.net`.

El *percent hack*, para el que la fuente no nombra mailer:

```
foo%psres.net@example.com
```

Enviado a `example.com`, el `%` se convierte en `@` y el correo se reenvía a
`foo@psres.net`.

Y dos formas que la fuente marca explícitamente como no utilizables para bypass de
control de acceso, incluidas aquí para no confundirlas con las anteriores:

```
collab%psres.net@[127.0.0.1]
```

Otras formas válidas que muestra la introducción del artículo, útiles como sondas de
tolerancia del validador:

```
"@"@example.com
"\""@example.com
```

## Impacto
Igual que el resto de la familia: verificar una dirección de un dominio ajeno y entrar
donde el dominio sea la credencial.

## Nota de triaje
`collab%psres.net(@example.com` y `collab%psres.net@example.com` pueden **ambos**
redirigir la entrega, pero por mecanismos distintos: el primero por el comentario, el
segundo por el *percent hack*. Conviene no fusionarlos en un solo informe, porque la
corrección difiere — uno exige decidir qué hacer con los comentarios RFC, el otro
corregir la conversión de `%` en el receptor.

## Remediación
`# [derivado]`: deshabilitar el *percent hack* y el enrutamiento por source route en la
configuración del mailer, y decidir explícitamente que la aplicación rechaza comentarios
y comillas en direcciones de registro, aun siendo sintaxis válida — aquí la
compatibilidad con el RFC completo tiene un coste de seguridad que conviene asumir de
forma consciente.

La defensa de fondo es la de la fuente: *"Never use the email domain as a sole means of
authorisation, because it can be easily spoofed as we've seen."*
