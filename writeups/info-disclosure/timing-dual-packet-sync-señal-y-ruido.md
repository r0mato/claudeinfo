---
clase: info-disclosure
tech: http2-timing
cwe: CWE-208
cvss: 0.0 # [derivado] es la primitiva de medicion, no una vulnerabilidad
payload: |
  # PROCEDIMIENTO 'dual-packet sync' - LITERAL de la fuente (saltos colapsados):
  disable TCP_NODELAY send a ping frame for each request with no body: send the headers withhold an empty data frame for each request with a body: send the headers, and the body except the final byte withhold a data frame containing the final byte wait for 100ms send a ping frame send the final frames
  #
  # LA CLAVE, cita LITERAL: 'Implementing this dual-packet sync turned out to be
  # extremely easy - just add an extra ping frame! This harmless sacrificial packet
  # ensures that the operating system coalesces the subsequent header frames.'
  #
  # Por que hacen falta DOS paquetes y no uno, cita LITERAL:
  #   'some servers start to process HTTP requests as soon as they've got the headers,
  #    without waiting for the body'
  # y por que no un paquete por cabecera:
  #   'the HTTP/2 RFC forbids interleaving header frames from separate requests so it's
  #    unlikely to work'
  #
  # EL PROBLEMA QUE RESUELVE - 'sticky request-order problem', cita LITERAL:
  #   'At the HTTP/2 layer, the two requests are completely concurrent, but the
  #    underlying TLS data is a stream so one request is still "first" i.e. one will be
  #    fully decrypted before the other.'
  # La solucion previa (Timeless Timing Attacks, 2020) era rellenar con parametros
  # dummy. La fuente la descarta: 'I've observed different numbers of parameters being
  # required on a single lab system, ten minutes apart.'
  #
  # MEJORA MEDIDA, cifras LITERALES:
  #   'the smallest time gap I'd personally exploited was 30,000us. Now, it's 200us.'
  #   'in the space of ten seconds you can now reliably detect a sub-millisecond differential'
precondicion: "El objetivo habla HTTP/2. La tecnica compara el ORDEN de las respuestas de un par de peticiones enviadas en el mismo paquete, no sus tiempos absolutos, con lo que elimina por completo el jitter de red."
como_se_descubre: |
  No se descubre: es el instrumento. Lo que hay que interiorizar es su limite, porque
  la fuente es inusualmente honesta al respecto.
  ECUACION SEÑAL/RUIDO (la imagen no se reconstruye), cita LITERAL de su lectura:
  'The success of every timing attack comes down to two competing variables - signal
  and noise. Signal refers to the size of the timing difference you want to detect, and
  noise refers to everything else that affects the response timing. If the signal is
  too quiet relative to the background noise, you won't hear it'
  Y el limite de repetir mediciones, LITERAL:
  'Note that this equation does not include "number of measurements". You can attempt to
  cancel out noise by taking repeated measurements, but this approach scales poorly.
  Once noise heavily outweighs signal you'll quickly need billions of measurements,
  resulting in an attack that takes so long the target will probably be decommissioned
  before it's complete.'
control_negativo: |
  # El 'control' de esta tecnica es la CALIBRACION, y la fuente da dos reglas:
  # 1. Construir un banco de pruebas local. LITERAL: 'Once you're working at the right
  #    level, consider building a local benchmark to measure the signal size that
  #    you'll need to detect.'
  # 2. Corroborar desde otro angulo. LITERAL: 'Carry your assumptions lightly and test
  #    them from different angles wherever possible.'
  # Ejemplo LITERAL de corroboracion que la propia fuente practica: 'when our invalid
  # JSON sequence got redacted, the timing difference disappeared! Taken together, this
  # strongly suggests that the delay is happening due to a component parsing the
  # response being sent to us.'
  # Eso es un control negativo perfecto: hacer desaparecer la CAUSA y comprobar que
  # desaparece el EFECTO.
mata: |
  - El objetivo no soporta HTTP/2 -> el metodo no aplica.
  - Ruido de servidor del orden de la señal. ADVERTENCIA LITERAL: 'Do not underestimate
    server noise... Server noise is the reason I haven't made any claims about what
    time-delay you can expect to detect with the enhanced single-packet attack - any
    such claim is so target-specific it's effectively meaningless.'
  - Defensa de limitacion: 'a rate limit restricting each IP address to one request per
    1-5 ms' rompe el single-packet attack.
  - FALSO POSITIVO ESTRUCTURAL, cita LITERAL: 'inputs that trigger errors can short-cut
    large code paths and result in significantly faster responses. In other words,
    timing attacks are exceptionally good at detecting exceptions'.
fuente: "https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work (James Kettle, publicado 2024-08-07, act. 2024-11-18). Procedimiento, citas y cifras literales. Idea original atribuida a 'Timeless Timing Attacks' (USENIX 2020). Integrado en el single-packet attack de Burp Suite; la fuente dice que colabora con el desarrollador de h2spacex. Banco de pruebas de la investigacion: 30.000 sitios web con programa de recompensas. La ecuacion señal/ruido es una IMAGEN y no se reconstruye."
confianza: alta
fecha: 2026-11-02
---
# [INFO-DISCLOSURE] Dual-packet sync — medir diferencias de 200 µs, y saber cuándo no creerlas

## Principio
Un ataque de temporización remoto compite contra el jitter de red. La solución es no
medir tiempos absolutos sino **comparar el orden de llegada** de dos respuestas a dos
peticiones enviadas en el mismo paquete. Con las dos peticiones saliendo juntas, el
jitter afecta a ambas por igual y desaparece de la ecuación.

Mejora medida, en cifras de la fuente: *"the smallest time gap I'd personally exploited
was 30,000μs. Now, it's 200μs."* Y: *"in the space of ten seconds you can now reliably
detect a sub-millisecond differential."*

## El problema que resuelve
Cita literal del *"sticky request-order problem"*:

> *"At the HTTP/2 layer, the two requests are completely concurrent, but the underlying
> TLS data is a stream so one request is still 'first' i.e. one will be fully decrypted
> before the other."*

La solución anterior (Timeless Timing Attacks, 2020) era rellenar la primera petición con
parámetros dummy para resincronizar. La fuente la descarta con un dato demoledor:
*"I've observed different numbers of parameters being required on a single lab system, ten
minutes apart."*

## Procedimiento
```
disable TCP_NODELAY send a ping frame for each request with no body: send the headers withhold an empty data frame for each request with a body: send the headers, and the body except the final byte withhold a data frame containing the final byte wait for 100ms send a ping frame send the final frames
```

La pieza ingeniosa, literal:

> *"Implementing this dual-packet sync turned out to be extremely easy - just add an extra
> ping frame! This harmless sacrificial packet ensures that the operating system coalesces
> the subsequent header frames."*

Y por qué **dos** paquetes y no uno: *"some servers start to process HTTP requests as soon
as they've got the headers, without waiting for the body"*. Por qué no uno por cabecera:
*"the HTTP/2 RFC forbids interleaving header frames from separate requests."*

## Lo más valioso del paper: cuándo no creer la medición
La ecuación señal/ruido es una imagen, pero su lectura es literal:

> *"If the signal is too quiet relative to the background noise, you won't hear it"*

Y el límite de la fuerza bruta estadística:

> *"You can attempt to cancel out noise by taking repeated measurements, but this approach
> scales poorly. Once noise heavily outweighs signal you'll quickly need billions of
> measurements, resulting in an attack that takes so long the target will probably be
> decommissioned before it's complete."*

La honestidad que conviene imitar:

> *"Do not underestimate server noise... Server noise is the reason I haven't made any
> claims about what time-delay you can expect to detect with the enhanced single-packet
> attack - any such claim is so target-specific it's effectively meaningless."*

Un investigador que publica una técnica de medición y se **niega** a dar una cifra de
sensibilidad está diciendo algo importante: cualquier número que circule sobre "qué
diferencia se puede detectar" es inventado.

## El falso positivo estructural
> *"inputs that trigger errors can short-cut large code paths and result in significantly
> faster responses. In other words, timing attacks are exceptionally good at detecting
> exceptions"*

Y la advertencia de fondo, que es la tesis del paper:

> *"It's that timing attacks are too powerful. They can detect so much that it's
> incredibly easy to misunderstand what you've detected. They're incredibly good at
> detecting 'something', but that something isn't necessarily what you're trying to
> detect."*

## El control negativo modelo
La fuente practica el mejor control posible: hacer desaparecer la **causa** y comprobar
que desaparece el **efecto**. Literal: *"when our invalid JSON sequence got redacted, the
timing difference disappeared! Taken together, this strongly suggests that the delay is
happening due to a component parsing the response being sent to us."*

Y la regla general: *"Carry your assumptions lightly and test them from different angles
wherever possible."*

## Impacto
Ninguno directo — CVSS 0.0. Es el instrumento que habilita la detección de scoped SSRF,
inyección ciega y parámetros ocultos.

## Remediación
De la fuente: *"To mitigate attacks that exploit smaller signals, you could try breaking
the single-packet attack by implementing a rate limit restricting each IP address to one
request per 1-5 ms."* Y para fabricantes de WAF: detectar cuándo un solo paquete contiene
varias peticiones HTTP y separarlas con un retardo mínimo.

Y la conclusión sobre funciones de tiempo constante, con su característico escepticismo:
*"yes I do recommend using constant-time functions when comparing user input with secret
keys. Just ask anyone who says this is an actual threat to provide a proof of concept."*
