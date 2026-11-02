---
clase: ssrf
tech: reverse-proxy
cwe: CWE-918
cvss: 8.6 # [derivado] SSRF indetectable por pingback; sin CVE ni recompensa indicados
payload: |
  # La fuente ACUÑA el nombre: 'I don't think there's an established name for this type
  # of SSRF, so I'll call it scoped SSRF.' Es una SSRF restringida a un dominio, que
  # segun la fuente 'can't be detected using pingback/OAST techniques'.
  #
  # PASO 1 - la respuesta NO distingue. Tabla LITERAL de la fuente (cabecera Host):
  #   random.example.com      -> 404 Not Found   (SSRF completa Y scoped SSRF)
  #   random.notexample.com   -> 404 Not Found   (completa) / 403 Forbidden (scoped)
  #
  # PASO 2 - la validacion sola NO es prueba. Par LITERAL (contenido distinto):
  #   Host: foo.example.com   -> 404 Not Found   25ms
  #   Host: foo.bar.com       -> 403 Forbidden   20ms
  #
  # PASO 3 - EL PAR QUE SI PRUEBA. LITERAL de la fuente, mismo host dos veces:
  #   Host: abc.example.com   -> 404 Not Found   25ms
  #   Host: abc.example.com   -> 404 Not Found   20ms
  # Cita LITERAL: 'The following request pair is what proves the issue - the faster
  # second response is evidence of DNS caching'
  #
  # La segunda respuesta es MAS RAPIDA porque la resolucion DNS quedo cacheada. Eso
  # demuestra que el servidor INTENTO resolver el nombre: es la respuesta a la
  # pregunta que la fuente formula como 'Did the server try to connect to the
  # specified hostname?'
  #
  # PASO 3-bis - si el resolver NO cachea los fallos. Tecnica LITERAL: 'sending an
  # overlong 64-octet DNS label, leading to the DNS client refusing to issue the lookup
  # and a faster response.'
  #   Host: aaa{62}.example.com  -> 404 Not Found   25ms
  #   Host: aaa{63}.example.com  -> 404 Not Found   20ms
  # ADVERTENCIA: la notacion {62}/{63} es la de la fuente, pero su texto dice
  # '64-octet'. La longitud exacta del label es AMBIGUA en la fuente. Probar varias.
precondicion: "Un proxy inverso que reenvia peticiones al dominio de la cabecera Host, pero RESTRINGIDO a un dominio concreto. La fuente lista las implementaciones: 'an internal DNS server, simple hostname validation, a firewall blocking outbound DNS, or a tight listener config'. Como la restriccion impide alcanzar el host del investigador, NO hay pingback y las tecnicas OAST no la ven."
como_se_descubre: |
  Esta es la aportacion central del paper. Cita LITERAL: 'The single biggest
  breakthrough in this research was when I realized I could use timing to detect a
  widely overlooked type of SSRF.'
  La logica es la que hay que interiorizar: el contenido de la respuesta NO puede
  distinguir 'el servidor valido el Host y lo rechazo' de 'el servidor intento
  conectar y fallo'. Los dos dan un 404. Pero solo el segundo genera una resolucion
  DNS, y una resolucion DNS deja huella en la CACHE — observable como una segunda
  respuesta mas rapida.
  Flujo de trabajo LITERAL de la fuente con Param Miner:
  1. 'Use Param Miner's "Detect scoped SSRF" scan to detect a reverse proxy'
  2. 'Run "Exploit scoped SSRF" to find alternative routes to internal systems'
  3. 'On each alternate route, run "Guess headers" to find useful headers'
control_negativo: |
  # Control LITERAL de la fuente: el par del PASO 3 ES el control, y la fuente explica
  # por que los pasos 1 y 2 NO lo son.
  # A: mismo host dos veces seguidas -> la SEGUNDA mas rapida = hubo lookup DNS
  # B: el par del paso 2 (hosts distintos) -> NO prueba nada: el contenido difiere,
  #    asi que la diferencia de tiempo puede venir del contenido y no del DNS
  # Cita LITERAL de la fuente sobre por que el contenido no basta: 'These two responses
  # show that it's doing some kind of validation on the Host header, but there isn't
  # sufficient information to tell if it's an open proxy. If you rely on the response
  # content, you'll end up with both false positives and false negatives.'
  # C: [derivado] repetir A una tercera vez -> debe seguir rapida (cache caliente).
  #    Si vuelve a ser lenta, no era cache y la señal es ruido.
mata: |
  - El servidor no intenta resolver el Host -> no hay segunda respuesta mas rapida.
  - El resolver no cachea (ni fallos ni exitos) -> usar la variante del label largo.
  - La varianza de red es del orden de los 5ms de diferencia -> sin señal fiable.
  - FALSO POSITIVO documentado: ~170 de 375 dominios detectados NO generaban pingback
    porque una IP invalida hacia que una libreria upstream lanzara 'an exception and
    stopped the slow IP-lookup from happening'. La fuente dice 'I think' sobre esta
    explicacion: es una hipotesis, no una certeza.
fuente: "https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work (James Kettle, publicado 2024-08-07, act. 2024-11-18). Tablas, tiempos y citas literales. Cifras de la fuente: 375 dominios vulnerables, 206 con pingback, 217 con cache visible, ~170 sin pingback. Sin CVE. Google aparece como caso donde el scan fallo; la unica cifra de recompensa del articulo es el titulo enlazado '$10k host header' de Ezequiel Pereira, no un pago al autor."
confianza: alta
fecha: 2026-11-02
---
# [SSRF] Scoped SSRF detectada por caché DNS — la SSRF que ningún pingback ve

## Principio
Una SSRF *scoped* es una SSRF restringida a un dominio. El servidor reenvía al host que
indica la cabecera `Host`, pero solo si pertenece a un dominio permitido. Como el
atacante no puede alcanzar su propio servidor, **no hay pingback** — y toda la
metodología OAST, que es la estándar para SSRF, queda ciega.

La fuente acuña el nombre y es explícita sobre el hueco: *"I don't think there's an
established name for this type of SSRF, so I'll call it scoped SSRF"*, y *"it can't be
detected using pingback/OAST techniques."*

## El razonamiento que resuelve el problema
El contenido de la respuesta **no puede** distinguir dos cosas muy distintas:

- el servidor validó el `Host` y lo rechazó
- el servidor intentó conectar y falló

Las dos devuelven un 404. Pero solo la segunda genera una **resolución DNS**. Y una
resolución DNS deja huella en la caché del resolver, observable como una segunda
respuesta más rápida.

## Payload
El par que **no** prueba nada (hosts distintos, contenido distinto):

```
Host: foo.example.com   -> 404 Not Found   25ms
Host: foo.bar.com       -> 403 Forbidden   20ms
```

El par que **sí** prueba, con el mismo host dos veces:

```
Host: abc.example.com   -> 404 Not Found   25ms
Host: abc.example.com   -> 404 Not Found   20ms
```

Cita literal: *"The following request pair is what proves the issue - the faster second
response is evidence of DNS caching."*

Y si el resolver no cachea los fallos, la variante del label sobrelargo: *"sending an
overlong 64-octet DNS label, leading to the DNS client refusing to issue the lookup and a
faster response."*

```
Host: aaa{62}.example.com  -> 404 Not Found   25ms
Host: aaa{63}.example.com  -> 404 Not Found   20ms
```

**Advertencia:** la notación `{62}`/`{63}` es la de la fuente, pero su texto dice
"64-octet". La longitud exacta del label es ambigua en el original; hay que probar
varias.

## Por qué el control importa tanto aquí
Cita literal de la fuente sobre el error que evita:

> *"These two responses show that it's doing some kind of validation on the Host header,
> but there isn't sufficient information to tell if it's an open proxy. If you rely on the
> response content, you'll end up with both false positives and false negatives."*

El diseño del par —mismo host, dos veces— está construido para que **lo único que cambie
sea el estado de la caché**. Cualquier par con contenido distinto introduce una variable
que confunde la medición.

## El falso positivo que la fuente documenta
De 375 dominios detectados por timing, ~170 **no** generaban pingback. La explicación que
ofrece el autor: una IP inválida hacía que una librería upstream lanzara *"an exception and
stopped the slow IP-lookup from happening"*. Y es honesto al marcarla como hipótesis —
dice *"I think"*.

Esto encaja con la advertencia más importante del paper: *"timing attacks are
exceptionally good at detecting exceptions"*. Una excepción corta rutas de código y
produce respuestas **más rápidas**, que es exactamente la señal que se busca. Hay que
contar con ello antes de interpretar.

## Impacto
SSRF alcanzable que ningún escáner basado en pingback detecta. Y la fuente señala la vía
de escalada: tomar el control de un subdominio del dominio permitido y apuntar su DNS *"to
an arbitrary IP address"* convierte una scoped SSRF en una SSRF completa.

## Remediación
La fuente no da un arreglo a nivel de código. Su recomendación central es de modelo
mental: *"developers should understand that attacker visibility into their system's inner
workings goes beyond the actual response content"*, y *"Assume an attacker can read every
line of code that gets executed."*

`# [derivado]`: para esta clase concreta, la defensa efectiva es no enrutar por la
cabecera `Host` en absoluto — resolver el destino desde configuración — y aislar los
proxies inversos en una DMZ endurecida, como recomienda el paper de 2017 del mismo autor.
