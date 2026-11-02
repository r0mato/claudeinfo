---
clase: ssrf
tech: python-urllib
cwe: CWE-918
cvss: 8.6 # [derivado] SSRF con bypass de validacion de host
payload: |
  # URL de ataque - LITERAL de la fuente:
  http://example.com\@evil.com
  #
  # COMPORTAMIENTO LITERAL de la fuente (Python urllib):
  urlsplit("http://example.com\@evil.com").hostname
  # devuelve:  evil.com
  #
  # La fuente cita el mecanismo: netloc.rpartition('@')
  # Es decir, urlsplit parte el netloc por la ULTIMA '@', asi que todo lo anterior se
  # trata como credenciales y lo posterior como host. La barra invertida no impide el
  # reparto.
  #
  # Valor de prueba que la fuente usa para validacion de dominio - LITERAL:
  <script>alert(1)</script>.owasp.org
precondicion: "El codigo valida el host de una URL con un parser y realiza la peticion con OTRO (o con el mismo parser pero leyendo un campo distinto). El validador lee 'example.com' y el cliente HTTP conecta a 'evil.com'. Confirmado en la fuente para Python urllib."
como_se_descubre: |
  Señal en recon: funcionalidad que acepta una URL COMPLETA del usuario y la valida
  por dominio (webhooks, importadores, validadores de enlaces, miniaturas).
  Sonda: enviar 'http://dominio-permitido\@host-controlado/' y observar si llega una
  peticion al host controlado. Si llega, hay confusion de parsers.
  La advertencia de la fuente sobre por que esto ocurre tanto es directa:
  'Do not accept complete URLs from the user because URL are difficult to validate and
  the parser can be abused depending on the technology used'.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: http://dominio-permitido\@host-controlado/   -> llega peticion a host-controlado
  # B: http://host-controlado/                       -> BLOQUEADO por el validador
  # El par A/B es el informe completo: B prueba que el validador FUNCIONA, A que se
  # puede esquivar. Sin B, el triador puede pensar que no habia validacion alguna y
  # clasificar mal la severidad.
  # C: http://dominio-permitido/  -> permitido (comportamiento normal)
mata: |
  - Se valida el HOST resuelto y no la cadena de la URL -> muere.
  - El codigo no acepta URLs completas, sino que recibe un identificador y CONSTRUYE
    la URL en servidor (la recomendacion de la fuente).
  - El mismo parser decide validacion y conexion, leyendo el mismo campo.
  - Allowlist aplicada sobre la IP de destino en el momento de conectar.
fuente: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html. La URL de ataque, el comportamiento de urlsplit, la referencia a netloc.rpartition('@') y el valor de prueba son literales de la pagina."
confianza: alta
fecha: 2026-11-02
---
# [SSRF] Confusión de parsers con `\@` — el validador lee un host y el cliente conecta a otro

## Principio
Validar una URL y usarla son dos operaciones que suelen recaer en parsers distintos, o
en el mismo parser leyendo campos distintos. Basta que discrepen en un carácter. La
sintaxis de URL permite credenciales antes de la `@`, y `urlsplit` de Python parte el
netloc por la **última** `@` — usando `netloc.rpartition('@')`. Así que todo lo anterior
se trata como usuario y lo posterior como host, y la barra invertida no altera ese
reparto.

## Payload
```
http://example.com\@evil.com
```

Comportamiento literal en Python:

```python
urlsplit("http://example.com\@evil.com").hostname
# -> 'evil.com'
```

Un validador que haga una comprobación textual —"¿empieza por un dominio permitido?"—
ve `example.com`. El cliente HTTP conecta a `evil.com`.

La fuente da también un valor útil para probar la tolerancia del validador de dominios:

```
<script>alert(1)</script>.owasp.org
```

## El control negativo decide la severidad
Hay que demostrar **las dos** cosas: que el validador funciona (enviar el host del
atacante a pelo y comprobar que se bloquea) y que se puede esquivar. Si solo se muestra
el payload que pasa, la lectura natural es "no había validación", lo que rebaja el
hallazgo a una omisión trivial en lugar de un bypass de un control existente. Es la
diferencia entre un informe que se prioriza y uno que se cierra.

## Impacto
SSRF con destino controlado: alcance a servicios internos, a endpoints de metadata
cloud, y a cualquier cosa que el servidor pueda ver y el atacante no.

## Remediación
Las citas literales de la fuente son inusualmente precisas en este punto:

> *"Do not accept complete URLs from the user because URL are difficult to validate and
> the parser can be abused depending on the technology used"*

> *"Match the host against an allowlist, and build the request yourself."*

> *"Treat parser disagreement as a rejection."*

> *"Reject a URL whose host is not read identically by every parser in play, rather than
> reconciling the readings."*

Esa última merece subrayarse porque es la regla general y no una mitigación puntual:
ante dos lecturas distintas de la misma URL, la respuesta correcta es **rechazar**, no
elegir una. Intentar reconciliar lecturas es cómo se construyen los bypasses de la
siguiente generación.

La fuente añade: *"Use the output value of the method/library as the IP address to
compare against the allowlist."* — comparar lo que se va a usar, no lo que se recibió.
