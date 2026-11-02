---
clase: idor
tech: referer-header
cwe: CWE-290
cvss: 8.8 # [derivado] acceso a funcionalidad administrativa
payload: |
  # Mecanica LITERAL de la fuente: '/admin' esta bien protegido, pero las subpaginas
  # como '/admin/deleteUser' solo inspeccionan la cabecera Referer.
  # Cita literal: 'If the Referer header contains the main /admin URL, then the
  # request is allowed.'
  #
  # La fuente NO da un valor literal de Referer. Por la mecanica que describe:
  GET /admin/deleteUser HTTP/1.1
  Referer: https://insecure-website.com/admin
  #
  # ADVERTENCIA: la peticion de arriba es RECONSTRUCCION mia a partir de la
  # descripcion en prosa. Lo literal de la fuente son: las rutas '/admin' y
  # '/admin/deleteUser', el nombre de cabecera 'Referer', y la frase citada.
  #
  # Observacion clave LITERAL de la fuente:
  #   'the Referer header can be fully controlled by an attacker.'
precondicion: "La pagina principal (/admin) tiene control de acceso robusto, pero las subpaginas delegan la decision en la cabecera Referer. Como el atacante controla por completo esa cabecera, el control es nominal."
como_se_descubre: |
  Señal en recon: /admin devuelve 403 pero una subruta como /admin/deleteUser responde
  distinto (otro codigo, otro cuerpo, otro tiempo). Esa asimetria sugiere que las
  subrutas se evaluan con otra regla.
  Sonda: pedir la subruta DOS veces, una sin Referer y otra con
  'Referer: https://<host>/admin'. Si solo la segunda funciona, el control es el Referer.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: GET /admin/deleteUser con 'Referer: https://<host>/admin'  -> ejecuta
  # B: GET /admin/deleteUser SIN cabecera Referer                  -> denegado
  # C: GET /admin                                                  -> 403 (control real)
  # El trio demuestra las tres piezas: C que el control existe, B que la subruta esta
  # protegida de base, A que el Referer lo abre. Sin B es imposible saber si la
  # subruta estaba protegida siquiera.
mata: |
  - Las subpaginas comprueban la identidad del usuario, no el Referer -> muere.
  - B tambien funciona -> la subruta nunca estuvo protegida; el hallazgo es
    'funcionalidad no protegida', no bypass por Referer.
  - Control de acceso centralizado aplicado a /admin y a todo su subarbol.
fuente: "https://portswigger.net/web-security/access-control (seccion 'Referer-based access control'). Rutas, nombre de cabecera y las dos frases citadas son literales; la pagina NO da un valor de ejemplo para Referer y la peticion completa es reconstruccion."
confianza: media
fecha: 2026-11-02
---
# [IDOR] Control de acceso basado en `Referer` — proteger la puerta y dejar las ventanas

## Principio
Es un patrón que surge de la pereza arquitectónica más que del desconocimiento: se
protege con rigor `/admin`, y para las subpáginas se asume que "si llegas aquí, es que
ya pasaste por allí". La comprobación se delega en la cabecera `Referer`. Pero el
`Referer` lo pone el cliente, y la propia fuente lo dice sin rodeos: *"the `Referer`
header can be fully controlled by an attacker."*

El control no es débil: es inexistente, con la apariencia de existir.

## Payload
Mecánica literal: *"If the `Referer` header contains the main `/admin` URL, then the
request is allowed."*

```http
GET /admin/deleteUser HTTP/1.1
Referer: https://insecure-website.com/admin
```

**Advertencia de procedencia:** la fuente no publica un valor de ejemplo para `Referer`.
Lo literal son las rutas, el nombre de la cabecera y las frases citadas; la petición
completa es reconstrucción mía a partir de la descripción en prosa. De ahí
`confianza: media`.

## Señal de recon
La asimetría es la pista: `/admin` devuelve 403 pero una subruta responde de otra forma
—otro código, otro cuerpo, otro tiempo. Cuando dos rutas del mismo subárbol se comportan
distinto frente al mismo usuario, están siendo evaluadas por reglas distintas, y una de
las dos reglas suele ser más débil.

## Por qué el control sin `Referer` es imprescindible
Si solo se prueba la petición **con** `Referer` y funciona, no se sabe nada: puede que
la subruta nunca estuviera protegida. La petición sin la cabecera es la que distingue
"bypass por Referer" de "funcionalidad simplemente no protegida". Son hallazgos
distintos, con correcciones distintas, y la diferencia es una petición.

## Impacto
Acceso a la funcionalidad administrativa de todo el subárbol. Y como el patrón suele
aplicarse de forma uniforme, confirmarlo en una subruta normalmente implica que todas
las hermanas son alcanzables igual.

## Remediación
De la fuente: *"Wherever possible, use a single application-wide mechanism for enforcing
access controls."* Es literalmente el remedio de este caso: el problema es que
`/admin` y `/admin/*` se protegen con mecanismos distintos.

`# [derivado]`: ninguna decisión de autorización debe depender de una cabecera que el
cliente controla. `Referer` no es un dato de autenticación — es una pista de navegación
opcional que el navegador puede omitir por política de privacidad, por lo que además
rompe a usuarios legítimos.
