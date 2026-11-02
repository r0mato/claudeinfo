---
clase: inyeccion
tech: graphql
cwe: CWE-200
cvss: 0.0 # [derivado] es el paso de descubrimiento, no la vulnerabilidad
payload: |
  # LA CONSULTA UNIVERSAL - LITERAL de la fuente.
  # Toda instancia de GraphQL la responde, asi que sirve como fingerprint.
  query{__typename}
  #
  # Respuesta esperada LITERAL de la fuente:
  {"data": {"__typename": "query"}}
  #
  # RUTAS A SONDEAR - LITERALES de la fuente, en este orden:
  /graphql
  /api
  /api/graphql
  /graphql/api
  /graphql/graphql
  # Si ninguna responde, la fuente indica probar ademas añadiendo /v1
  # (p.ej. /graphql/v1)
  #
  # Si POST no da nada util, la fuente dice reenviar la consulta universal con
  # OTROS metodos: GET, o x-www-form-urlencoded.
precondicion: "Ninguna mas alla de alcanzar el servidor por HTTP. La consulta universal no requiere autenticacion, ni conocer el esquema, ni que la introspeccion este habilitada: '__typename' es un campo meta que toda implementacion de GraphQL expone por especificacion."
como_se_descubre: |
  Es el primer paso de todo trabajo con GraphQL y cuesta 5 peticiones. El valor esta en
  que un endpoint GraphQL no autenticado suele quedar fuera del inventario de API del
  propio equipo: se despliega para la aplicacion movil o para un frontend concreto y no
  aparece en la documentacion.
  Señal adicional: revisar el historial HTTP del navegador mientras se usa la interfaz
  (la fuente recomienda hacerlo con el navegador de Burp). Si el frontend habla GraphQL,
  la ruta aparece ahi sin necesidad de adivinarla.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: POST {"query":"query{__typename}"} a la ruta candidata
  #    -> {"data":{"__typename":"query"}}  = hay GraphQL
  # B: POST la misma consulta a una ruta que SE SABE que no existe
  #    -> 404 o error de aplicacion, nunca la estructura {"data":{"__typename":...}}
  # El par B importa porque algunos frameworks devuelven 200 con una pagina de error
  # para cualquier ruta: sin B, un 200 se lee como 'hay GraphQL' cuando no lo hay.
  # C: si A falla con POST, repetir con GET y con x-www-form-urlencoded antes de
  #    descartar la ruta (indicacion explicita de la fuente).
mata: |
  - Ninguna de las rutas responde a la consulta universal con ningun metodo -> no hay
    endpoint GraphQL alcanzable ahi.
  - El endpoint exige autenticacion antes de parsear la consulta (devuelve 401 sin
    procesar) -> hace falta credencial primero.
  - ADVERTENCIA: la fuente usa el dominio generico insecure-website.com y no nombra
    ningun objetivo real. Lo reproducible es la tecnica sobre GraphQL como tecnologia.
fuente: "https://portswigger.net/web-security/graphql (PortSwigger Web Security Academy). Consulta universal, respuesta esperada y lista de rutas literales de la pagina. Burp Scanner emite la incidencia 'GraphQL endpoint found' segun la propia pagina."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Descubrimiento de endpoints GraphQL con la consulta universal

## Principio
`__typename` es un campo meta que la especificación obliga a exponer en toda
implementación de GraphQL. Eso lo convierte en un fingerprint perfecto: una sola
consulta que funciona siempre, sin autenticación, sin conocer el esquema y sin que la
introspección esté habilitada.

## Payload
```graphql
query{__typename}
```

Respuesta que confirma la presencia, literal de la fuente:

```json
{"data": {"__typename": "query"}}
```

Rutas a sondear, en el orden que da la fuente:

```
/graphql
/api
/api/graphql
/graphql/api
/graphql/graphql
```

Y si ninguna responde, la fuente indica probar añadiendo `/v1`.

## El detalle que más endpoints encuentra
Si `POST` no da nada útil, la fuente dice explícitamente reenviar la consulta universal
con **otros métodos**: `GET`, o `x-www-form-urlencoded`. Es la indicación que separa un
barrido superficial de uno completo — un endpoint que rechaza `POST` sin cuerpo JSON
puede contestar perfectamente a `GET`, y descartarlo tras una sola petición deja el
hallazgo en la mesa.

## Por qué este paso rinde
Un endpoint GraphQL suele quedar **fuera del inventario de API del propio equipo**: se
despliega para la aplicación móvil o para un frontend concreto y no entra en la
documentación pública ni en el alcance declarado. Eso lo convierte en superficie poco
revisada, que es exactamente el criterio del principio 12 de `docs/ELITE-MINDSET.md`
(los bugs críticos no están en las zonas más miradas).

Vía complementaria y gratuita: revisar el historial HTTP mientras se navega la interfaz.
Si el frontend habla GraphQL, la ruta real aparece ahí sin adivinar nada.

## Impacto
Ninguno directo — CVSS 0.0. Es el paso que habilita los demás writeups de GraphQL de
esta carpeta.

## Advertencia de procedencia
La fuente es material docente de la Web Security Academy: usa el dominio genérico
`insecure-website.com` y no nombra ningún objetivo real. Lo reproducible aquí es la
técnica sobre GraphQL **como tecnología nombrada**, con payloads literales y
específicos — el criterio con el que este catálogo acepta material docente.

## Remediación
De la fuente: si la API no es pública, deshabilitar la introspección; si lo es, revisar
el esquema buscando campos no intencionados. `# [derivado]`: lo primero es
**inventariar** el endpoint. Un GraphQL que el equipo de seguridad no sabe que existe no
está protegido por ninguna política, con independencia de cómo esté configurado.
