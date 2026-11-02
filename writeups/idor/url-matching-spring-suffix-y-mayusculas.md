---
clase: idor
tech: spring-framework
cwe: CWE-289
cvss: 8.8 # [derivado] acceso a funcionalidad administrativa
payload: |
  # Las tres discrepancias LITERALES de la fuente, sobre el endpoint /admin/deleteUser:
  #
  # 1) MAYUSCULAS. Cita literal: 'a request to /ADMIN/DELETEUSER may still be mapped
  #    to the /admin/deleteUser endpoint.'
  /ADMIN/DELETEUSER
  #
  # 2) SUFIJO (Spring 'useSuffixPatternMatch'). Cita literal: 'a request to
  #    /admin/deleteUser.anything would still match the /admin/deleteUser pattern.
  #    Prior to Spring 5.3, this option is enabled by default.'
  /admin/deleteUser.anything
  #
  # 3) BARRA FINAL. La fuente contrapone /admin/deleteUser y /admin/deleteUser/ y dice:
  #    'you may be able to bypass access controls by appending a trailing slash to
  #    the path.'
  /admin/deleteUser/
precondicion: "El mecanismo de control de acceso y el de enrutamiento normalizan la ruta de forma DISTINTA. Cita literal sobre el efecto: el mecanismo menos tolerante 'may treat these as two different endpoints and fail to enforce the correct restrictions'. Para la variante de sufijo, la precondicion es concreta y VERSIONADA: Spring anterior a 5.3, donde useSuffixPatternMatch esta activo por defecto."
como_se_descubre: |
  Señal en recon: cabeceras o comportamiento que delaten Spring (y, por tanto, version
  anterior a 5.3). Sonda sobre cualquier ruta que devuelva 403: reenviarla en
  mayusculas, con '.anything' al final y con barra final, y comparar las tres
  respuestas con la original.
  Las tres son peticiones, cuestan nada, y cada una prueba una normalizacion distinta.
  Conviene probarlas SIEMPRE que exista un 403 por ruta: son el equivalente, en el
  enrutador, de lo que X-Original-URL es en el proxy.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: GET /admin/deleteUser.anything  -> ejecuta (403 esquivado)
  # B: GET /admin/deleteUser           -> 403
  # C: GET /admin/rutaInexistente.anything -> 404
  # El control C importa: descarta que el servidor acepte CUALQUIER ruta con sufijo.
  # Si C devuelve 200, la aplicacion esta sirviendo algo generico y A no prueba
  # bypass de autorizacion sino otra cosa.
mata: |
  - Spring 5.3 o posterior (useSuffixPatternMatch desactivado por defecto) -> muere (2).
  - El control de acceso y el enrutador comparten la MISMA funcion de normalizacion.
  - Las tres variantes devuelven 403 igual que la ruta original.
  - El control se aplica por identidad y recurso, no por coincidencia de cadena de ruta.
fuente: "https://portswigger.net/web-security/access-control (seccion 'Broken access control resulting from URL-matching discrepancies'). Las tres variantes y la nota de version de Spring son literales de la pagina."
confianza: alta
fecha: 2026-11-02
---
# [IDOR] Discrepancias de coincidencia de URL — mayúsculas, sufijo (Spring <5.3) y barra final

## Principio
Hay dos componentes leyendo la misma ruta: el que decide si estás autorizado y el que
decide qué código ejecutar. Si normalizan distinto, existe una cadena que el primero
considera "otra ruta" (y por tanto no restringe) y el segundo mapea al endpoint
protegido. Cita literal sobre el efecto: el mecanismo menos tolerante *"may treat these
as two different endpoints and fail to enforce the correct restrictions"*.

## Payload
Sobre un endpoint `/admin/deleteUser` protegido:

**Mayúsculas** — *"a request to `/ADMIN/DELETEUSER` may still be mapped to the
`/admin/deleteUser` endpoint."*

```
/ADMIN/DELETEUSER
```

**Sufijo** — *"a request to `/admin/deleteUser.anything` would still match the
`/admin/deleteUser` pattern. Prior to Spring 5.3, this option is enabled by default."*

```
/admin/deleteUser.anything
```

**Barra final** — *"you may be able to bypass access controls by appending a trailing
slash to the path."*

```
/admin/deleteUser/
```

## Por qué la variante de Spring es la más valiosa
Es la única de las tres con una **precondición versionada y verificable**: Spring
anterior a 5.3, donde `useSuffixPatternMatch` está activo por defecto. Eso la convierte
en algo que se puede buscar a escala —detectar la versión y probar el sufijo— en lugar
de una sonda a ciegas. Y el hecho de que fuera el **comportamiento por defecto**
significa que la población afectada no son despliegues mal configurados, sino
despliegues normales de una versión concreta.

## Impacto
Acceso a funcionalidad administrativa. El patrón se repite para cualquier control
basado en coincidencia de cadena de ruta, incluidas reglas de WAF y de proxy, así que
las tres sondas tienen valor más allá del enrutador de la aplicación.

## Remediación
De la fuente: *"Wherever possible, use a single application-wide mechanism for enforcing
access controls."* Y: *"At the code level, make it mandatory for developers to declare
the access that is allowed for each resource, and deny access by default."*

`# [derivado]`: actualizar a Spring 5.3 o posterior cierra la variante de sufijo. La
corrección estructural es que la autorización se decida sobre el **recurso ya
resuelto** —el controlador y el objeto concretos— y no sobre la cadena de la petición;
mientras se autorice comparando texto, cada diferencia de normalización será un bypass.
