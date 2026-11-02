---
clase: ssrf
tech: url-schemes
cwe: CWE-918
cvss: 8.6 # [derivado] lectura de ficheros locales e interaccion con servicios no HTTP
payload: |
  # Esquemas LITERALES de la fuente (los lista en su seccion de notas):
  file://
  phar://
  gopher://
  data://
  dict://
  #
  # ADVERTENCIA DE PROCEDENCIA: la fuente lista los NOMBRES de esquema y nada mas.
  # NO da URLs de ejemplo completas para ninguno de ellos. No las construyo de
  # memoria. Lo reproducible aqui es la LISTA de esquemas a probar, que es
  # precisamente el valor practico: son los cinco que hay que incluir en la sonda.
  #
  # Para que sirve cada uno (razonamiento mio, no de la fuente):
  #   file://    lectura de ficheros del sistema local
  #   phar://    deserializacion en PHP a partir de un archivo phar
  #   gopher://  construccion de peticiones TCP casi arbitrarias (Redis, SMTP, etc.)
  #   data://    inyeccion de contenido en linea sin servidor externo
  #   dict://    interaccion con servicios por protocolo DICT
  #
  # Protocolos que la fuente dice permitir (Case 2, restriccion literal):
  #   HTTP  o  HTTPS
precondicion: "El cliente HTTP de la aplicacion admite esquemas distintos de http/https. Depende de la libreria: muchos clientes de alto nivel solo hablan HTTP, mientras que envoltorios de libcurl o funciones de fichero de PHP admiten varios. La precondicion es de LIBRERIA, no de aplicacion."
como_se_descubre: |
  Tras confirmar una SSRF, probar los cinco esquemas es una sonda de coste bajo y alto
  rendimiento: cada uno que funcione amplia la clase de vulnerabilidad a otra cosa
  (file:// la convierte en lectura de ficheros, phar:// en deserializacion,
  gopher:// en interaccion con servicios internos no HTTP).
  Señal previa: si la funcionalidad usa PHP y pasa la URL a una funcion de fichero
  (file_get_contents, fopen), la probabilidad de que admita esquemas es alta.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: esquema file:// apuntando a un fichero que SE SABE que existe
  #    -> contenido en la respuesta o diferencia observable
  # B: esquema file:// apuntando a un fichero inexistente
  #    -> error DISTINTO del de A
  # El par A/B distingue 'el esquema se admite' de 'el esquema se rechaza': si A y B
  # dan el mismo error, el esquema esta bloqueado y no es que el fichero falte.
  # C: http:// a un host controlado -> confirma que la SSRF base funciona
mata: |
  - El cliente HTTP solo admite http y https -> mueren todos.
  - Allowlist de protocolos aplicada antes de la peticion (la defensa de la fuente).
  - A y B producen el mismo error -> el esquema esta bloqueado.
  - phar:// requiere ademas que exista una cadena de deserializacion explotable.
fuente: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html (seccion de notas). Los cinco nombres de esquema y la restriccion 'HTTP o HTTPS' son literales de la pagina; la pagina NO da URLs de ejemplo. Los usos por esquema son analisis mio."
confianza: media
fecha: 2026-11-02
---
# [SSRF] Esquemas de URL no HTTP — `file://`, `phar://`, `gopher://`, `data://`, `dict://`

## Principio
Una SSRF se piensa normalmente como "hacer que el servidor pida una URL HTTP". Si el
cliente admite otros esquemas, la vulnerabilidad deja de ser una sola cosa: `file://`
la convierte en lectura de ficheros locales, `phar://` en deserialización, `gopher://`
en la capacidad de construir peticiones TCP casi arbitrarias contra servicios internos
que no hablan HTTP.

Lo decisivo es que esto **no depende de la aplicación sino de la librería**. El mismo
código es una SSRF modesta con un cliente HTTP de alto nivel y una lectura de ficheros
con un envoltorio de libcurl o una función de fichero de PHP.

## Payload
Los esquemas, literales de la fuente:

```
file://
phar://
gopher://
data://
dict://
```

## Advertencia de procedencia
La fuente lista los **nombres** de esquema y nada más: no da URLs de ejemplo completas
para ninguno. No las construyo de memoria. Lo reproducible y útil aquí es la lista en sí
—son los cinco que hay que incluir en la sonda— y eso es lo que aporta el writeup. Para
la forma concreta de cada URL hay que acudir a la documentación del protocolo. De ahí
`confianza: media`.

Lo que sigue es análisis mío, no de la fuente, y lo marco como tal:

| Esquema | Para qué sirve |
|---|---|
| `file://` | lectura de ficheros del sistema local |
| `phar://` | deserialización en PHP desde un archivo phar |
| `gopher://` | peticiones TCP casi arbitrarias (Redis, SMTP…) |
| `data://` | inyectar contenido en línea, sin servidor externo |
| `dict://` | interacción con servicios por protocolo DICT |

## El control negativo con un fichero inexistente
Es el que separa "el esquema está bloqueado" de "el fichero no existe". Los dos
producen un error, y si no se comparan, un esquema que **sí** funciona se descarta por
haber elegido mal la ruta de prueba. Dos peticiones resuelven la ambigüedad.

## Impacto
Variable y potencialmente mayor que el de la SSRF original: lectura de credenciales en
ficheros de configuración, deserialización hasta ejecución de código, o escritura en un
Redis interno vía `gopher://`.

## Remediación
La restricción literal que da la fuente es una allowlist de protocolos: **`HTTP` o
`HTTPS`**, aplicada antes de realizar la petición. `# [derivado]`: conviene aplicarla
sobre el esquema ya parseado por la misma librería que hará la conexión, no sobre la
cadena de entrada — si se valida con un parser y se conecta con otro, reaparece el
problema de confusión de parsers del writeup `parser-confusion-backslash-arroba`.
