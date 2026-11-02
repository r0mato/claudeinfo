---
clase: auth
tech: jwt-kid
cwe: CWE-22
cvss: 9.1 # [derivado] firma valida con secreto conocido (cadena vacia)
payload: |
  # Cabecera LITERAL de la fuente:
  { "kid": "../../path/to/file", "typ": "JWT", "alg": "HS256", "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc" }
  #
  # EL CASO ELEGANTE, descrito por la fuente: apuntar kid a /dev/null
  #   { "kid": "../../../dev/null", "typ": "JWT", "alg": "HS256" }
  # /dev/null se lee como CADENA VACIA. Firmando el token con una cadena vacia como
  # secreto HMAC, la firma es valida.
  # (La cabecera con ../../path/to/file es literal de la fuente; la variante concreta
  #  con /dev/null es reconstruccion mia a partir de su descripcion en prosa.)
  #
  # La fuente señala tambien un vector de SQLi si las claves se guardan en BD.
precondicion: "El valor de 'kid' se usa como parte de una ruta de fichero SIN validacion, y el servidor acepta un algoritmo simetrico (HS256). Las dos condiciones son necesarias: el traversal da el fichero, y el algoritmo simetrico es lo que permite usar su contenido como secreto HMAC."
como_se_descubre: |
  Señal en recon: cabecera 'kid' presente, y alg simetrico. Sonda de traversal:
  valores como '../../../etc/passwd' producen a menudo un error distinto del rechazo
  normal de firma, y ese cambio de error es la pista de que el valor llega al sistema
  de ficheros.
  El razonamiento clave: no hay que ADIVINAR el contenido de un fichero para usarlo
  como clave. Basta elegir un fichero cuyo contenido sea CONOCIDO y constante.
  /dev/null es el candidato perfecto porque su contenido es la cadena vacia en todos
  los sistemas.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: kid='../../../dev/null' + token firmado con secreto = cadena vacia -> aceptado
  # B: kid='../../../dev/null' + token firmado con un secreto NO vacio    -> rechazado
  # El par B demuestra que la clave usada es realmente el contenido del fichero, y no
  # que la firma se ignore. Sin B, el hallazgo es ambiguo.
  # C: kid apuntando a un fichero inexistente -> error distinto; mapea el comportamiento
mata: |
  - 'kid' se valida contra una allowlist de identificadores conocidos -> muere.
  - El servidor solo acepta algoritmos asimetricos: aunque haya traversal, el contenido
    del fichero no sirve como clave HMAC.
  - B tambien se acepta -> la firma no se verifica (otro writeup).
  - El proceso no puede leer la ruta (permisos, contenedor sin /dev/null accesible).
fuente: "https://portswigger.net/web-security/jwt (seccion 'Injecting self-signed JWTs via the kid parameter'). Cabecera con '../../path/to/file' literal de la pagina; el caso /dev/null se describe en prosa en la pagina y la cabecera concreta es reconstruccion."
confianza: media
fecha: 2026-11-02
---
# [AUTH] `kid` como path traversal — firmar con el contenido de `/dev/null`

## Principio
`kid` (*key ID*) identifica cuál de varias claves usar. Si la implementación lo
convierte en una ruta de fichero sin validar, el atacante elige qué fichero se lee como
clave. El salto conceptual que hace el ataque viable es este: **no hay que adivinar el
contenido del fichero**. Basta elegir uno cuyo contenido se conozca de antemano. Y hay
un fichero cuyo contenido es conocido, constante y vacío en todo sistema Unix.

## Payload
Cabecera literal de la fuente:

```json
{ "kid": "../../path/to/file", "typ": "JWT", "alg": "HS256", "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc" }
```

El caso que la fuente describe en prosa, y cuya cabecera concreta reconstruyo:

```json
{ "kid": "../../../dev/null", "typ": "JWT", "alg": "HS256" }
```

`/dev/null` se lee como cadena vacía. Firmando el token con **la cadena vacía** como
secreto HMAC, la firma es válida y el servidor la acepta.

## Por qué hacen falta las dos precondiciones
El traversal por sí solo no basta, y el algoritmo simétrico por sí solo tampoco. El
traversal da control sobre *qué fichero se lee*; el algoritmo simétrico es lo que
permite que el contenido de ese fichero funcione como **secreto compartido** con el que
el atacante también puede firmar. Con RS256 el contenido del fichero tendría que ser
una clave privada válida, lo que devuelve el problema a adivinar.

## Impacto
Suplantación total con firma criptográficamente válida. La fuente añade una segunda vía
en el mismo parámetro: si las claves se guardan en base de datos, `kid` puede ser un
punto de inyección SQL — lo que convierte una cabecera de JWT en superficie de ataque
sobre el almacén de credenciales.

## Remediación
Cita literal: *"Make sure that you're not vulnerable to path traversal or SQL injection
via the `kid` header parameter."* `# [derivado]`: tratar `kid` como un identificador
opaco que se busca en una allowlist o en un mapa cerrado, nunca como ruta ni como
fragmento de consulta. La regla general de la familia sigue valiendo: la clave de
verificación se resuelve desde configuración del servidor, no desde el token.
