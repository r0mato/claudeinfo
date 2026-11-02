---
clase: inyeccion
tech: sql-multi-dbms
cwe: CWE-89
cvss: 0.0 # [derivado] son las primitivas de construccion, no una vulnerabilidad
payload: |
  # CONCATENACION DE CADENAS - LITERAL de la fuente:
  # Oracle:      'foo'||'bar'
  # Microsoft:   'foo'+'bar'
  # PostgreSQL:  'foo'||'bar'
  # MySQL:       'foo' 'bar'          <- nota de la fuente: espacio entre las dos cadenas
  # MySQL:       CONCAT('foo','bar')
  #
  # SUBSTRING - LITERAL de la fuente. Nota de la pagina: desplazamiento con base 1,
  # los ejemplos devuelven 'ba':
  # Oracle:      SUBSTR('foobar', 4, 2)
  # Microsoft:   SUBSTRING('foobar', 4, 2)
  # PostgreSQL:  SUBSTRING('foobar', 4, 2)
  # MySQL:       SUBSTRING('foobar', 4, 2)
  #
  # COMENTARIOS - LITERAL de la fuente:
  # Oracle:      --comment
  # Microsoft:   --comment      /*comment*/
  # PostgreSQL:  --comment      /*comment*/
  # MySQL:       #comment       -- comment      /*comment*/
  #              ^ nota de la fuente: MySQL requiere un ESPACIO tras el doble guion
  #
  # CONSULTAS APILADAS (batched) - LITERAL de la fuente:
  # Oracle:      no soportadas. Cita literal: 'Does not support batched queries.'
  # Microsoft:   QUERY-1-HERE; QUERY-2-HERE     y tambien   QUERY-1-HERE QUERY-2-HERE
  # PostgreSQL:  QUERY-1-HERE; QUERY-2-HERE
  # MySQL:       QUERY-1-HERE; QUERY-2-HERE
  #              nota de la fuente: normalmente NO se pueden usar para inyeccion SQL,
  #              aunque ocasionalmente es posible mediante ciertas APIs de PHP o Python.
precondicion: "Inyeccion SQL confirmada. Estas son las primitivas con las que se construyen los payloads de las demas tecnicas: sin substring no hay extraccion caracter a caracter, y sin la sintaxis correcta de comentario no se trunca la consulta original."
como_se_descubre: |
  Doble uso.
  (1) Como PRIMITIVAS: substring es lo que permite extraer un caracter por peticion en
      las tecnicas ciegas; la concatenacion permite inyectar el valor robado dentro de
      otra expresion (p.ej. en EXTRACTVALUE de MySQL).
  (2) Como FINGERPRINT: las tres difieren por motor, asi que probar cual no da error
      identifica la familia sin necesidad de leer ninguna version. Esto es util cuando
      SELECT @@version no es alcanzable o un WAF bloquea la palabra 'version'.
  Las dos notas sintacticas valen mas que el resto: el ESPACIO tras '--' en MySQL y el
  ESPACIO entre cadenas en 'foo' 'bar' son causa frecuente de payloads que fallan por
  razones que no se ven al leerlos.
control_negativo: |
  # [derivado] diseño de test A/B, usado como fingerprint
  # A: 'foo'||'bar'   -> funciona en Oracle y PostgreSQL, ERROR en Microsoft y MySQL
  # B: 'foo'+'bar'    -> funciona en Microsoft; en MySQL suma numericamente (da 0)
  # C: 'foo' 'bar'    -> funciona en MySQL
  # La lectura es el PATRON de exitos y fallos, no un solo resultado. B merece
  # atencion: en MySQL no da error, da 0, lo que es un falso negativo silencioso si se
  # espera un error como señal.
mata: |
  - No hay inyeccion -> no aplica.
  - Contexto de inyeccion que no admite expresiones de cadena (p.ej. solo numerico).
  - WAF que bloquee los operadores o las palabras clave.
  - Oracle: no soporta consultas apiladas, en ningun caso.
fuente: "https://portswigger.net/web-security/sql-injection/cheat-sheet (secciones 'String concatenation', 'Substring', 'Comments' y 'Batched (stacked) queries'). Payloads, notas sintacticas y la cita sobre Oracle son literales de la pagina. SQLite no figura en la pagina."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Primitivas por motor — concatenación, substring, comentarios y consultas apiladas

## Principio
Estas no son técnicas de explotación sino las piezas con las que se construyen las
demás: sin `SUBSTRING` no hay extracción carácter a carácter, y sin la sintaxis correcta
de comentario no se trunca la consulta original. Tienen además un segundo uso que suele
pasarse por alto: como **fingerprint**, porque difieren por motor.

## Payload
**Concatenación**
```sql
-- Oracle         'foo'||'bar'
-- Microsoft      'foo'+'bar'
-- PostgreSQL     'foo'||'bar'
-- MySQL          'foo' 'bar'          -- espacio entre las dos cadenas
-- MySQL          CONCAT('foo','bar')
```

**Substring** (desplazamiento con base 1; todos devuelven `ba`)
```sql
-- Oracle         SUBSTR('foobar', 4, 2)
-- Microsoft      SUBSTRING('foobar', 4, 2)
-- PostgreSQL     SUBSTRING('foobar', 4, 2)
-- MySQL          SUBSTRING('foobar', 4, 2)
```

**Comentarios**
```sql
-- Oracle         --comment
-- Microsoft      --comment      /*comment*/
-- PostgreSQL     --comment      /*comment*/
-- MySQL          #comment       -- comment      /*comment*/
```

**Consultas apiladas**
```sql
-- Oracle         no soportadas: "Does not support batched queries."
-- Microsoft      QUERY-1-HERE; QUERY-2-HERE    y    QUERY-1-HERE QUERY-2-HERE
-- PostgreSQL     QUERY-1-HERE; QUERY-2-HERE
-- MySQL          QUERY-1-HERE; QUERY-2-HERE
```

Sobre MySQL, la fuente matiza que normalmente **no** se pueden usar para inyección SQL,
aunque ocasionalmente es posible a través de ciertas APIs de PHP o Python.

## Las dos notas que arruinan más payloads
**MySQL exige un espacio tras el doble guion.** `--comment` no comenta en MySQL;
`-- comment` sí. Y la concatenación de MySQL por yuxtaposición necesita el espacio:
`'foo' 'bar'`. Son dos caracteres invisibles al leer un payload, y cuando faltan el
fallo no se parece a un error de sintaxis sino a "el objetivo no es vulnerable".

Microsoft acepta además consultas apiladas **sin punto y coma** (`QUERY-1-HERE
QUERY-2-HERE`), lo que es útil cuando un filtro bloquea el `;`.

## Fingerprint por tolerancia
El patrón de éxitos y fallos identifica el motor sin leer ninguna versión, lo que sirve
cuando `SELECT @@version` no es alcanzable o un WAF bloquea la palabra. Hay un falso
negativo que conviene conocer: `'foo'+'bar'` en MySQL **no da error**, suma
numéricamente y devuelve `0`. Si se espera un error como señal de "motor incorrecto",
MySQL pasará desapercibido.

## Impacto
Ninguno directo — CVSS 0.0. Son las primitivas de las que dependen los demás writeups
de esta carpeta.

## Remediación
Consultas parametrizadas. Filtrar caracteres o palabras clave (comillas, `--`, `;`) es
insuficiente por construcción: este writeup es, en buena medida, el catálogo de formas
alternativas de escribir lo mismo.
