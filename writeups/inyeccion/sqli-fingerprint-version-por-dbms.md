---
clase: inyeccion
tech: sql-multi-dbms
cwe: CWE-89
cvss: 0.0 # [derivado] no es la vulnerabilidad: es el paso de identificacion que decide todo lo demas
payload: |
  # Consultas LITERALES de la fuente para obtener la version, por DBMS:
  #
  # Oracle:
  SELECT banner FROM v$version
  SELECT version FROM v$instance
  #
  # Microsoft (MSSQL):
  SELECT @@version
  #
  # PostgreSQL:
  SELECT version()
  #
  # MySQL:
  SELECT @@version
  #
  # Notese que Microsoft y MySQL comparten la MISMA sintaxis (@@version): esta
  # consulta sola no los distingue. Para separarlos hay que usar otro eje, p.ej.
  # los comentarios (ver writeup sqli-concatenacion-comentarios-por-dbms):
  # MySQL exige espacio tras '--', Microsoft no.
  #
  # SQLite NO aparece en ninguna parte de la pagina fuente.
precondicion: "Existe un punto de inyeccion SQL ya confirmado. Este writeup no sirve para DESCUBRIR la inyeccion, sino para identificar el motor una vez confirmada. Hace falta un canal de salida: union, mensaje de error, o un oraculo booleano/temporal."
como_se_descubre: |
  Es el PRIMER paso tras confirmar una inyeccion, y el de mayor rendimiento: casi
  todas las tecnicas posteriores (enumeracion de esquema, retardos, errores
  condicionales) tienen sintaxis DISTINTA por motor, asi que identificar mal el motor
  hace fracasar todo lo siguiente y produce la conclusion erronea de 'no explotable'.
  Via alternativa cuando no hay canal directo: probar las variantes de CONCATENACION,
  que difieren por motor ('foo'||'bar' en Oracle/PostgreSQL, 'foo'+'bar' en Microsoft,
  'foo' 'bar' en MySQL). La que no provoque error identifica la familia.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: la consulta de version del motor SOSPECHADO -> devuelve una cadena de version
  # B: la consulta de version de OTRO motor         -> error de sintaxis
  # El par es el fingerprint: lo informativo es la combinacion de la que funciona y
  # las que fallan, no solo el exito de una.
  # Si NINGUNA funciona, el canal de salida no esta operativo (no es que falte el
  # motor): revisar primero el canal antes de concluir nada.
mata: |
  - No hay canal de salida operativo -> no se puede leer la respuesta (revisar el canal).
  - La inyeccion esta en un contexto que no admite SELECT (p.ej. solo ORDER BY)
    -> usar otro eje de fingerprint, como la concatenacion.
  - WAF que bloquee 'version' por palabra clave -> probar el eje de comentarios.
fuente: "https://portswigger.net/web-security/sql-injection/cheat-sheet (PortSwigger SQL injection cheat sheet). Consultas literales de la pagina. SQLite no figura en la pagina."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Fingerprint del motor SQL — el paso que decide si todo lo demás funciona

## Principio
Casi nada de la explotación SQL es portable. La enumeración de esquema, los retardos,
los errores condicionales y la extracción por mensajes de error tienen sintaxis distinta
en cada motor. Por eso identificar el motor no es un paso preliminar opcional: es la
bifurcación de la que cuelga el resto del árbol. Equivocarse aquí produce una secuencia
de errores de sintaxis que se interpretan, falsamente, como "no explotable".

## Payload
```sql
-- Oracle
SELECT banner FROM v$version
SELECT version FROM v$instance

-- Microsoft (MSSQL)
SELECT @@version

-- PostgreSQL
SELECT version()

-- MySQL
SELECT @@version
```

## El detalle que importa
**Microsoft y MySQL comparten `@@version`.** Esta consulta sola no los distingue, y
confundirlos lleva a elegir mal la sintaxis de retardo (`WAITFOR DELAY` frente a
`SLEEP`) y la de errores condicionales. Para separarlos hay que usar otro eje — el de
los comentarios es el más limpio: MySQL exige un espacio tras `--`, Microsoft no.

SQLite no aparece en la página fuente, así que no lo incluyo: cualquier payload para
SQLite aquí sería inventado.

## Cuando no hay canal de salida
Si no se puede leer una respuesta, el fingerprint se hace por **tolerancia de
sintaxis** en lugar de por contenido: probar las formas de concatenación y ver cuál no
provoca error. `'foo'||'bar'` funciona en Oracle y PostgreSQL, `'foo'+'bar'` en
Microsoft, `'foo' 'bar'` en MySQL. La que pasa identifica la familia sin necesidad de
devolver datos.

## Impacto
Ninguno por sí mismo — de ahí el CVSS 0.0. Es el paso de reconocimiento que habilita
los demás writeups de esta carpeta.

## Lectura del control negativo
Lo informativo no es que una consulta funcione, sino **la combinación** de la que
funciona y las que fallan. Y si ninguna funciona, la conclusión correcta no es "no hay
motor identificable" sino "el canal de salida no está operativo": hay que arreglar el
canal antes de sacar conclusiones sobre el motor.

## Remediación
La remediación es la de la inyección subyacente, no la del fingerprint: consultas
parametrizadas. Ocultar la versión del motor es ofuscación y, como muestra este
writeup, se puede inferir por tolerancia de sintaxis sin leer ninguna versión.
