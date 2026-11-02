---
clase: inyeccion
tech: sql-multi-dbms
cwe: CWE-89
cvss: 7.5 # [derivado] extraccion de datos bit a bit sin canal visible
payload: |
  # Consultas LITERALES de la fuente. 'YOUR-CONDITION-HERE' es marcador DE LA FUENTE:
  # es una plantilla donde se inserta la condicion booleana a evaluar.
  #
  # Oracle:
  SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual
  #
  # Microsoft:
  SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END
  #
  # PostgreSQL:
  1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)
  #
  # MySQL:
  SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')
  #
  # INSTANCIACION concreta (Microsoft), extrayendo el primer caracter de una password:
  SELECT CASE WHEN (SUBSTRING((SELECT TOP 1 password FROM users),1,1)='a') THEN 1/0 ELSE NULL END
  #
  # Notese el mecanismo por motor:
  #  - Oracle/Microsoft/PostgreSQL: fuerzan DIVISION POR CERO si la condicion es cierta.
  #  - MySQL: usa una subconsulta que devuelve VARIAS FILAS, lo que tambien es error.
  # El patron comun: convertir 'verdadero' en un error y 'falso' en silencio.
precondicion: "Inyeccion SQL confirmada sin canal de salida visible (no hay union ni mensajes de error con datos), pero la aplicacion responde de forma DISTINGUIBLE ante un error de base de datos frente a una ejecucion correcta (p.ej. 500 vs 200, o una pagina de error distinta). Motor ya identificado."
como_se_descubre: |
  Se llega aqui cuando la inyeccion esta confirmada pero no se puede leer la salida.
  La sonda es construir una condicion SIEMPRE CIERTA y otra SIEMPRE FALSA y comprobar
  que la aplicacion responde distinto:
  - condicion '1=1' -> deberia dar error (500)
  - condicion '1=2' -> deberia dar respuesta normal (200)
  Si ambas dan lo mismo, el oraculo no funciona y hay que pasar a retardos temporales.
control_negativo: |
  # Control de ORACULO, imprescindible antes de extraer un solo dato:
  # A: condicion siempre cierta (1=1) -> ERROR observable
  # B: condicion siempre falsa  (1=2) -> respuesta NORMAL
  # Solo si A y B se distinguen, el canal existe. Esto NO es opcional: sin verificar
  # el oraculo, cada respuesta posterior es ruido interpretado como señal, y se
  # extraen 'datos' que son invencion del propio test.
  # C: [derivado] repetir A dos veces para descartar intermitencia (caches, balanceo).
mata: |
  - La aplicacion devuelve la misma respuesta con y sin error de BD -> sin oraculo;
    pasar a retardos temporales (ver sqli-retardos-temporales-condicionales).
  - El error de BD se captura y se traduce a una pagina generica identica a la normal.
  - Motor mal identificado -> la sintaxis CASE/IF falla por razones ajenas a la condicion.
  - Respuestas intermitentes por caches o balanceo (ver control C).
fuente: "https://portswigger.net/web-security/sql-injection/cheat-sheet (seccion 'Conditional errors'). Consultas literales de la pagina, incluido el marcador 'YOUR-CONDITION-HERE'. La instanciacion concreta y el analisis del mecanismo por motor son añadidos mios."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Errores condicionales — convertir un booleano en un error de base de datos

## Principio
Cuando no hay canal para leer datos pero la aplicación distingue visiblemente entre
"consulta correcta" y "error de base de datos", ese contraste es un canal de un bit. La
técnica fuerza un error **solo si** la condición evaluada es cierta: verdadero produce
error, falso produce silencio. Con un bit por petición se extrae cualquier dato.

## Payload
```sql
-- Oracle
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual

-- Microsoft
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END

-- PostgreSQL
1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)

-- MySQL
SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')
```

`YOUR-CONDITION-HERE` es marcador de la fuente: la plantilla se instancia con la
condición a evaluar. Por ejemplo, para el primer carácter de una contraseña en
Microsoft:

```sql
SELECT CASE WHEN (SUBSTRING((SELECT TOP 1 password FROM users),1,1)='a') THEN 1/0 ELSE NULL END
```

## Dos mecanismos distintos bajo el mismo patrón
Oracle, Microsoft y PostgreSQL fuerzan una **división por cero**. MySQL usa otra vía: una
subconsulta que devuelve **varias filas**, lo que también es un error. Conviene verlo
porque explica cómo construir variantes cuando un WAF bloquea `1/0`: lo que hace falta
no es la división, es cualquier operación que falle de forma condicional.

## El control de oráculo no es opcional
Antes de extraer un solo dato hay que probar una condición siempre cierta (`1=1`) y una
siempre falsa (`1=2`) y comprobar que la aplicación responde distinto. Si no se verifica,
cada respuesta posterior es ruido interpretado como señal, y se termina "extrayendo"
datos que son un artefacto del propio test. Es el error más caro de esta técnica porque
produce resultados que parecen coherentes.

Merece la pena repetir la prueba cierta dos veces: cachés y balanceo de carga producen
intermitencia que imita un oráculo.

## Impacto
Extracción completa de datos arbitrarios de la base de datos, un bit por petición, sin
necesidad de que la aplicación muestre nunca un dato. Es lento pero no tiene techo.

## Remediación
Consultas parametrizadas. `# [derivado]`: como defensa en profundidad, capturar los
errores de base de datos y devolver una respuesta **indistinguible** de la normal — si
el error y el éxito producen la misma salida, el canal de un bit desaparece. Eso no
arregla la inyección, pero elimina este método de explotación.
