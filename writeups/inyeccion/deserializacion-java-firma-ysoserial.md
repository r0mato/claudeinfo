---
clase: inyeccion
tech: java
cwe: CWE-502
cvss: 9.8 # [derivado] RCE mediante cadenas de gadgets
payload: |
  # ---- DETECCION ----
  # Cita LITERAL de la fuente: los objetos Java serializados 'always begin with the
  # same bytes, which are encoded as "ac ed" in hexadecimal and "rO0" in Base64'.
  #
  # Por tanto, las dos firmas a buscar en cookies, parametros y cuerpos:
  ac ed        # hexadecimal
  rO0          # Base64
  #
  # ADVERTENCIA: la forma 'ac ed 00 05' que circula mucho NO aparece en la fuente.
  # Lo literal son 'ac ed' y 'rO0'.
  #
  # ---- GENERACION DE CADENAS DE GADGETS ----
  # Comando LITERAL de la fuente para Java 16 y posteriores (las continuaciones con '\'
  # dependen de saltos de linea que el render colapso):
  java -jar ysoserial-all.jar \ --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \ --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \ --add-opens=java.base/java.net=ALL-UNNAMED \ --add-opens=java.base/java.util=ALL-UNNAMED \ [payload] '[command]'
  #
  # '[payload]' y '[command]' son MARCADORES DE LA PROPIA FUENTE, no elisiones mias.
  # Los --add-opens hacen falta desde Java 16 porque el sistema de modulos bloquea el
  # acceso reflexivo que las cadenas necesitan.
  #
  # ---- CADENAS NOMBRADAS, para DETECCION en lugar de explotacion ----
  #   URLDNS      -> provoca una consulta DNS. La fuente la describe como la cadena de
  #                  deteccion 'most universal'. No ejecuta codigo: solo resuelve un
  #                  nombre, asi que es SEGURA de lanzar contra un objetivo.
  #   JRMPClient  -> abre una conexion TCP a una IP en crudo.
  #
  # La fuente NO proporciona ningun payload de cadena de gadgets, ni linea de comando
  # de PHPGGC, ni payload PHAR. No los invento.
  #
  # ---- SINK EN CODIGO ----
  # Metodo a buscar: ObjectInputStream.readObject()
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException { // implementation }
precondicion: "La aplicacion deserializa datos Java que vienen del cliente. Para RCE hace falta ademas que el classpath contenga una libreria con una cadena de gadgets conocida. Desde Java 16, generar las cadenas exige los flags --add-opens porque el sistema de modulos bloquea el acceso reflexivo."
como_se_descubre: |
  Buscar las firmas 'rO0' (Base64) o 'ac ed' (hex) en TODO dato que viaje del cliente al
  servidor: cookies, parametros ocultos, cabeceras, cuerpos. Son inconfundibles.
  Revision de codigo: buscar readObject().
  Burp Suite Professional, LITERAL de la fuente: 'Burp Scanner will automatically flag
  any HTTP messages that appear to contain serialized objects'.
  ORDEN CORRECTO Y SEGURO: usar primero URLDNS. Solo provoca una consulta DNS, asi que
  confirma que la deserializacion ocurre SIN ejecutar nada en el objetivo. Es la
  diferencia entre demostrar la vulnerabilidad y causar el impacto — y en una prueba
  autorizada es la unica primera opcion defendible.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: payload URLDNS apuntando a un dominio propio -> llega la consulta DNS
  # B: el mismo payload con un byte corrompido      -> no llega nada
  # El par A/B confirma que es la DESERIALIZACION la que dispara el lookup y no otra
  # parte de la aplicacion procesando la cadena.
  # C: una cadena Base64 aleatoria con prefijo rO0 -> error de deserializacion
  #    distinto; mapea como responde el objetivo ante datos invalidos
mata: |
  - No hay deserializacion de datos del cliente.
  - Comprobacion de integridad antes de deserializar.
  - El classpath no contiene ninguna libreria con cadena de gadgets conocida
    -> no hay RCE, aunque la deserializacion insegura sigue siendo un fallo.
  - ADVERTENCIA de la fuente: no confiar en eliminar cadenas de gadgets. La
    vulnerabilidad es deserializar entrada del usuario.
fuente: "https://portswigger.net/web-security/deserialization/exploiting. Firmas, comando de ysoserial y cadenas nombradas literales de la pagina. Los marcadores '[payload]' y '[command]' son de la propia pagina. La fuente NO da payload de cadena de gadgets, ni comando de PHPGGC, ni payload PHAR; ysoserial.net y gadgetinspector NO se mencionan."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Deserialización en Java — `rO0`, y por qué URLDNS va primero

## Principio
Los objetos Java serializados empiezan siempre por los mismos bytes. Cita literal: *"always
begin with the same bytes, which are encoded as 'ac ed' in hexadecimal and 'rO0' in
Base64."*

Eso convierte la detección en un problema de búsqueda de texto: `rO0` en una cookie o un
parámetro es inconfundible y no aparece por casualidad.

## Payload
Las firmas:

```
ac ed        # hexadecimal
rO0          # Base64
```

**Advertencia de procedencia:** la forma `ac ed 00 05` circula mucho asociada a esta
clase, pero **no aparece en la fuente**. Lo literal son `ac ed` y `rO0`.

Generación de cadenas, para Java 16 y posteriores:

```bash
java -jar ysoserial-all.jar \ --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \ --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \ --add-opens=java.base/java.net=ALL-UNNAMED \ --add-opens=java.base/java.util=ALL-UNNAMED \ [payload] '[command]'
```

`[payload]` y `[command]` son marcadores de la propia página. Los `--add-opens` hacen
falta desde Java 16 porque el sistema de módulos bloquea el acceso reflexivo que las
cadenas necesitan — un detalle que convierte un comando que "no funciona" en uno que sí,
y que falta en casi todo el material de terceros.

## URLDNS va primero, y es una cuestión de criterio
La fuente nombra dos cadenas y describe `URLDNS` como la de detección *"most universal"*.
Lo decisivo es qué hace: **solo provoca una consulta DNS**. No ejecuta código.

Eso la convierte en la única primera opción defendible en una prueba autorizada. Confirma
que la deserialización ocurre sin ejecutar nada en el objetivo — es la diferencia entre
**demostrar** la vulnerabilidad y **causar** el impacto. Lanzar una cadena de RCE como
primera prueba ejecuta código en un sistema ajeno para averiguar si se puede ejecutar
código, lo que invierte el orden correcto.

`JRMPClient` es el siguiente escalón: abre una conexión TCP a una IP en crudo, útil cuando
el DNS está bloqueado pero la salida TCP no.

## Nota de procedencia
La fuente **no proporciona** ningún payload de cadena de gadgets, ni línea de comando de
PHPGGC, ni payload PHAR. `ysoserial.net` y `gadgetinspector` no se mencionan. No los
invento.

## Impacto
Ejecución remota de código cuando el classpath contiene una librería con cadena de
gadgets conocida. Sin ella, la deserialización insegura sigue siendo un fallo reportable
— y la fuente insiste en que la vulnerabilidad es deserializar entrada del usuario, no la
presencia del gadget.

## Remediación
De la fuente: evitar deserializar entrada del usuario; si es inevitable, comprobación de
integridad **antes** de deserializar; serialización específica por clase en lugar de la
genérica.

Y la advertencia que cierra: *no confiar en eliminar cadenas de gadgets*. Quitar un gadget
del classpath cierra un exploit concreto y deja la vulnerabilidad en pie, con exploits de
corrupción de memoria todavía posibles.
