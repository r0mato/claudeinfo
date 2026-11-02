---
clase: inyeccion
tech: graphql
cwe: CWE-307
cvss: 7.5 # [derivado] anula el limite de intentos sobre un secreto
payload: |
  # LITERAL de la fuente (la pagina lo llama 'simplified example' y lo muestra como
  # consulta cruda, no dentro de un cuerpo JSON).
  # ADVERTENCIA (H1): el render colapso los saltos de linea.
  query isValidDiscount($code: Int) { isValidDiscount(code:$code){ valid } isValidDiscount2:isValidDiscount(code:$code){ valid } isValidDiscount3:isValidDiscount(code:$code){ valid } }
  #
  # Mecanica: 'isValidDiscount2:' y 'isValidDiscount3:' son ALIAS. GraphQL permite
  # consultar el mismo campo varias veces en UNA consulta si cada instancia lleva un
  # alias distinto. El servidor ejecuta las tres, pero el limite de peticiones ve UNA
  # sola peticion HTTP.
  #
  # Escalado: el patron se repite tantas veces como aliases quepan en el cuerpo, asi
  # que el numero de intentos por peticion HTTP solo lo acota el limite de tamaño.
precondicion: "El limite de intentos se aplica por PETICION HTTP (o por IP y unidad de tiempo contando peticiones), no por operacion ejecutada. El campo atacado debe aceptar un argumento y devolver un resultado distinguible (aqui, 'valid')."
como_se_descubre: |
  Señal en recon: cualquier campo de GraphQL que valide un secreto y devuelva un
  booleano o un error distinguible — codigos de descuento, tokens de 2FA, codigos de
  invitacion, comprobaciones de 'existe este usuario'.
  La pregunta clave no es tecnica sino de diseño: ¿que CUENTA el limitador? Si cuenta
  peticiones HTTP y el protocolo permite N operaciones por peticion, el limite real es
  N veces mayor de lo que el equipo cree. Este desajuste es invisible en el codigo del
  limitador, porque el limitador funciona exactamente como se escribio.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: una peticion con 3 aliases y 3 valores distintos
  #    -> 3 resultados en la respuesta, y el contador del limite sube SOLO 1
  # B: 3 peticiones HTTP separadas con 1 valor cada una
  #    -> la tercera (o la N-esima) choca con el limite
  # El par A/B es la demostracion completa, y es incontestable: mismo numero de
  # intentos, resultado distinto segun como se empaqueten. Conviene incluir en el
  # informe el numero de aliases que se logro meter en una sola peticion, porque es la
  # medida del factor de amplificacion.
mata: |
  - El limite se aplica por OPERACION ejecutada, no por peticion HTTP -> muere.
  - Limite de aliases configurado (la fuente lo nombra como 'operation limits').
  - Limite de tamaño en bytes de la consulta suficientemente bajo.
  - Analisis de coste de consulta ('cost analysis', que la fuente nombra).
  - El campo no devuelve un resultado distinguible por intento.
fuente: "https://portswigger.net/web-security/graphql (seccion de bypass de limitacion de peticiones mediante aliases). Payload literal de la pagina; la pagina lo presenta como ejemplo simplificado."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Alias de GraphQL para anular el límite de intentos

## Principio
GraphQL permite consultar el mismo campo varias veces en una sola consulta, siempre que
cada instancia lleve un alias distinto. El servidor ejecuta todas. El limitador de
peticiones, que cuenta peticiones HTTP, ve **una**.

El desajuste no está en el limitador —que hace exactamente lo que se escribió— sino en
que la unidad que cuenta (peticiones) dejó de corresponder a la unidad que importa
(intentos). Es el mismo error de nivel que medir carga por conexiones cuando el
protocolo multiplexa.

## Payload
```graphql
query isValidDiscount($code: Int) { isValidDiscount(code:$code){ valid } isValidDiscount2:isValidDiscount(code:$code){ valid } isValidDiscount3:isValidDiscount(code:$code){ valid } }
```

`isValidDiscount2:` e `isValidDiscount3:` son los aliases. La fuente presenta esto como
ejemplo simplificado; el patrón se repite tantas veces como quepa, así que el número de
intentos por petición HTTP solo lo acota el límite de tamaño del cuerpo.

Nota de procedencia: el render de la fuente colapsó los saltos de línea del bloque.

## Dónde buscarlo
Cualquier campo que valide un secreto y devuelva algo distinguible: códigos de
descuento, tokens de 2FA, códigos de invitación, comprobaciones de existencia de
usuario. La pregunta de recon es de diseño, no de técnica: **¿qué cuenta el limitador?**
Si cuenta peticiones HTTP y el protocolo admite N operaciones por petición, el límite
real es N veces mayor de lo que el equipo cree.

## La medida que hay que incluir en el informe
Cuántos aliases se logró meter en una sola petición. Ese número **es** el factor de
amplificación, y convierte el hallazgo de una observación conceptual en una magnitud: un
límite de 5 intentos por minuto con 500 aliases por petición es un límite de 2.500
intentos por minuto. Sin la cifra, el informe se lee como teórico.

## Impacto
Fuerza bruta efectiva sobre cualquier secreto de poca entropía que el esquema valide:
tokens de 2FA de 6 dígitos, códigos de descuento, PIN. Anula el control que se suponía
que lo impedía, sin disparar sus alarmas — porque desde el punto de vista del limitador
no está pasando nada anómalo.

## Remediación
De la fuente, las defensas contra fuerza bruta son cuatro y son acumulativas: limitar la
profundidad de las consultas, configurar **límites de operación** (campos únicos,
aliases, campos raíz), acotar el tamaño en bytes de la consulta, y considerar análisis
de coste.

`# [derivado]`: la corrección de fondo es contar **operaciones ejecutadas** y no
peticiones HTTP. Mientras la unidad de medida del limitador no coincida con la unidad de
trabajo del servidor, habrá una forma de empaquetar más trabajo por petición.
