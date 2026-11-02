---
clase: logica-negocio
tech: ecommerce
cwe: CWE-840
cvss: 5.3 # [derivado] perdida economica acotada al importe del descuento
payload: |
  # ADVERTENCIA DE PROCEDENCIA: la fuente NO muestra ninguna peticion HTTP, URL,
  # nombre de parametro ni valor literal para este caso. Lo UNICO literal es el
  # escenario y la condicion de negocio:
  #
  #   'a 10% discount on orders over $1000'   (condicion literal de la fuente)
  #
  # SECUENCIA, descrita en prosa por la fuente (reproducida, no citada):
  #   1. Añadir articulos a la cesta hasta superar el umbral de $1000
  #   2. El sistema aplica el descuento del 10%
  #   3. Eliminar de la cesta los articulos no deseados
  #   4. Realizar el pedido: el descuento SIGUE aplicado aunque el total ya no
  #      cumple la condicion que lo justificaba
  #
  # No construyo una peticion de ejemplo: cualquier nombre de parametro que escribiera
  # seria inventado. La secuencia de PASOS es lo reproducible, y es suficiente para
  # reproducir el fallo en cualquier tienda con esta mecanica.
precondicion: "La logica de negocio aplica un ajuste de precio al cumplirse una condicion y NO vuelve a comprobar esa condicion cuando el pedido cambia despues. La fuente lo describe asi: la logica no re-verifica si el pedido cambio tras aplicarse el descuento."
como_se_descubre: |
  Metodologia LITERAL de la fuente para esta clase: pensar en los objetivos del
  atacante y buscar formas de alcanzarlos con la funcionalidad disponible; localizar
  los puntos donde los precios u otros valores sensibles se AJUSTAN segun criterios
  que el usuario controla; averiguar que algoritmo aplica el ajuste y CUANDO; e
  intentar alcanzar un estado en el que el ajuste ya no se corresponde con el
  criterio original.
  La fuente subraya que esta clase exige conocimiento del DOMINIO: hay que leer la
  documentacion del negocio y consultar a expertos de la materia. No se encuentra con
  herramientas, porque no hay nada malformado en ninguna peticion: todas las acciones
  son legitimas por separado.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: superar el umbral -> recibir descuento -> retirar articulos -> finalizar
  #    -> el descuento se mantiene con un total inferior al umbral
  # B: construir el pedido final DIRECTAMENTE, por debajo del umbral
  #    -> NO se aplica descuento
  # El par A/B es el informe completo: dos pedidos con el MISMO contenido final y
  # precios DISTINTOS segun el orden de las acciones. Presentado asi es incontestable,
  # porque no hay que explicar ninguna anomalia tecnica: solo dos recibos.
mata: |
  - El total y las condiciones de descuento se recalculan en el momento de confirmar
    el pedido -> muere.
  - El descuento se vincula al pedido mediante una transaccion atomica que revalida
    la condicion.
  - Cambiar la cesta invalida los ajustes aplicados y fuerza un recalculo.
fuente: "https://portswigger.net/web-security/logic-flaws/examples (seccion 'Domain-specific flaws'). La condicion '10% discount on orders over $1000' y el escenario son de la pagina; la pagina NO proporciona peticiones, parametros ni valores literales, y no da remediacion especifica para esta clase."
confianza: media
fecha: 2026-11-02
---
# [LÓGICA-NEGOCIO] Descuento por umbral que sobrevive a la retirada de artículos

## Principio
Una condición comprobada **una vez** no es una condición: es un instante. Si el sistema
aplica un descuento al superar un umbral y no vuelve a comprobar el umbral cuando el
pedido cambia, el estado final del pedido puede no cumplir nada de lo que justificó su
precio.

Lo notable de esta clase es que **ninguna petición es maliciosa**. Añadir artículos es
legítimo. Quitarlos es legítimo. Confirmar el pedido es legítimo. El fallo está
únicamente en el orden, lo que explica por qué ninguna herramienta lo encuentra: no hay
nada malformado que detectar.

## Payload
**Advertencia de procedencia:** la fuente no muestra ninguna petición, URL, nombre de
parámetro ni valor para este caso. Lo único literal es la condición de negocio:

> *"a 10% discount on orders over $1000"*

Y la secuencia, que la fuente describe en prosa:

1. Añadir artículos hasta superar el umbral de $1000.
2. El sistema aplica el descuento del 10%.
3. Eliminar de la cesta los artículos no deseados.
4. Confirmar el pedido: el descuento sigue aplicado aunque el total ya no cumpla la
   condición.

No construyo una petición de ejemplo porque cualquier nombre de parámetro que escribiera
sería inventado. La secuencia de pasos es lo reproducible —y basta para reproducir el
fallo en cualquier tienda con esta mecánica— pero el writeup va con `confianza: media`
precisamente por eso.

## El informe son dos recibos
El control negativo de esta clase es especialmente potente: construir el mismo pedido
final por la vía directa, sin pasar por el umbral, y comprobar que no lleva descuento.
Eso deja dos pedidos con **contenido idéntico y precio distinto** según el orden de las
acciones. Presentado así no hay nada que discutir ni ninguna anomalía técnica que
explicar: son dos facturas del mismo carrito.

## Cómo se encuentra
La metodología de la fuente para esta clase: pensar en los objetivos del atacante y
buscar cómo alcanzarlos con la funcionalidad existente; localizar dónde se **ajustan**
precios u otros valores sensibles según criterios que el usuario controla; averiguar qué
algoritmo hace el ajuste y **cuándo**; e intentar llegar a un estado donde el ajuste ya
no corresponda al criterio.

La fuente insiste en que esta clase requiere conocimiento del dominio: leer la
documentación del negocio y hablar con expertos de la materia. Es la clase de
vulnerabilidad que un tester externo encuentra peor que alguien que entiende el negocio,
y la razón de que los programas con lógica compleja sigan teniendo hallazgos después de
años de escaneo automático.

## Impacto
Pérdida económica acotada al importe del descuento por pedido, pero repetible sin
límite. La severidad real depende del tamaño del ajuste y de si existen controles
posteriores de conciliación.

## Remediación
La fuente no da remediación específica para esta clase; lo que sigue es derivado.
`# [derivado]`: recalcular el total y revalidar **todas** las condiciones de descuento en
el momento de confirmar el pedido, dentro de una transacción atómica, y tratar cualquier
cambio en la cesta como invalidación de los ajustes aplicados.

De las recomendaciones generales de la fuente, la que aplica: identificar las
suposiciones sobre el estado del servidor y verificarlas en el código, y documentar las
dependencias y efectos secundarios entre componentes — porque aquí la suposición no
escrita era "el pedido no cambia después de aplicarse el descuento".
