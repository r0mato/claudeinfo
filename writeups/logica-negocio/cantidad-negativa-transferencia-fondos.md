---
clase: logica-negocio
tech: web-app-generic
cwe: CWE-20
cvss: 8.6 # [derivado] transferencia de fondos en direccion contraria a la prevista
payload: |
  # CODIGO VULNERABLE - LITERAL de la fuente (saltos de linea colapsados por el render):
  $transferAmount = $_POST['amount']; $currentBalance = $user->getBalance(); if ($transferAmount <= $currentBalance) { // Complete the transfer } else { // Block the transfer: insufficient funds }
  #
  # PARAMETRO: amount    (literal de la fuente)
  # VALOR DEL ATAQUE: -$1000   (aparece literal en la prosa de la fuente)
  #
  # Instanciado como peticion (reconstruccion mia; la fuente NO muestra la peticion
  # HTTP, solo el parametro y el valor):
  POST /transfer
  Content-Type: application/x-www-form-urlencoded
  amount=-1000&recipient=<cuenta-victima>
  #
  # RAZONAMIENTO LITERAL de la fuente:
  #   'If the attacker sent -$1000 to the victim's account, this might result in them
  #    receiving $1000 from the victim instead. The logic would always evaluate that
  #    -1000 is less than the current balance and approve the transfer.'
precondicion: "El tipo de dato acepta valores que las reglas de negocio deberian rechazar (numeros negativos) y NO existe validacion explicita en servidor que los rechace. La comprobacion presente ('importe <= saldo') es correcta para su proposito y resulta SIEMPRE cierta con un negativo."
como_se_descubre: |
  Metodologia de la fuente: usar un proxy y un repetidor para enviar valores no
  convencionales, centrandose en rangos que un usuario legitimo no introduciria
  nunca: numeros excepcionalmente altos o bajos, cadenas anormalmente largas y tipos
  de dato inesperados.
  Las preguntas que la fuente propone hacerse: ¿hay limites? ¿que pasa EN los limites?
  ¿se aplica alguna transformacion o normalizacion?
  Y una heuristica de propagacion muy util: si un formulario maneja mal esta entrada,
  probablemente los demas tambien. Un hallazgo de este tipo justifica revisar todos
  los formularios numericos de la aplicacion, no solo el que fallo.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: amount=-1000   -> transferencia aprobada (saldo del atacante AUMENTA)
  # B: amount=1000 con saldo insuficiente -> bloqueado por 'fondos insuficientes'
  # C: amount=0       -> observar; delimita si el rechazo es '<= 0' o solo '< 0'
  # El control B es el que demuestra que la validacion EXISTE y funciona para su
  # proposito: es lo que convierte el hallazgo en un fallo de LOGICA y no en 'falta
  # validacion'. El control C delimita exactamente donde esta la frontera, dato que
  # el equipo de desarrollo necesita para corregirlo bien.
mata: |
  - Validacion explicita en servidor que exija importe > 0 -> muere.
  - El tipo de dato impide negativos (unsigned) en toda la cadena, incluida la BD.
  - La transaccion se valida contra reglas de negocio ademas de contra el saldo.
  - Nota de la fuente: los controles de cliente pueden impedir este valor en la
    interfaz, lo que NO es una defensa; hay que enviarlo con un proxy.
fuente: "https://portswigger.net/web-security/logic-flaws/examples (seccion 'Failing to handle unconventional input'). Codigo PHP, nombre de parametro 'amount', valor '-$1000' y el razonamiento citado son literales de la pagina. ADVERTENCIA: la pagina NO muestra ninguna peticion HTTP, URL ni cuerpo completo; la peticion de arriba es reconstruccion. El render colapso los saltos de linea del PHP."
confianza: media
fecha: 2026-11-02
---
# [LÓGICA-NEGOCIO] Importe negativo en una transferencia — la comprobación correcta, siempre cierta

## Principio
La comprobación `importe <= saldo` es correcta para lo que pretende: evitar que alguien
gaste más de lo que tiene. Pero con un importe negativo es **siempre** cierta, así que
la transferencia se aprueba siempre. El fallo no está en la validación, que funciona:
está en que nadie expresó la regla de negocio implícita de que un importe es positivo.

La fuente lo formula así: *"The logic would always evaluate that -1000 is less than the
current balance and approve the transfer."*

## Payload
Código vulnerable, literal de la fuente:

```php
$transferAmount = $_POST['amount']; $currentBalance = $user->getBalance(); if ($transferAmount <= $currentBalance) { // Complete the transfer } else { // Block the transfer: insufficient funds }
```

Parámetro: `amount`. Valor del ataque: `-$1000`.

**Advertencia de procedencia:** la fuente no muestra ninguna petición HTTP, URL ni
cuerpo completo — solo el código, el nombre del parámetro y el valor en prosa. La
petición siguiente es reconstrucción mía, y por eso el writeup va con
`confianza: media`:

```http
POST /transfer
Content-Type: application/x-www-form-urlencoded

amount=-1000&recipient=<cuenta-victima>
```

El efecto, en palabras de la fuente: *"If the attacker sent -$1000 to the victim's
account, this might result in them receiving $1000 from the victim instead."*

## El control que cambia el diagnóstico
Probar una transferencia legítima con saldo insuficiente y comprobar que **sí** se
bloquea. Eso demuestra que la validación existe y funciona, lo que reclasifica el
hallazgo de "falta validación" a "fallo de lógica de negocio" — dos cosas con
correcciones distintas. Y probar `amount=0` delimita si la frontera está en `< 0` o en
`<= 0`, que es el dato concreto que el equipo necesita para arreglarlo bien y no a
medias.

## Cómo buscarlo
La metodología de la fuente: enviar con un proxy valores que un usuario legítimo nunca
introduciría —números excepcionalmente altos o bajos, cadenas anormalmente largas,
tipos de dato inesperados— y preguntarse si hay límites, qué pasa exactamente en los
límites, y si se aplica alguna transformación.

La heurística más rentable es la de propagación: si un formulario maneja mal esta
entrada, probablemente los demás también. Un hallazgo así justifica revisar **todos** los
campos numéricos de la aplicación, porque el fallo no es de ese formulario sino de la
cultura de validación del equipo.

Y la nota que evita falsos negativos: los controles de cliente suelen impedir el valor
en la interfaz. Eso no es una defensa — hay que enviarlo con un proxy, saltándose el
formulario.

## Impacto
Transferencia de fondos en dirección contraria a la prevista: el atacante se acredita
dinero de la cuenta de la víctima. Impacto financiero directo.

## Remediación
De la fuente (página general de fallos de lógica): asegurarse de que *"the value of any
input is sensible before proceeding"*, y evitar suposiciones implícitas sobre el
comportamiento del usuario. La propia página advierte de que los controles de cliente
pueden bloquear estas entradas en la interfaz y **no** constituyen una defensa.

`# [derivado]`: la regla general es que toda regla de negocio implícita —un importe es
positivo, una cantidad es entera, una fecha es futura— debe existir como validación
explícita en servidor. Las reglas que solo viven en la cabeza del desarrollador son las
que el atacante encuentra.
