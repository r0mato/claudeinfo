---
clase: inyeccion
tech: php
cwe: CWE-502
cvss: 9.8 # [derivado] desde bypass de autenticacion hasta RCE segun los metodos magicos presentes
payload: |
  # OBJETOS SERIALIZADOS LITERALES de la fuente.
  # ADVERTENCIA de la fuente reproducida tal cual: el primer ejemplo usa DOS PUNTOS
  # entre clave y valor, el segundo usa PUNTO Y COMA. Se reproducen ambos como estan.
  O:4:"User":2:{s:4:"name":s:6:"carlos";s:10:"isLoggedIn":b:1;}
  O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}
  #
  # Los prefijos de longitud CUADRAN: User=4, name=4, carlos=6, isLoggedIn=10,
  # username=8, isAdmin=7. Al modificar un valor hay que RECALCULAR su longitud o el
  # objeto no se deserializa — es la causa numero uno de fallo en esta clase.
  #
  # Codigo que lo asigna - LITERAL de la fuente:
  $user->name = "carlos"; $user->isLoggedIn = true;
  #
  # SINK VULNERABLE - LITERAL de la fuente:
  $user = unserialize($_COOKIE); if ($user->isAdmin === true) { // allow access to admin interface }
  #
  # SEGUNDO SINK, con comparacion LAXA - LITERAL de la fuente:
  $login = unserialize($_COOKIE) if ($login['password'] == $password) { // log in successfully }
  # (la fuente imprime esta linea sin punto y coma; probablemente perdido en el render)
  #
  # COMPARACIONES LAXAS que la fuente documenta - LITERALES:
  5 == "5"
  5 == "5 of something"
  0 == "Example string"
  # La ultima es la explotable: con '==', un 0 entero iguala a CUALQUIER cadena no
  # numerica. Si se puede forzar que la password almacenada se deserialice como el
  # entero 0, cualquier cadena pasa la comprobacion.
  #
  # METODOS MAGICOS que la fuente nombra, por lenguaje:
  #   PHP:    __construct()  __wakeup()  __destruct()
  #   Java:   readObject()
  #   Python: __init__  (nombrado solo como analogo de __construct)
  # Firma LITERAL del de Java:
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException { // implementation }
  #
  # NOTA: '__toString' NO aparece en la fuente. No lo incluyo como literal suyo.
precondicion: "La aplicacion deserializa datos que vienen del cliente (en el ejemplo, una cookie). Para bypass de autorizacion basta modificar un atributo. Para RCE hacen falta metodos magicos que se invoquen durante la deserializacion (__wakeup, __destruct) y que hagan algo util con atributos controlados."
como_se_descubre: |
  Señales de reconocimiento LITERALES de la fuente:
  - PHP: el formato usa 'letters representing the data type and numbers representing
    the length of each entry' (O:, s:, b:).
  - Java: el prefijo 'ac ed' en hexadecimal o 'rO0' en Base64.
  - Revision de codigo: buscar unserialize(), serialize() y readObject().
  - Burp Suite Professional marca automaticamente los mensajes HTTP que parecen
    contener objetos serializados.
  Metodologia de caja negra LITERAL: examinar 'all data being passed into the website'
  buscando datos serializados y comprobar si son controlables.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: objeto con isAdmin modificado a b:1 y las longitudes RECALCULADAS -> acceso admin
  # B: el mismo objeto con una longitud INCORRECTA -> fallo de deserializacion
  # El par A/B es diagnostico y practico a la vez: si A falla, B dice si la causa es
  # la longitud (la mas probable) o la politica. Es el control que mas tiempo ahorra en
  # esta clase, porque un prefijo de longitud mal calculado produce un fallo que parece
  # una defensa.
  # C: el objeto ORIGINAL sin modificar -> confirma que la sesion funciona de base
mata: |
  - La aplicacion no deserializa datos del cliente -> muere.
  - Comprobacion de integridad (firma digital) ANTES de deserializar. La fuente
    subraya que la comprobacion debe ejecutarse antes de la deserializacion.
  - Serializacion especifica por clase en lugar de la generica.
  - Comparacion estricta '===' en lugar de '==' -> mata la via de la comparacion laxa.
  - ADVERTENCIA de la fuente: NO confiar en eliminar cadenas de gadgets. La
    vulnerabilidad es deserializar entrada del usuario, y siguen siendo posibles
    exploits de corrupcion de memoria.
fuente: "https://portswigger.net/web-security/deserialization y https://portswigger.net/web-security/deserialization/exploiting. Objetos serializados, codigo, comparaciones laxas y firmas literales de las paginas. La fuente NO contiene objetos serializados de Java, Ruby ni Python, ni la forma 'ac ed 00 05', ni '__toString'."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] Deserialización en PHP — el prefijo de longitud es la mitad del trabajo

## Principio
`unserialize()` reconstruye un objeto desde una cadena. Si esa cadena viene del cliente,
el cliente decide el estado del objeto — y en algunos casos, qué código se ejecuta durante
la reconstrucción.

## Payload
Objetos serializados literales de la fuente:

```
O:4:"User":2:{s:4:"name":s:6:"carlos";s:10:"isLoggedIn":b:1;}
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}
```

El sink:

```php
$user = unserialize($_COOKIE); if ($user->isAdmin === true) { // allow access to admin interface }
```

Nota de procedencia: el primer ejemplo de la fuente usa **dos puntos** entre clave y
valor y el segundo **punto y coma**. Reproduzco ambos como están.

## El detalle que hace fallar la mayoría de intentos
Los prefijos de longitud tienen que cuadrar: `User`=4, `name`=4, `carlos`=6,
`isLoggedIn`=10, `username`=8, `isAdmin`=7. **Al modificar cualquier valor hay que
recalcular su longitud**, o el objeto no se deserializa.

Es la causa número uno de fallo en esta clase, y produce un síntoma engañoso: el objeto
se rechaza, lo que parece una defensa. Por eso el control negativo útil aquí no es
"¿funciona?" sino "¿falla por longitud o por política?" — y se resuelve enviando
deliberadamente una longitud incorrecta para ver si el error es el mismo.

## La comparación laxa es la vía más elegante
La fuente documenta tres comparaciones:

```php
5 == "5"
5 == "5 of something"
0 == "Example string"
```

La tercera es la explotable. Con `==`, el entero `0` iguala a **cualquier cadena no
numérica**. Así que en este sink:

```php
$login = unserialize($_COOKIE) if ($login['password'] == $password) { // log in successfully }
```

si se consigue que la contraseña almacenada se deserialice como el entero `0`, cualquier
cadena pasa la comprobación. No hay que adivinar ni romper nada: se cambia el **tipo** del
dato, igual que en la inyección de operadores NoSQL.

## Métodos mágicos
La fuente nombra, por lenguaje: `__construct()`, `__wakeup()` y `__destruct()` en PHP;
`readObject()` en Java, con su firma:

```java
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException { // implementation }
```

Y `__init__` en Python, solo como análogo de `__construct`. **`__toString` no aparece en
la fuente**, así que no lo presento como literal suyo.

## Impacto
Desde bypass de autorización —cambiar `isAdmin` a `b:1`— hasta ejecución remota de código,
según qué métodos mágicos existan y qué hagan con los atributos controlados.

## Remediación
De la fuente: evitar deserializar entrada del usuario salvo necesidad real; si hay que
hacerlo, añadir una comprobación de integridad como una firma digital, **que debe
ejecutarse antes de la deserialización**; y preferir serialización específica por clase a
la genérica, para controlar qué campos se exponen.

Con la advertencia que conviene citar en cualquier informe de esta clase: **no confiar en
eliminar cadenas de gadgets**. La vulnerabilidad es deserializar entrada del usuario, y
siguen siendo posibles exploits de corrupción de memoria aunque no haya gadget conocido.
