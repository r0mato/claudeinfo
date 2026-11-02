---
clase: race
tech: facebook
cwe: CWE-362
cvss: 7.5 # [derivado] sin CVE ni severidad publicada; estimado por validacion de direccion no controlada
payload: |
  # URL literal de la fuente (reproducida tal cual, incluido el & ya decodificado):
  /confirmemail.php?e=user@gmail.com&c=13475&code=84751
  #
  # Tecnica: cambiar la direccion de correo de la cuenta a DOS direcciones distintas
  # simultaneamente. El resultado documentado es un unico correo que contiene DOS
  # codigos de confirmacion distintos, uno por cada direccion.
precondicion: "El flujo de cambio de correo acepta dos peticiones concurrentes y genera los codigos antes de resolver cual es la direccion definitiva. Descrito en la fuente original (Josip Franjkovic, 2016) sobre Facebook."
como_se_descubre: |
  Señal: un correo de confirmacion que contiene MAS de un codigo, o codigos que no
  corresponden a la direccion que los recibe. El caso es el precedente historico del
  patron que PortSwigger formalizo en 2023: la pista no es un error ni una respuesta
  distinta, sino un correo cuyo CONTENIDO es internamente incoherente.
  Nota de la fuente de 2023 sobre por que esta clase se pasa por alto: hay objetivos
  cuyos correos 'didn't tell you who the code was for', lo que oculta la pista por
  completo.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: dos peticiones de cambio de correo simultaneas a dos direcciones propias
  #    -> un correo con DOS codigos (o codigos cruzados)
  # B: las mismas dos peticiones separadas en el tiempo
  #    -> dos correos, un codigo cada uno, cada cual a su direccion
  # Usar siempre direcciones propias en la prueba.
mata: |
  - Parcheado: el caso es de 2016 y Facebook lo corrigio.
  - El correo llega con un solo codigo coherente con su destinatario -> sin ventana.
  - Los correos del objetivo no indican a que direccion pertenece el codigo
    -> la pista es invisible aunque la ventana exista (buscar pistas de segundo orden).
fuente: "Citado en https://portswigger.net/research/smashing-the-state-machine (James Kettle, 2023-08-09) como caso previo, atribuido a una entrada de blog de 2016 de Josip Franjkovic: https://www.josipfranjkovic.com/blog/race-conditions-on-web . Cita literal del articulo de PortSwigger: 'The bug? Changing your Facebook email address to two different addresses simultaneously could trigger an email containing two distinct confirmation codes, one for each address:'"
confianza: media
fecha: 2026-11-02
---
# [RACE] Facebook: dos cambios de correo simultáneos generan dos códigos en un solo mensaje

## Principio
Cuando el flujo de cambio de correo genera el código antes de fijar cuál es la dirección
definitiva, dos peticiones concurrentes producen dos códigos que no quedan ligados a su
dirección respectiva. El atacante acaba con un código válido para una dirección que no
controla.

## Payload
El enlace de confirmación tiene esta forma literal:

```
/confirmemail.php?e=user@gmail.com&c=13475&code=84751
```

La técnica consiste en pedir el cambio a dos direcciones distintas a la vez. Lo que
describe la fuente: un único correo con **dos códigos de confirmación distintos**, uno
por cada dirección.

## Impacto
Validar una dirección ajena, con el mismo techo que el caso de Devise: donde el control
de acceso dependa del dominio del correo, la validación es la llave. El valor de
conservar este caso de 2016 es histórico y metodológico — es el precedente del patrón
que PortSwigger formalizó siete años después, y muestra que la clase llevaba tiempo
siendo explotable antes de tener nombre y herramienta.

## Remediación
Ligar cada código de confirmación a su dirección de forma atómica, de modo que el código
y su destinatario se escriban y se lean como una sola unidad. `# [derivado]`: es el
mismo principio que la fuente de 2023 formula como *"Avoid mixing data from different
sources"* — aquí el código y la dirección se resuelven por separado y por eso pueden
descoordinarse.

## Nota de detección
El detalle más transferible no es el payload sino la forma de la pista. La fuente de 2023
señala que algunos objetivos envían correos que *"didn't tell you who the code was for"*.
Cuando el correo no nombra su dirección, esta clase se vuelve invisible a la inspección
directa y solo aparece por pistas de segundo orden: comportamiento cambiado más tarde,
o un código que funciona donde no debería.
