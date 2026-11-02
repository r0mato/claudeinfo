---
clase: auth
tech: postmessage
cwe: CWE-346
cvss: 8.8 # [derivado] completa la cadena hasta secuestro de cuenta con un clic
payload: |
  # Gadget 1 - emisor LITERAL de la fuente:
  openedwindow = window.open('https://www.example.com');
  ...
  openedwindow.postMessage('{"type":"sdk-load-embed"}','*');
  #
  # ADVERTENCIA DE PROCEDENCIA: la RESPUESTA del listener, que es la que transporta
  # location.href, aparece en la fuente SOLO en una captura de pantalla. El texto no
  # la contiene y NO la reconstruyo.
  #
  # Los '...' son de la propia fuente.
  #
  # Mecanica: el atacante abre la pagina del 'non-happy path' (con el token aun en la
  # URL), le manda un postMessage de sondeo, y un listener con comprobacion de origen
  # debil responde incluyendo location.href -> el token sale al atacante.
precondicion: "(1) La victima ha aterrizado en la pagina del 'non-happy path' con el token aun en location.href (ver writeups oauth-response-type-switching y oauth-redirect-uri-*). (2) Esa pagina tiene un listener de postMessage con comprobacion de origen DEBIL o inexistente. (3) El atacante conserva un handle de ventana hacia esa pagina (window.open)."
como_se_descubre: |
  Inventariar los listeners de postMessage de las paginas que participan en el flujo
  OAuth, INCLUIDAS las paginas de error. Buscar en el JS listeners cuya comprobacion
  de origen sea laxa: ausencia de comprobacion, 'indexOf' en lugar de igualdad, o
  comparacion contra una lista vacia.
  Señal de alto valor: SDKs de terceros (analitica, soporte, chat) cargados en paginas
  de callback. La fuente señala que cambios posteriores via Google Tag Manager o del
  propio proveedor pueden INTRODUCIR la fuga mas tarde: un flujo auditado hoy puede
  volverse vulnerable sin que cambie el codigo del sitio.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: postMessage de sondeo al handle de ventana desde un origen ATACANTE
  #    -> si llega respuesta con location.href, la comprobacion de origen es debil
  # B: el mismo postMessage desde el origen LEGITIMO
  #    -> respuesta esperada (comportamiento normal del SDK)
  # El par distingue 'el listener responde a cualquiera' de 'el listener funciona'.
  # Si A no recibe nada, la comprobacion de origen es correcta y el gadget muere,
  # aunque el token siga varado en la URL.
mata: |
  - El listener compara event.origin por igualdad exacta contra una constante -> muere.
  - La pagina de destino no carga scripts de terceros (la recomendacion del IETF).
  - El sitio consume y limpia el token de la URL al cargar -> no hay nada que leer.
  - El atacante no puede obtener un handle de ventana hacia la pagina.
fuente: "https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/ (Frans Rosen, Detectify, 2022-07-06), 'Gadget 1: Weak or no origin-check postMessage-listeners that leaks URL'. Emisor literal de la pagina; la respuesta del listener solo existe en captura. La fuente dice que el servicio de analitica y un tercero 'had a bug bounty', sin indicar pagos."
confianza: media
fecha: 2026-11-02
---
# [AUTH] Gadget de fuga: listener de `postMessage` con origen débil que devuelve `location.href`

## Principio
Esta es la segunda mitad de la cadena. La primera deja un token válido varado en la URL
de una página que no lo consume; esta lo extrae. El vehículo es un patrón corriente en
SDKs de terceros: un listener de `postMessage` que, al recibir un mensaje de sondeo,
responde con información de contexto **incluyendo la URL actual**. Si ese listener no
comprueba el origen con rigor, responde al atacante — y la URL que devuelve lleva el
token dentro.

## Payload
El emisor, literal de la fuente:

```javascript
openedwindow = window.open('https://www.example.com');
...
openedwindow.postMessage('{"type":"sdk-load-embed"}','*');
```

## Advertencia de procedencia
La **respuesta** del listener, que es la pieza que transporta `location.href`, aparece
en el artículo únicamente en una captura de pantalla. El texto no la contiene y no la
reconstruyo: inventar la forma de un mensaje sería fabricar el payload que importa. De
ahí `confianza: media`.

## Lo que hace peligrosa a esta clase
Dos cosas, y ninguna es técnica.

La primera: el gadget vive en **código de terceros**. El equipo que implementó OAuth
correctamente no escribió el listener, y probablemente no sabe que existe.

La segunda, que la fuente señala y es la más incómoda: cambios posteriores a través de
Google Tag Manager o del propio proveedor del SDK **pueden introducir la fuga más
tarde**. Un flujo OAuth auditado hoy y declarado seguro puede volverse vulnerable mañana
sin que cambie una línea del código del sitio. Eso convierte la recomendación del IETF
—ninguna página del flujo carga recursos de terceros— en un control estructural y no en
una buena práctica opcional: es lo único que resiste cambios que no controlas.

## Impacto
Cierra la cadena hasta secuestro de cuenta con un clic: la víctima pulsa un enlace, el
baile se rompe, el token queda en la URL y el gadget lo entrega al atacante.

## Remediación
Comparar `event.origin` por igualdad exacta contra una constante — nunca con `indexOf`,
nunca contra una lista que pueda estar vacía. Y la regla del IETF que cita la fuente:
*"The page rendered as a result of the OAuth authorization response and the
authorization endpoint SHOULD NOT include third-party resources or links to external
sites."* Con la extensión que añade el autor, en negrita en el original: *"This also
includes the error-pages that might show up if the endpoint fails to complete the
sign-in process successfully."*

La fuente es concreta sobre el inventario: *"Know what kind of pages that are involved in
the OAuth-dance. This includes exception- or error pages that could be triggered to show
up in the flow if any parameters expected in the dance are wrong or missing."* Y:
*"Make sure those pages does not use any third-party scripts."*
