---
clase: idor
tech: client-side-js
cwe: CWE-615
cvss: 7.5 # [derivado] revelacion de funcionalidad administrativa no protegida
payload: |
  # Fragmento LITERAL de la fuente (el script esta servido a TODOS los usuarios):
  <script>
  var isAdmin = false;
  if (isAdmin) {
     ...
     var adminPanelTag = document.createElement('a');
     adminPanelTag.setAttribute('href', 'https://insecure-website.com/administrator-panel-yb556');
     adminPanelTag.innerText = 'Admin panel';
     ...
  }
  </script>
  # Los '...' son de la propia fuente.
  #
  # Cita literal de la fuente: 'the script containing the URL is visible to all users
  # regardless of their role.'
  #
  # URLs relacionadas, literales de la pagina:
  https://insecure-website.com/admin
  https://insecure-website.com/robots.txt
  https://insecure-website.com/administrator-panel-yb556
precondicion: "La funcionalidad administrativa no esta protegida por autorizacion en el servidor y se 'protege' unicamente ocultando su URL. El bloque condicional de JS se entrega a todos los usuarios, con la URL dentro, aunque la rama no se ejecute. ADVERTENCIA: la fuente usa un dominio de ejemplo generico (insecure-website.com) y NO nombra ningun objetivo real; lo reproducible aqui es el PATRON, no un caso concreto."
como_se_descubre: |
  1. Descargar todo el JS del sitio, incluidos bundles y source maps, y buscar cadenas
     de ruta dentro de ramas condicionales por rol ('isAdmin', 'role', 'permissions').
     Una rama que no se ejecuta sigue siendo texto entregado al cliente.
  2. robots.txt: la fuente lo nombra expresamente. Una ruta que se pide excluir de la
     indexacion es una ruta que existe y que alguien considera sensible.
  3. Fuerza bruta con wordlist, que la fuente menciona para rutas ofuscadas.
  El orden importa: (1) y (2) son gratis y suelen dar el resultado que (3) busca a
  base de ruido.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: GET /administrator-panel-yb556 SIN sesion (o con sesion de usuario normal)
  #    -> si devuelve el panel, no hay autorizacion: el hallazgo es control de acceso
  # B: GET /administrator-panel-yb556 con sesion de administrador
  #    -> devuelve el panel (comportamiento esperado)
  # El par A/B es decisivo para la CLASIFICACION del hallazgo. Si A devuelve 403, lo
  # unico que hay es revelacion de informacion (una URL filtrada), no bypass de
  # control de acceso. Son severidades muy distintas y conviene no inflar el reporte.
mata: |
  - A devuelve 403/401 -> hay autorizacion real; el hallazgo se reduce a fuga de la URL.
  - El JS se genera por rol en el servidor y no incluye la rama de admin para usuarios
    normales.
  - La URL no aparece en JS, robots.txt ni source maps, y no es adivinable.
fuente: "https://portswigger.net/web-security/access-control (seccion 'Unprotected functionality'). Fragmento de JS y URLs literales de la pagina. La pagina usa el dominio de ejemplo insecure-website.com y no nombra objetivos reales."
confianza: media
fecha: 2026-11-02
---
# [IDOR] JavaScript de cliente que filtra la URL del panel administrativo ofuscado

## Principio
Ofuscar la URL de una función administrativa no es control de acceso, y la razón
concreta es que el navegador necesita el código completo para decidir qué mostrar. El
servidor envía el bloque condicional **a todos**, con la URL dentro. La rama no se
ejecuta para un usuario normal, pero el texto ya está en su máquina.

Cita literal: *"the script containing the URL is visible to all users regardless of
their role."*

## Payload
```html
<script>
var isAdmin = false;
if (isAdmin) {
   ...
   var adminPanelTag = document.createElement('a');
   adminPanelTag.setAttribute('href', 'https://insecure-website.com/administrator-panel-yb556');
   adminPanelTag.innerText = 'Admin panel';
   ...
}
</script>
```

El sufijo `-yb556` es el intento de ofuscación, y está servido en claro a cualquiera
que mire el fuente.

## Advertencia de procedencia
La fuente es material docente: usa el dominio genérico `insecure-website.com` y **no
nombra ningún objetivo real**. Lo reproducible aquí es el patrón de búsqueda, no un caso
concreto, y por eso va con `confianza: media`. Lo conservo porque el patrón sí es
accionable y la cita sobre la visibilidad del script es literal.

## Orden de búsqueda
Tres vías, en orden de coste creciente:

1. **JS y source maps**: buscar cadenas de ruta dentro de ramas condicionales por rol
   (`isAdmin`, `role`, `permissions`). Gratis y silencioso.
2. **robots.txt**, que la fuente nombra expresamente. Una ruta que alguien pide excluir
   de la indexación es una ruta que existe y que se considera sensible. Gratis.
3. **Fuerza bruta con wordlist**, que la fuente también menciona. Ruidosa y la última
   opción — y normalmente innecesaria si (1) y (2) dieron resultado.

## El control negativo decide la severidad
Pedir la URL filtrada **sin privilegios** es lo que distingue dos hallazgos muy
distintos. Si devuelve el panel, es un bypass de control de acceso. Si devuelve 403,
lo único que hay es una URL filtrada: revelación de información, severidad mucho menor.
Reportar el segundo como el primero es un error que cuesta credibilidad, y cuesta una
sola petición evitarlo.

## Remediación
Cita literal, que es exactamente la lección: *"Never rely on obfuscation alone for
access control."* Y: *"Unless a resource is intended to be publicly accessible, deny
access by default."*

`# [derivado]`: la autorización se comprueba en el servidor en cada petición al recurso.
Lo que el cliente muestre u oculte es una cuestión de interfaz, nunca de seguridad — y
el código que decide la interfaz viaja al cliente por definición.
