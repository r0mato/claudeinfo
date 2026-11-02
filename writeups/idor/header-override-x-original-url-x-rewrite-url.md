---
clase: idor
tech: front-end-proxy
cwe: CWE-290
cvss: 8.8 # [derivado] acceso a funcionalidad administrativa restringida
payload: |
  # Peticion LITERAL de la fuente (los '...' son de la propia pagina):
  POST / HTTP/1.1
  X-Original-URL: /admin/deleteUser
  ...
  #
  # Cabeceras que la fuente nombra como no estandar y capaces de sobrescribir la URL
  # de la peticion original:
  #   X-Original-URL
  #   X-Rewrite-URL
  # La fuente NO da valor de ejemplo para X-Rewrite-URL; por simetria:
  X-Rewrite-URL: /admin/deleteUser
  #
  # Regla de control de acceso del front-end del ejemplo, LITERAL:
  DENY: POST, /admin/deleteUser, managers
  #
  # Mecanica: el front-end ve la peticion a '/' y la permite (su regla solo cubre
  # /admin/deleteUser). La aplicacion de atras reescribe la ruta usando la cabecera
  # y ejecuta /admin/deleteUser.
precondicion: "Cita literal de la fuente: 'If a website uses rigorous front-end controls to restrict access based on the URL, but the application allows the URL to be overridden via a request header, then it might be possible to bypass the access controls.' Es decir: control de acceso aplicado en el front-end por URL, y un framework de atras que honre estas cabeceras no estandar."
como_se_descubre: |
  Señal en recon: dos capas (CDN/proxy/WAF delante, aplicacion detras) y rutas
  administrativas que devuelven 403 desde el borde en lugar de 404. Un 403 del borde
  indica que es el FRONT-END quien decide, que es la precondicion.
  Sonda de coste minimo: pedir '/' con 'X-Original-URL: /admin' y comparar la
  respuesta con la de pedir '/' a secas. Si el contenido cambia, la cabecera se honra.
  Esta sonda es barata y conviene lanzarla siempre que se vea un 403 de borde, porque
  el fallo no esta en la aplicacion ni en el proxy, sino en que cada uno cree que la
  URL es otra.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: POST / con 'X-Original-URL: /admin/deleteUser'  -> respuesta de /admin/deleteUser
  # B: POST / sin la cabecera                           -> respuesta de la raiz
  # C: POST /admin/deleteUser directo                   -> 403 del front-end
  # El trio es el informe completo: C demuestra que el control EXISTE, A que se puede
  # esquivar, B que la diferencia la causa la cabecera. Sin C, un triador puede pensar
  # que la ruta era publica.
mata: |
  - El framework de atras no honra X-Original-URL ni X-Rewrite-URL -> muere.
  - El front-end elimina (strip) estas cabeceras en el borde, que es la correccion.
  - El control de acceso se aplica EN la aplicacion y no solo en el front-end.
  - A y C dan la misma respuesta -> la cabecera no se honra.
fuente: "https://portswigger.net/web-security/access-control (seccion 'Broken access control resulting from platform misconfiguration'). Peticion, nombres de cabecera y regla DENY literales de la pagina. La pagina no da valor de ejemplo para X-Rewrite-URL ni menciona X-Forwarded-For en esta seccion."
confianza: alta
fecha: 2026-11-02
---
# [IDOR] Sobrescritura de la URL con `X-Original-URL` / `X-Rewrite-URL` — el proxy y la app no miran la misma ruta

## Principio
Cuando el control de acceso vive en el front-end y se decide por la URL, todo depende
de que el front-end y la aplicación estén de acuerdo en cuál **es** la URL. Varios
frameworks honran cabeceras no estándar que reescriben la ruta. El atacante pide una
ruta inocua, el proxy la aprueba, y la aplicación atiende otra.

Nótese que esto no es una vulnerabilidad de la aplicación ni del proxy por separado:
cada uno hace lo que se espera de él. El fallo está en la arquitectura de dos capas.

## Payload
```http
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
...
```

Los `...` son de la propia fuente. La regla del front-end del ejemplo:

```
DENY: POST, /admin/deleteUser, managers
```

El front-end ve una petición a `/`, que su regla no cubre, y la permite. La aplicación
reescribe la ruta desde la cabecera y ejecuta `/admin/deleteUser`.

La fuente nombra `X-Rewrite-URL` como la otra cabecera con el mismo efecto, aunque no
da valor de ejemplo para ella.

## Señal de recon que conviene memorizar
Un **403 devuelto por el borde** (en lugar de un 404) es la pista: significa que algo
delante de la aplicación está decidiendo según la URL, que es exactamente la
precondición. En cuanto se vea ese patrón, la sonda cuesta una petición: pedir `/` con
`X-Original-URL: /admin` y comparar.

## Impacto
Acceso a funcionalidad administrativa protegida, con el techo que marque esa
funcionalidad — en el ejemplo de la fuente, borrar usuarios. Y como el control vive en
el borde, el bypass suele aplicar a **todas** las rutas que ese borde protege, no solo a
una.

## Remediación
Citas literales de la fuente: *"Wherever possible, use a single application-wide
mechanism for enforcing access controls."* Y: *"Unless a resource is intended to be
publicly accessible, deny access by default."*

`# [derivado]`: el front-end debe **eliminar** `X-Original-URL` y `X-Rewrite-URL` de
toda petición entrante antes de reenviarla; son cabeceras internas y nunca deben
aceptarse del cliente. Pero la corrección de fondo es la que dice la fuente: el control
de acceso pertenece a la aplicación, donde se conoce la ruta real y la identidad del
usuario, no a una capa que solo ve texto.
