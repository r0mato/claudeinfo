---
clase: auth
tech: s3-cdn-csp
cwe: CWE-346
cvss: 8.8 # [derivado] XSS en subdominio de cliente + fuga de token OAuth
payload: |
  # URLs LITERALES de la fuente (CDN de un proveedor de analitica, anonimizado por el
  # autor como analytics.example.com):
  https://cdn.analytics.example.com/img/customer42326/event-image.png
  https://cdn.analytics.example.com/img/customer21131/test.png
  https://cdn.analytics.example.com/img/customer54353/icon-register.svg
  https://cdn.analytics.example.com/img/customer94342/tiger.svg
  https://cdn.customer12345.analytics.example.com/img/customer94342/tiger.svg
  #
  # SVG con XSS, LITERAL de la fuente:
  <?xml version="1.0" encoding="UTF-8" standalone="no"?>
  <svg id="svg2"  xmlns_xlink="http://www.w3.org/1999/xlink" viewbox="0 0 500 500" width="100%" height="100%" version="1.1">
  <script xlink_href="data:,alert(document.domain)"></script>
  </svg>
  # NOTA: la fuente imprime 'xmlns_xlink' y 'xlink_href' con subrayado (eran escapes
  # de markdown). En XML real son 'xmlns:xlink' y 'xlink:href'.
  #
  # El iframe del atacante, LITERAL. La clave es el 'img%2f' en lugar de 'img/':
  <div id="leak"><iframe
  id="i" name="i"
  src="https://cdn.customer12345.analytics.example.com/img%2fcustomer94342/listener.svg"
  onload="run()"></iframe></div>
precondicion: "MECANICA LITERAL de la fuente: el CDN enviaba 'Content-Security-Policy: default-src 'self'' para todo lo que estuviera bajo 'img/'. S3 trata la '/' como parte de la clave del objeto, de modo que 'img%2f' SIGUE RESOLVIENDO al mismo objeto pero esa ruta NO coincide con la regla que añade la CSP. Ademas, el SVG subido por OTRO cliente se sirve bajo el subdominio del cliente victima (mix-up de clientes en el CDN)."
como_se_descubre: |
  Dos observaciones independientes que solo valen juntas:
  1. El CDN sirve ficheros de un cliente bajo el subdominio de OTRO cliente
     (probar cdn.customerAAA.../img/customerBBB/fichero.svg).
  2. La cabecera CSP se añade por PREFIJO DE RUTA ('img/'), no por objeto.
  La sonda para (2) es pedir el mismo objeto con 'img%2f' y comparar las cabeceras de
  respuesta: si la CSP desaparece, la regla es textual sobre la ruta y el almacen
  resuelve la forma codificada.
  Generalizacion: cualquier control de seguridad aplicado por coincidencia de PREFIJO
  DE RUTA mientras el almacen trata la ruta como clave OPACA tiene esta forma.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: GET .../img%2fcustomer94342/listener.svg -> 200 y SIN cabecera CSP
  # B: GET .../img/customer94342/listener.svg   -> 200 y CON 'default-src self'
  # El par A/B es el hallazgo completo en dos peticiones: mismo objeto, misma
  # respuesta, politica de seguridad distinta. Es la demostracion mas limpia posible
  # y no requiere montar el flujo OAuth para evidenciarla.
mata: |
  - La CSP se aplica por objeto o a nivel de respuesta, no por prefijo de ruta -> muere.
  - El CDN no sirve ficheros de un cliente bajo el subdominio de otro.
  - Los SVG subidos se sirven con Content-Type que no ejecuta, o desde origen aislado.
  - El proveedor de analitica ya lo corrigio (el autor se lo reporto).
fuente: "https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/ (Frans Rosen, Detectify, 2022-07-06), 'Gadget 3' ejemplo 2. Amazon S3 nombrado como backend del CDN. El proveedor de analitica esta anonimizado por el autor. Sin CVE ni recompensa indicados."
confianza: alta
fecha: 2026-11-02
---
# [AUTH] Bypass de CSP por codificación de ruta en un CDN sobre S3 — `img%2f` deja caer la cabecera

## Principio
El CDN añadía `Content-Security-Policy: default-src 'self'` a todo lo servido bajo
`img/`. La regla se evalúa sobre el **texto de la ruta**. Pero S3 trata la `/` como un
carácter cualquiera dentro de la clave del objeto, así que `img%2fcustomer94342/...`
resuelve al mismo fichero — y no coincide con la regla. Mismo objeto, misma respuesta,
sin política de seguridad.

Es un desajuste entre dos capas que leen la misma cadena con reglas distintas: una la
interpreta como jerarquía de rutas, la otra como clave opaca.

## Payload
Las URLs del CDN, que muestran la estructura por cliente:

```
https://cdn.analytics.example.com/img/customer94342/tiger.svg
https://cdn.customer12345.analytics.example.com/img/customer94342/tiger.svg
```

La segunda es ya media vulnerabilidad: el fichero del cliente `94342` servido bajo el
subdominio del cliente `12345`.

El SVG con XSS, literal de la fuente:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg id="svg2"  xmlns_xlink="http://www.w3.org/1999/xlink" viewbox="0 0 500 500" width="100%" height="100%" version="1.1">
<script xlink_href="data:,alert(document.domain)"></script>
</svg>
```

La fuente imprime `xmlns_xlink` y `xlink_href` con subrayado, residuo de los escapes de
markdown; en XML real son `xmlns:xlink` y `xlink:href`.

Y el iframe del atacante, donde está la pieza decisiva — `img%2f` en lugar de `img/`:

```html
<div id="leak"><iframe
id="i" name="i"
src="https://cdn.customer12345.analytics.example.com/img%2fcustomer94342/listener.svg"
onload="run()"></iframe></div>
```

## El control negativo es el informe
Dos peticiones bastan para demostrarlo todo:

| | Petición | Resultado |
|---|---|---|
| A | `GET .../img%2fcustomer94342/listener.svg` | 200, **sin** CSP |
| B | `GET .../img/customer94342/listener.svg` | 200, **con** `default-src 'self'` |

El mismo objeto, servido igual, con política distinta. No hace falta montar el flujo
OAuth para evidenciar el fallo: el par A/B es autosuficiente, lo que lo hace fácil de
triar y difícil de discutir.

## Impacto
Tres fallos encadenados: mix-up de clientes en el CDN, ejecución de SVG subido, y
pérdida de la CSP por codificación de ruta. El resultado es XSS en el subdominio del
cliente víctima, que sirve como gadget para leer el token OAuth varado — y, con la CSP
caída, para exfiltrarlo sin restricción de destino.

## Remediación
`# [derivado]`, ya que la fuente no da remediación para este caso: aplicar las cabeceras
de seguridad **por objeto o por respuesta**, no por coincidencia de prefijo de ruta;
normalizar y decodificar la ruta antes de evaluar cualquier regla; aislar los ficheros
subidos por clientes distintos en orígenes distintos; y servir SVG de usuario con un
`Content-Type` que no ejecute o desde un dominio sandbox.

La lección transferible es la regla general: **un control de seguridad que coincide por
prefijo de ruta sobre un almacén que trata la ruta como clave opaca siempre tiene un
bypass de codificación.** Vale para CSP, para reglas de WAF y para autorización por
ruta.
