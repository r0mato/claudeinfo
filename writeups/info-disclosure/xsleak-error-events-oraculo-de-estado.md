---
clase: info-disclosure
tech: xs-leaks
cwe: CWE-203
cvss: 5.3 # [derivado] fuga de informacion entre origenes sin leer el cuerpo de la respuesta
payload: |
  # CODIGO LITERAL de la fuente (saltos de linea colapsados por el render):
  function checkId(id) {     const script = document.createElement('script');     script.src = `https://example.com/api/users/${id}`;     script.onload = () => {         console.log(`Logged user id: ${id}`);     };     document.body.appendChild(script); }  // Generate array [0, 1, ..., 40] const ids = Array(41)     .fill()     .map((_, i) => i + 0);  for (const id of ids) {     checkId(id); }
  #
  # OBSERVACION IMPORTANTE: el snippet registra UNICAMENTE un handler 'onload'.
  # NO hay handler 'onerror'. La informacion esta en el SILENCIO: si onload no se
  # dispara, la respuesta no fue 200.
  #
  # Oraculo segun la fuente: '200 OK' para el usuario autenticado y
  # '401 Unauthorized' para los demas IDs.
  #
  # DEFENSA 1 - token de subrecurso, URL LITERAL de la fuente:
  /api/users/1234?token=be930b8cfb5011eb9a030242ac130003
  #
  # DEFENSA 2 - Sec-Fetch-Site, CODIGO LITERAL de la fuente
  # (el comentario '// ... more code' es de la propia pagina, no una elision mia):
  app.get('/api/users/:id', authorization, (req, res) => {     if (req.get('Sec-Fetch-Site') === 'cross-site') {         return res.sendStatus(403);     }      // ... more code      return res.send({ id: 1234, name: 'John', role: 'admin' }); });
precondicion: "El endpoint devuelve estados HTTP DISTINTOS segun el usuario autenticado (200 para el propio, 401 para los demas). Cita de la fuente sobre por que esto es alcanzable: incrustar recursos de otro origen esta 'generally allowed'. El atacante NUNCA necesita leer el cuerpo de la respuesta: le basta saber si cargo o no."
como_se_descubre: |
  Señal en recon: endpoints de API cuyo codigo de estado depende de la identidad del
  solicitante. El patron '200 para lo tuyo / 401 para lo ajeno' es correcto desde el
  punto de vista de autorizacion y aun asi es un oraculo.
  Sonda desde una pagina del atacante: incrustar el endpoint con <script src> para un
  rango de IDs y registrar cuales disparan onload. No hace falta CORS ni leer nada.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: incrustar /api/users/<id-propio>  -> onload SI dispara
  # B: incrustar /api/users/<id-ajeno>   -> onload NO dispara
  # C: incrustar /api/users/999999999 (inexistente) -> comparar con B
  # El control C importa: si un ID inexistente se comporta IGUAL que uno ajeno, el
  # oraculo solo distingue 'existe y es mio' de 'todo lo demas', que es una fuga mas
  # debil. Si se comportan DISTINTO, el oraculo distingue tres estados y permite
  # enumerar que IDs existen, que es una fuga mayor.
mata: |
  - El endpoint devuelve el MISMO estado HTTP para todos los casos (p.ej. 200 con
    cuerpo vacio, o 404 uniforme) -> el oraculo desaparece.
  - Comprobacion de Sec-Fetch-Site que rechace peticiones cross-site.
  - Token de subrecurso impredecible en la URL.
  - Cross-Origin-Resource-Policy que impida la incrustacion.
fuente: "https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html (seccion 'Attacks based on error events'). Codigo de ataque, URL con token y codigo de Sec-Fetch-Site literales de la pagina. Contenido CC BY-SA 4.0 segun el pie de la pagina. ADVERTENCIA: el render colapso los saltos de linea del codigo."
confianza: alta
fecha: 2026-11-02
---
# [INFO-DISCLOSURE] XS-Leak por eventos de error — el código de estado como oráculo entre orígenes

## Principio
La política del mismo origen impide **leer** una respuesta de otro origen, pero no
impide **incrustar** un recurso de otro origen ni observar si la carga tuvo éxito. Eso
deja un canal de un bit por petición que la SOP no cubre. Si el estado HTTP depende de
quién eres, ese bit habla de ti.

Lo incómodo es que el patrón vulnerable es el patrón **correcto**: devolver 200 para tus
propios datos y 401 para los de otro es exactamente lo que se espera de una API bien
autorizada.

## Payload
```javascript
function checkId(id) {     const script = document.createElement('script');     script.src = `https://example.com/api/users/${id}`;     script.onload = () => {         console.log(`Logged user id: ${id}`);     };     document.body.appendChild(script); }  // Generate array [0, 1, ..., 40] const ids = Array(41)     .fill()     .map((_, i) => i + 0);  for (const id of ids) {     checkId(id); }
```

## El detalle elegante: no hay `onerror`
El snippet registra **únicamente** `onload`. No hay handler de error. La información
está en el silencio: si `onload` no se dispara, la respuesta no fue 200. Eso hace el
ataque más robusto de lo que parece, porque no depende de que el navegador exponga
ningún detalle del fallo — solo de que la ausencia de éxito sea observable, y eso no se
puede ocultar.

## El tercer estado que conviene comprobar
Vale la pena probar un ID que **no exista**. Si se comporta igual que un ID ajeno, el
oráculo solo distingue "existe y es mío" del resto: fuga moderada. Si se comporta
distinto, el oráculo distingue tres estados y permite además **enumerar qué IDs
existen**, lo que convierte la fuga en un inventario de la base de usuarios. Es una
petición y cambia el impacto que se reporta.

## Impacto
Determinar desde un sitio cualquiera qué cuenta tiene abierta la víctima en otro
servicio, y enumerar identificadores válidos. Es desanonimización entre orígenes: el
atacante no obtiene datos, obtiene **la identidad** de quien visita su página.

## Remediación
Dos defensas literales de la fuente. Token de subrecurso en la URL:

```
/api/users/1234?token=be930b8cfb5011eb9a030242ac130003
```

La fuente precisa que el token *"should be long and unique"* y que el back-end
*"must correctly validate the token passed in the request."*

Y comprobación de Fetch Metadata:

```javascript
app.get('/api/users/:id', authorization, (req, res) => {     if (req.get('Sec-Fetch-Site') === 'cross-site') {         return res.sendStatus(403);     }      // ... more code      return res.send({ id: 1234, name: 'John', role: 'admin' }); });
```

El `// ... more code` es de la propia página. Los valores que el navegador pone en
`Sec-Fetch-Site` son `cross-site`, `same-origin`, `same-site` y `none`. La fuente nombra
también `Cross-Origin-Resource-Policy`, con valores `same-site`, `same-origin` y
`cross-origin`, aunque no da una línea de cabecera completa.

`# [derivado]`: la defensa más simple, cuando el diseño lo permite, es uniformar el
estado HTTP — responder siempre 200 y poner el resultado de la autorización en el
cuerpo, que la SOP sí protege.
