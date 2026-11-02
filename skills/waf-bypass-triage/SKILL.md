---
name: waf-bypass-triage
description: Triaje de evasion de WAF por discrepancia de parseo de contenido (JSON, multipart, XML). Decide que mutacion estructural probar y exige el control negativo antes de cualquier conclusion.
model: claude-opus-5
---

# 0 — SEÑAL CITADA

> **WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls.**
> Akhavani, Jabiyev, Kallus, Topcuoglu, Bratus, Kirda. arXiv:2503.10846v4, CC BY 4.0.
> Repositorio: `github.com/sa-akhavani/waffled` (HEAD `747f79d`, MIT).

La precondicion de TODA la clase, y es de parseo, no de payload:

> *"Our method exploits content parsing discrepancies between WAFs and web application
> frameworks."*

**El payload de ataque NUNCA cambia.** Las mutaciones se aplican *"everywhere except the
attack payload itself"*. Lo que se modifica es el ENVOLTORIO: el nombre de la cabecera
`Content-Type`, su valor, el delimitador de boundary, la posicion de un byte NUL.

**Instruccion literal de los autores, que es el paso 1 de esta skill:**

> *"It only modifies the request structure. If you are testing a WAF, make sure that these
> attack payloads are detected by the WAF when sent in a normal request."*

Descargo de los autores, que esta skill hereda:

> *"The listed bypasses are only and only for testing purposes and education purposes. We
> highly discourage the use of these bypasses in any production environment."*

Alcance: **pruebas autorizadas** sobre infraestructura propia o con permiso explicito.

---

# 1 — Arbol de decision (coste creciente)

## Paso 0 — CONTROL NEGATIVO. Obligatorio, no opcional (coste: 1 peticion)
Enviar el payload de ataque en una peticion **perfectamente formada**:

```
POST /json HTTP/1.1
Host: <objetivo>
Content-Type: application/json
Content-Length: 52

{"field1":"<script>alert(document.cookie)</script>"}
```

- **NO se bloquea** -> PARAR. El WAF no inspecciona ese endpoint o esa clase. Ningun
  resultado posterior prueba nada. Esto NO es un bypass: es ausencia de inspeccion.
- **Se bloquea** -> hay inspeccion. Seguir.

El dataset trae las cuatro bases detectables en `bypass-database/detectables/` (XSS e
inyeccion, JSON y multipart). Usar esas, no una inventada.

## Paso 1 — Fingerprint del WAF y del framework (coste: 2-3 peticiones)
Sin esto no se puede fechar el hallazgo ni cumplir el criterio de objetivo identificable.
Señales utiles de la propia infraestructura (`Server:`):
`awselb/2.0` · `Microsoft-Azure-Application-Gateway/v2` · `nginx/1.18.0` ·
`cloudflare` · `AkamaiGHost`.

Si el objetivo expone cabeceras de depuracion de CRS, son oro: `x-crs-version`,
`x-crs-paranoia-level`. El dataset documenta bypasses contra **CRS 3.3.6, paranoia 1 y 2**.

- **Sin version ni fecha** -> el hallazgo no es reportable como bypass de un producto
  concreto. Anotarlo y seguir, pero el informe lo dira.

## Paso 2 — Corromper el NOMBRE de `Content-Type` (coste: 4 peticiones)
**Empezar aqui siempre.** Es el grupo con mejor relacion coste/resultado: el WAF no
reconoce el tipo, **no inspecciona el cuerpo**, y el framework de la aplicacion —mas
tolerante— lo parsea igual.

```
ContentType: application/json          <- sin el guion
Content_-Type: multipart/form-data; boundary=real
Cntent-Type: multipart/form-data; boundary=real
(y la variante: cabecera Content-Type AUSENTE por completo)
```

- **Alguna pasa** -> hallazgo. Ir al paso 6 (clasificar) y parar de probar mutaciones.

## Paso 3 — Alterar el VALOR de `Content-Type` (coste: 3 peticiones)
```
Content-Type: \tmultipart/form-data; boundary*0=re;boundary*1=al
Content-Type: multipart/form-data; boundary*0=re;boundary*1=al
Content-Type: multipart/form-data; boundary=real;      (+ cuerpo sin linea en blanco)
```
El `\t` es un **TAB real (0x09)**, no la cadena de dos caracteres. `boundary*0`+`boundary*1`
es continuacion **RFC 2231** y se concatena a `real`.

## Paso 4 — Byte NUL, por posicion (coste: 9 peticiones)
El NUL **cuenta como byte** en `Content-Length`. Emitir el byte real `0x00`, no `\x00`.

**JSON — 3 posiciones:**
```
{"field1"<NUL>:"<payload>"}      <- entre nombre y dos puntos
{"field1<NUL>:"<payload>"}       <- dentro del nombre, comilla desbalanceada
{"f<NUL>eld1":"<payload>"}       <- en medio del nombre
```

**Multipart — 6 posiciones:** nombre de cabecera de parte (`conten<NUL>-extra:`), valor de
`content-disposition` (`form-da<NUL>a;`), valor del `Content-Type` de parte
(`tex<NUL>t/plain`), valor del charset en el cuerpo (`u<NUL>tf-8`), separador
(`name="field1"<NUL>` + **LF desnudo**), y dentro del nombre entrecomillado
(`name="field1<NUL>"`).

## Paso 5 — Estructura: boundary y XML (coste: 7 peticiones)
**Boundary:** primer delimitador con **un solo guion** (`-real`) · primer delimitador
**eliminado** (`\r\n`) · **CR solitario** (`boundary=real\r` + `\n--real`).

**XML:** `Content-Type` **dentro del cuerpo**, tras la linea en blanco · valor **sin nombre
de cabecera** (`application/xml` suelto) · valor **duplicado**
(`application/xmlapplication/xml`) · entidad del DOCTYPE + comentario + `&gt;` adyacentes al
payload · `]` o un caracter suelto desbalanceando el cierre.

## Paso 6 — Clasificar y fechar (coste: 0 peticiones)
Mapear la mutacion a su clase oficial (TABLE IV/V/VI del paper: `Boundary Delimiter
Manipulation`, `Content-Disposition Disruption`, `Linefeed Removal`, `Whitespace
Alteration`, `Disrupted Body Field`, `Boundary Header Tampering`, y 6 mas). Registrar WAF,
version, ruleset y **fecha de la prueba**: un bypass sin fecha no es verificable.

---

# 2 — Trampas de falso positivo

**1. Ausencia de inspeccion leida como bypass.** Si el paso 0 no se bloquea, el WAF no
estaba mirando. **Señal de muerte:** el payload de ataque pasa **tambien** en una peticion
perfectamente formada. Es el error que invalida informes enteros de esta clase, y la razon
de que los propios autores exijan el control primero.

**2. El `\x00` del paper tomado como literal.** El HTML del paper **no tiene ni un byte de
control**: sus `\x00`, `\t` y `\r\n` son **texto de 2-4 caracteres ASCII**. **Señal de
muerte:** el payload falla y `Content-Length` cuadra contando `\x00` como cuatro bytes en
lugar de uno. Hay que **emitir el byte real**.

**3. El origen bloquea, no el WAF.** Un 400 o un 403 puede venir del servidor de aplicacion
rechazando la peticion malformada, no del WAF detectando el ataque. **Señal de muerte:** la
misma mutacion estructural **con un payload inofensivo** produce el mismo codigo de estado.
Si la estructura corrupta se rechaza sola, no has esquivado nada: has roto la peticion.

---

# 3 — Cuándo esta skill NO es la correcta

- El objetivo **no tiene WAF** (paso 0 no bloquea) -> no hay nada que evadir. El hallazgo,
  si existe, es la vulnerabilidad subyacente.
- Lo que discrepa son **dos parsers HTTP** sobre el framing de la peticion (CL/TE, Expect,
  chunked), no sobre el contenido -> `skill:desync-triage`
- La discrepancia esta en la **URL o el host** (userinfo, UNC, normalizacion de ruta)
  -> `skill:ssrf-escalation`
- El filtro que se esquiva es de **sanitizacion de HTML en el navegador**, no un WAF de red
  -> `skill:xss-sink-triage`
- El bypass es de **control de acceso por ruta** (`%3F`, sufijo, barra final) y no de
  inspeccion de contenido -> ver `writeups/idor/` y `docs/ELITE-CHEATSHEET-BYPASS.md` §1
- El objetivo es la **verificacion de firma** de un token, no un WAF
  -> `skill:jwt-attack-tree`

---

# 4 — Output

Escribir en `evidencias/waf-bypass-triage-<slug>.md`:

- **resultado del paso 0**, textual: ¿se bloqueo la peticion bien formada? Sin esto el
  informe no vale.
- WAF y framework identificados, con version, ruleset y **fecha de la prueba**
- paso del arbol alcanzado y por que se paro ahi
- la mutacion exacta que paso, **en bytes** (indicando donde hay NUL, TAB o CR reales)
- su clase oficial en TABLE IV/V/VI
- las tres trampas de falso positivo, con su resultado — en particular la 3: la misma
  mutacion con payload inofensivo
- remediacion: que el WAF **bloquee** lo que no puede parsear. "No inspeccionado" debe ser
  un estado de rechazo, no de aprobacion silenciosa (HTTP-Normalizer del propio paper)

Sin el paso 0 documentado, el informe no esta terminado.
