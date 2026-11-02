# ELITE-PLAN FASE 7 — Arsenal: cheatsheet de bypasses + metodología + mindset ampliado
**Fecha:** 2026-11-02 · **Raíz del repo:** `/home/user/claudeinfo` · rama `claude/quirky-feynman-s2jxet`

---

## 0 — ESTADO REAL DEL REPO (el prompt asume vacío; no lo está)

El Paso 0 del prompt describe un repo sin estructura. Hay **3 commits empujados** y:

| Capa | Estado | Techo del contrato |
|---|---|---|
| writeups | **96** en 10 clases | 120 → margen de **24** |
| skills | **6/6 — EN EL TECHO** | 6 |
| `docs/ELITE-MINDSET.md` | 20 principios con fuente | 20-30 → margen de **10** |
| `docs/ELITE-SOURCES.md` | 34 fuentes + backlog | — |
| `docs/ELITE-CHEATSHEET-BYPASS.md` | **NO EXISTE** | 1 |
| `docs/ELITE-METHODOLOGY.md` | **NO EXISTE** | 1 |

Planifico el **delta**. No rehago lo hecho ni recreo carpetas que ya existen.

---

## 1 — PRUEBAS DE VIABILIDAD (ejecutadas, no asumidas)

Antes de planificar probé las fuentes **nuevas** del prompt. Cuatro resultados cambian el plan:

### V1 — X/Twitter: INACCESIBLE. `HTTP 402 Payment Required`
Probados `x.com/naglinagli`, `twitter.com/rabhi_` (301 → x.com) y `x.com/albinowax`.
**Los tres devuelven 402.** Sin cuerpo de respuesta, sin muro de login, sin shell JS: la API
de X está detrás de pago y WebFetch no la alcanza.

**Consecuencia:** la Fase 1 del prompt —"busca en X/Twitter sus hilos"— **no es ejecutable
para ninguno de los 12 hunters**. No es un fallo recuperable con otra ruta ni con Chrome MCP
(que tampoco existe en esta sesión, hallazgo H3 de la Fase 0 original).

### V2 — "Decepticon WAF Bypass skill": NO LOCALIZABLE
Búsqueda extendida: **ningún resultado menciona ese nombre.** No puedo confirmar qué es ni
acceder a su tabla de técnicas. Queda fuera.

### V3 — `wafrift`: EXISTE pero NO es fuente de bypasses
Dos repos distintos comparten el nombre (`santhreal/wafrift`, `santhsecurity/wafrift`) y
ninguno se confirma canónico. Lo alcanzable y útil es el **código fuente en docs.rs**
(`wafrift-encoding`), que lista estrategias de codificación.

Pero eso es un **índice de técnicas de una herramienta**, no bypasses verificados contra
un WAF nombrado con versión y fecha. **Falla el criterio 2 del contrato.** Lo usaré solo
como taxonomía de nombres, marcado como tal — nunca como origen de una entrada del
cheatsheet.

### V4 — TBHM v5: sin fuente primaria. Pero hay algo mejor
No encontré slides ni writeup de v5. Lo que **sí** es alcanzable y vale más: las
**transcripciones de DEF CON en texto plano** (`media.defcon.org/.../*.txt` y `.srt`),
incluida la de *The Bug Hunter's Methodology* de Jason Haddix. Son **sus palabras
literales**, lo que satisface el criterio de fuente atribuible mejor que un hilo de X.

---

## 2 — SUSTITUTO DE LA FASE 1 (decisión declarada, no consulta)

X está muerto como fuente. Sustituyo hilo por hilo con material **citable y verbatim**:

| Hunter del prompt | Sustituto alcanzable |
|---|---|
| Jason Haddix | Transcripción DEF CON de TBHM (`media.defcon.org`, texto plano) |
| Rhynorater / Teknogeek | Notas de episodio de Critical Thinking (ep. 63 jhaddix, ep. 109 Creative Recon) |
| Gal Nagli | Writeups propios publicados; "Braindump on VDPs" citado en notas del podcast |
| NahamSec | Artículos de su blog |
| Frans Rosén | **YA EN EL REPO**: 5 writeups de OAuth desde Detectify Labs |
| James Kettle | **YA EN EL REPO**: 11 papers de PortSwigger Research |
| rabhi | **YA EN EL REPO**: entrevista YesWeHack, 8 principios citados |
| Gareth Heyes | **YA EN EL REPO**: email atom + prototype pollution |
| EdOverflow, Stök, dawgyg, putsi | Charlas y entrevistas si existen en transcripción; si no → rechazo registrado |

**Regla:** si un hunter no tiene material citable verbatim, **no invento un principio a su
nombre**. Se registra en `ELITE-REJECTED.md` como fallo de acceso. Atribuir una frase a
una persona real sin tenerla literal es la peor falta posible en este documento.

---

## 3 — EL CHEATSHEET: de dónde sale realmente

El prompt lo apoya en WAFFLED + Decepticon + wafrift + X. Dos de los cuatro han caído. La
base real será:

**(a) WAFFLED (arXiv:2503.10846)** — en verificación ahora mismo. arXiv es de acceso
abierto, así que el acceso no es el riesgo; el riesgo es que el paper describa *categorías*
sin dar *payloads literales*. Lo estoy comprobando antes de prometerlo.

**(b) El corpus de discrepancias de parser que YA está en el repo.** Esto es lo importante:
los 96 writeups contienen **~20 bypasses de discrepancia de parser ya verificados** contra
productos nombrados, cada uno cumpliendo el contrato. El cheatsheet no nace de fuentes
dudosas: nace de **sintetizar y cruzar material que ya pasó el filtro**:

- `%3F` contra `<Files>` + PHP-FPM (Apache, 2.4.60) — bypass de ACL
- `img%2f` tira la CSP de un CDN sobre S3
- `%2F..%2F` escapa del alcance de una regla de caché (Cloudflare/ChatGPT)
- `Expect:` vanilla y ofuscado (Akamai CVE-2025-32094, T-Mobile, GitLab)
- `Content-Type:` como selector de módulo en Apache (handler confusion)
- `\@` rompe `urlsplit` de Python; `%5C%5C` fuerza UNC en Windows
- `--` **no** cierra el parseo de opciones en curl
- encoded-word RFC 2047, UUCP bang path, comentarios RFC 2822, Punycode malformado
- `'foo' 'bar'` y `-- ` (con espacio) en MySQL; `;` como delimitador en Rails
- `__pro__proto__to__` reconstruye `__proto__` tras un filtro de una pasada
- `Expect: y 100-continue`, `response_type=code,id_token`, `/CaLlBaCk`

**(c) Lo que NO entra:** repos genéricos de GitHub (prohibidos por contrato — y las dos
alternativas que la búsqueda devolvió, `botesjuan/...` e `Ilias1988/...`, son exactamente
eso), blogs de Medium sin verificación, y la lista de estrategias de wafrift como si fueran
bypasses confirmados.

---

## 4 — CUOTAS DE ESTA FASE

| Entregable | Cuota | Nota |
|---|---|---|
| `docs/ELITE-CHEATSHEET-BYPASS.md` | 1, con 25-40 bypasses | Solo verificados. Sin relleno. |
| `docs/ELITE-METHODOLOGY.md` | 1 | Recon / Ataque / Reporte / Decisión, con cita por sección |
| `docs/ELITE-MINDSET.md` | +10 principios (20 → 30) | Solo con cita verbatim |
| writeups | hasta +24 (96 → 120) | Ver pregunta 3 |
| skills | 0 o +1 | Ver pregunta 1 |

---

## 5 — EJECUCIÓN

Ultracode está activo, así que orquestaré con el **Workflow tool**: abanico de extracción
en paralelo sobre las fuentes nuevas, y después una pasada de **verificación adversarial**
sobre cada bypass del cheatsheet antes de admitirlo — el mismo patrón que ya detectó seis
contradicciones internas en las fuentes primarias de la Fase 6.

Convenciones que se mantienen: `# [derivado]` para lo razonado, `confianza: alta/media`
con el caveat declarado en el propio fichero, y nada reconstruido desde imágenes.

---

## 6 — NOTA DE ALCANCE

Un cheatsheet de evasión de WAF es material de doble uso, igual que los 96 writeups que ya
contiene el repo. Se construye con la misma disciplina: **WAF nombrado con versión o fecha,
payload literal, y la remediación defensiva en cada entrada** — que es precisamente lo que
un defensor necesita para configurar reglas. Pensado para pruebas autorizadas, como declara
el README. Sin cambios respecto a lo ya aceptado.

## 7 — Los marcadores de cita de tu prompt

Tu prompt lleva marcadores tipo `[9†L5-L32]`, `[7†L4-L37]`, `[0†L10-L15]`. Vienen de otra
sesión o herramienta y **no puedo resolverlos**. Verifico las afirmaciones que acompañan de
forma independiente y te digo cuando no se sostienen — como ya pasó con los pagos de
*Cracking the lens*, donde mi propia premisa era falsa.

---
## 8 — DECISIONES DEL USUARIO (2026-11-02, Fase 7)

- **Skills:** subir a **7** añadiendo `waf-bypass-triage`. Rompe el techo de 6 del contrato
  en uno, por decisión explícita del usuario.
- **Push:** **seguir empujando** a `claude/quirky-feynman-s2jxet`. Anula el "NO hagas git
  push" del prompt; el usuario reconfirma el patrón ya establecido (3 commits en GitHub) y
  el contenedor sigue siendo efímero.
- **Techo de writeups:** **200**, no 120. Anula la cuota del propio prompt. Margen actual:
  96 → 200 = **104 writeups**.

## 9 — WAFFLED: VERIFICADO, con DOS correcciones a la premisa del prompt

Paper confirmado: *WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application
Firewalls* — Akhavani, Jabiyev, Kallus, Topcuoglu, Bratus, Kirda. ACSAC 2025, pp. 689-702.
DOI 10.1109/ACSAC67867.2025.00062. CC BY 4.0. v1 2025-03-13, v4 2026-03-13.

### Corrección 1 — los 1207 bypasses NO están publicados
Cita literal de la sección 9: *"Sensitive bypass requests will remain restricted until the
vulnerabilities are resolved."* El prompt los trata como material disponible. No lo son.

Lo que **sí** publica: gramáticas del fuzzer, configuración de WAFs y HTTP-Normalizer, en
`github.com/sa-akhavani/waffled/`.

### Corrección 2 — AWS NO fue bypasseado. El paper se contradice con su abstract
- Abstract: *"1207 bypasses across 5 well-known WAFs, AWS, Azure, Cloud Armor, Cloudflare,
  and ModSecurity."*
- Tabla 1, columna "Bypassed": **`No` para Amazon AWS WAF**; `Yes` para los otros cuatro.
- Sección 7.4: *"Our findings, including the lack of successful bypasses against AWS WAF,
  validate this hypothesis."*
- La sección 9 de divulgación **omite AWS**.

Son **4** WAFs bypasseados, no 5. El cheatsheet lo dirá así.

### Lo que SÍ es usable, y es sustancial
**24 clases de bypass con un ejemplo literal cada una**: 12 multipart (Tabla 3), 7 XML
(Tabla 4), 5 JSON (Tabla 5). Más el Listing 4, con la continuación de boundary RFC 2231
(`boundary*0=real-;boundary*1=boundary`), y el Listing 3 con la petición multipart base.

### Otras incoherencias internas registradas
- **1207 aparece antes Y después de deduplicar.** Sección 6.1 lo da como "successful mutated
  requests" y como "unique bypasses found for (WAF, Framework) pairs". El paper no lo explica.
- **Conteo de frameworks inconsistente:** la sección 5.1 dice 6; la 5.3 y la Tabla 2 listan 7.
- **El "más del 90%" se apoya en ~50 sitios, no 100.** Sección 6.4: *"We chose the first 100
  search results... About half of these webpages were excluded."* La 3.2 dice "100 live websites".
- **Resultados fechados:** la Tabla 1 se encabeza *"As of July 2024."* Cloudflare *"stated
  that they are working on a fix"* y Azure estaba retirando CRS 3.0. La aplicabilidad actual
  a cualquier WAF concreto **no está establecida** y el cheatsheet lo dirá en cada entrada.
- Todos los payloads de ataque del paper usan **la misma cadena XSS de libro**: las
  mutaciones se aplican *"everywhere except the attack payload itself"*. Es decir, el paper
  aporta **envoltorios**, no payloads de ataque.

## 10 — ESTADO DE LAS FUENTES NUEVAS DEL PROMPT

| Fuente del prompt | Estado |
|---|---|
| WAFFLED (arXiv:2503.10846) | ✅ **Verificado.** 24 clases con ejemplo literal. Dos correcciones arriba. |
| X/Twitter (12 hunters) | ❌ **HTTP 402** en los tres perfiles probados. Inejecutable. |
| Decepticon WAF Bypass skill | ❌ **No localizable.** Ningún resultado menciona el nombre. |
| wafrift | ⚠️ Existe (dos repos homónimos, ninguno canónico). Solo taxonomía de nombres. |
| TBHM v5 | ⚠️ Sin v5. Sustituido por la **transcripción DEF CON 28** de Haddix, texto plano. |
| hackcert Advanced Tactics | ⏳ En verificación en el workflow de extracción. |
| Critical Thinking Podcast | ⚠️ Audio. Se buscan notas de episodio; sin transcripción esperada. |
