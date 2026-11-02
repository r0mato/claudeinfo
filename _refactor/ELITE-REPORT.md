# ELITE-REPORT — Informe final
**Fecha:** 2026-11-02 · **Repo:** `r0mato/claudeinfo` · **Rama:** `claude/quirky-feynman-s2jxet`
**Estado inicial:** repo vacío, 0 commits, sin estructura.

---

## 1 — Resumen

| Capa | Producido | Techo del contrato |
|---|---|---|
| Writeups | **56** | 120 |
| Skills | **6** | 6 |
| Principios de mindset | **20** | 10-15 (superado) |
| Fuentes consultadas | **13 documentos** de 5 dominios Tier 1/2 | — |

Quedé en 56 de 120 writeups **por decisión, no por falta de tiempo**. El contrato dice
"mejor 30 de élite que 300 mediocres" y es la regla que apliqué: cerré cada clase cuando
agoté los *principios distintos* de sus fuentes, en lugar de generar variantes
casi idénticas para subir el número. El fichero `ELITE-REJECTED.md` documenta 40+
candidatos descartados, que es la otra mitad del trabajo.

## 2 — Writeups por clase

| Clase | Creados | Cuota del plan | Nota |
|---|---|---|---|
| `auth` | 17 | 16 | ✅ superada. 7 JWT + 5 parsers de correo + 5 OAuth |
| `xss` | 9 | 20 | ⚠️ cerrada en 9: agoté los principios distintos del cheat sheet |
| `inyeccion` | 9 | 18 | ⚠️ 6 SQLi + 3 argument injection. SSTI cayó entera (fuente sin payloads) |
| `idor` | 4 | 10 | ⚠️ material docente sin objetivo real; ver §5 |
| `info-disclosure` | 4 | 12 | ⚠️ XS-Leaks agotado; varias técnicas sin código en la fuente |
| `protocolo` | 4 | 14 | ⚠️ regla H2 descartó los casos con vendor sin nombrar |
| `race` | 4 | 8 | ⚠️ 4 de 9 casos de la fuente tenían objetivo real nombrado |
| `ssrf` | 3 | 12 | ⚠️ el cheat sheet de OWASP es preventivo, no ofensivo |
| `logica-negocio` | 2 | 10 | ⚠️ 4 de 6 clases de la fuente no tienen un solo payload |

**Lectura honesta de las cuotas incumplidas:** no son un fallo de esfuerzo sino un
hallazgo sobre las fuentes. Los cheat sheets de OWASP y las páginas de la Web Security
Academy son material **defensivo y docente**: tienen técnica, no casos. Las cuotas altas
que fijé en la Fase 0 suponían que rendirían como la investigación original de
PortSwigger, y no lo hacen. Para llenar `ssrf`, `idor` y `logica-negocio` hace falta otra
clase de fuente: reportes divulgados de HackerOne con ID verificable.

## 3 — Skills creadas (6/6, todas ≤200 líneas)

| Skill | Líneas | Señal citada |
|---|---|---|
| `desync-triage` | 146 | Kettle, "HTTP/1.1 must die" (2025) |
| `xss-sink-triage` | 143 | PortSwigger XSS cheat sheet |
| `jwt-attack-tree` | 142 | PortSwigger JWT + algorithm confusion |
| `oauth-flow-audit` | 152 | Rosén, "dirty dancing" (2022) + borrador IETF |
| `ssrf-escalation` | 149 | OWASP SSRF ("treat parser disagreement as a rejection") |
| `race-window` | 152 | Kettle, "Smashing the state machine" (2023) |

**Desviación del plan:** sustituí `idor-at-scale` por `jwt-attack-tree`. Razón: JWT
acumuló 7 writeups con payloads literales y un árbol de coste claro, mientras que el
material de IDOR dio 4 writeups sin objetivo real y no sostenía una skill con señal
citada. Preferí 6 skills con base documental a 6 que cubrieran el plan.

## 4 — Validación (Fase 4)

Todo ejecutado y pasado:

- **Frontmatter:** los **12** campos del contrato presentes en los 56 writeups
  (verifiqué los 12, no solo `clase` y `payload` como pedía el script del prompt).
- **Placeholders prohibidos:** `grep -rlE "YOUR-LAB-ID|<target>|REDACTED"` → **vacío**.
  (Nota: el grep del prompt sin `-E` trata el `|` como literal y nunca habría
  coincidido; lo corregí.)
- **Skills ≤200 líneas:** 6/6, máximo 152.
- **Bloques obligatorios de skill:** 6/6 con frontmatter completo, `0 — SEÑAL CITADA`,
  "Cuándo esta skill NO es la correcta", "Trampas de falso positivo" y output en
  `evidencias/`.
- **`description` ≤200 chars:** 6/6, máximo 169.
- **Referencias cruzadas `skill:*`:** encontré 1 rota (`skill:idor`) y la corregí.
  Las 6 restantes resuelven a skills existentes.

## 5 — Decisiones de criterio que cambiaron el resultado

Cuatro juicios que conviene que revises, porque alteran qué entró:

1. **Redacción con vendor nombrado (acordado contigo).** Acepté los casos de PortSwigger
   donde el host está redactado pero el vendor aparece en prosa, usando el host literal
   cuando el artículo lo da (`auth.lastpass.com`, `h1.sec.gitlab.net`, `app.netlify.com`).
   Sin esto, `protocolo` se habría quedado en 0.
2. **IDOR: solo lo atado a algo concreto.** Acepté los writeups ligados a un producto,
   cabecera o versión (`X-Original-URL`, Spring <5.3, `Referer`) y rechacé el
   `?customer_number=132355` genérico. Es una línea discutible y la declaro.
3. **Campos derivados marcados.** El contrato exige `control_negativo`, que casi ninguna
   fuente publica. Lo diseñé yo y marqué cada línea con `# [derivado]`, igual que las
   remediaciones inferidas y los CVSS estimados. Nunca verás un campo razonado
   presentado como citado.
4. **No reconstruí payloads image-only.** Los vectores finales de GitHub, Zendesk,
   GitLab y Joomla solo existen en capturas. Reproducir "a ojo" una dirección de correo
   que depende de cada `=00` habría producido lo más peligroso para este catálogo: un
   payload inventado con apariencia de literal.

## 6 — Hallazgo técnico sobre las fuentes (H1), y cómo lo gestioné

La conversión HTML→texto **colapsa los saltos de línea dentro de los bloques de código**.
Para los payloads de una línea (XSS, SQLi, URLs, direcciones de correo) es inocuo. Para
los multi-línea dependientes de CRLF —desync HTTP— significa que no tengo los bytes
exactos.

Qué hice: los 4 writeups de `protocolo` y los de `race` con pares de peticiones llevan
una **nota de procedencia explícita** indicando que la estructura por líneas está
reconstruida desde la sintaxis de cabeceras, y van como `confianza: media`. Además es una
de las tres trampas de falso positivo de `skill:desync-triage`.

Reconstruir en silencio habría sido más cómodo y habría producido un catálogo que falla
en producción sin explicar por qué.

## 7 — Distribución de confianza

| `confianza` | Writeups | Qué significa |
|---|---|---|
| `alta` | 32 | payload literal verificado, objetivo o producto nombrado |
| `media` | 24 | CRLF reconstruido, host redactado con vendor nombrado, o payload parcial declarado |
| `baja` | 0 | nada llegó a guardarse con confianza baja: se rechazó |

(Cifras contadas con `grep -rl "^confianza: X" writeups/`, no estimadas.)

## 8 — Qué haría a continuación

1. **Reportes divulgados de HackerOne con ID verificable** — es lo único que llena
   `idor`, `logica-negocio` y `ssrf` cumpliendo el criterio de objetivo real.
2. **SSTI desde PortSwigger** en lugar de OWASP, que no tiene payloads.
3. **El PDF de `splitting-the-email-atom`** por otra vía, para verificar el número exacto
   de barras invertidas y subir esos 5 writeups de `media` a `alta`.
4. **Verificar `oncuechange`** contra la fuente: es el único vector de XSS cuyos bytes no
   puedo garantizar (espacios frente a `%0A` en el `data:` URI de WebVTT).
