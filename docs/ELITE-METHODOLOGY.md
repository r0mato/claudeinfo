# ELITE-METHODOLOGY — Flujo de trabajo combinado, con cita por sección
**Fecha:** 2026-11-02 · Para **pruebas autorizadas**.

---

## 0 — CÓMO LEER ESTE DOCUMENTO

Un documento de metodología que presente a los mejores hunters como si estuvieran de
acuerdo no sirve de nada. **No lo están.** La tensión central de este documento es real y
está citada, no suavizada:

> **Jason Haddix** dedica una charla entera de DEF CON a construir un pipeline de recon
> amplio y lo automatiza en «un script de bash gigante y horrible».
>
> **NahamSec** escribe, con subrayado propio en el original: ***"I quit recon"***.

Las dos posturas vienen de hunters de primer nivel y **ninguna es un error**. La sección 1
explica qué resuelve cada una y cómo decidir en cuál estás. Ese juicio es la metodología;
la lista de herramientas es la parte fácil.

### Fiabilidad de las fuentes (gradada, porque no son iguales)

| Fuente | Tipo | Fiabilidad |
|---|---|---|
| **Jason Haddix**, TBHM 4.002, DEF CON 28 Safe Mode, Red Team Village (ago. 2020) | Transcripción **ASR** de audio | **Media.** Alta tasa de error en nombres propios. Todas las citas recompuestas uniendo subtítulos. Hueco de audio real de 26,4 s. **No citar palabra por palabra en público sin verificar contra el vídeo.** |
| **NahamSec** (Ben Sadeghipour), `nahamsec.com/posts` | Texto publicado por el autor | **Alta.** `<pre>` con saltos reales; el énfasis subrayado es suyo. |
| **rabhi** (nº1 histórico YesWeHack), entrevista YesWeHack 2025-09-16 | Texto editado | **Alta.** |
| **Chackal y Serizao**, YesWeHack 2024-03-13 | Texto editado | **Alta.** Traducción posiblemente del francés. |
| **Inti De Ceukelaire**, pentest-tools.com | **Transcripción de audio** | **Media.** Errores evidentes (*"using your might"* por *"mind"*, *"Intigrity"*). |
| **James Kettle**, PortSwigger Research (11 papers) | Investigación publicada | **Alta.** |
| **hackcert.com**, *Advanced Tactics for Bug Bounty Hunting* | Blog | **BAJA — NO ATRIBUIBLE. Ver aviso ⚠️ abajo.** |

### ⚠️ Aviso sobre hackcert.com

Esta fuente aparecía en el encargo original. **No es atribuible a una persona verificable** y
se usa aquí **solo como inventario de técnicas**, nunca como autoridad. Los indicios,
verificados en HTML crudo:

- La página del artículo declara `author = "Zainab Tariq Abbasi"` con fecha **6 abr. 2026**.
- El índice del blog firma **las 10 entradas de su primera página** con el mismo autor
  (`Rokibul Islam`) y **la misma fecha** (`25 may. 2026`). El nombre `Zainab` aparece **0
  veces** en el índice.
- El blog declara `Showing 1-10 of 389 entries`.
- Contiene una **atribución factual errónea**: asigna a Jack Cable el ATO de *Sign in with
  Apple*, que fue de **Bhavuk Jain** ($100.000, abril-mayo 2020).

389 artículos con metadatos idénticos y bylines que no concuerdan entre página e índice
apuntan a contenido generado en lote. **Las técnicas que lista son reales y comprobables por
separado; la autoría no.**

---

## 1 — RECON: la tensión Haddix ↔ NahamSec

### 1.1 La postura de Haddix: el recon es multiplicativo

Define el objetivo [06:02.700]:

> *"This is the art of finding as many assets related to a target as possible... the more
> websites you identify, or the more infrastructure you identify, the better your chances of
> getting in or finding a bounty."*

Y el mecanismo que lo justifica [24:11.210]:

> *"this idea of starting with seeds and then moving to subs really is going to multiply. The
> more seeds you find the more subdomain enumeration you can do. The more subdomains you find
> is related to how many sites you find. The more sites you find, the more successful you'll
> be."*

**Su orden literal de fases** [06:29.920]: dominios en alcance desde el brief → adquisiciones
→ enumeración de ASN → *reverse whois* → enumeración de subdominios → análisis de puertos →
escaneo de vulnerabilidades y automatización.

### 1.2 La postura de NahamSec: dejó el recon

> *"I jumped from program to program because I couldn't find anything interesting. I was
> continuously relying too much on automation and recon, until I realized that most of my
> bounties are coming from programs I spent extensive amounts of time understanding their core
> business... It officially pushed me to shift my mindset from **finding bugs through
> automation to looking at the core application** where they deploy new functionality every
> quarter. **I quit recon** and it helped me figure out a new framework that has allowed me to
> exceed my goals for this year."*

El **subrayado es del propio autor** en el HTML original, no añadido aquí.

Su argumento económico, en otro post:

> *"When hundreds or thousands of hunters use identical tools and methodologies, they're all
> discovering the same issues. It's like everyone following the same treasure map - the obvious
> spots will be picked clean."*

Y su redefinición de la palabra:

> *"Recon doesn't necessarily mean gathering subdomains and file/directory listing, it is also
> understanding what and how the application does what it's supposed to do."*

### 1.3 Cómo se resuelve la tensión (análisis propio, marcado como tal)

`# [derivado]` Las dos posturas responden a **preguntas distintas**:

- El recon amplio de Haddix resuelve **«¿dónde hay superficie que nadie ha mirado?»**. Escala
  con el tamaño del alcance y se automatiza bien.
- El rechazo de NahamSec resuelve **«¿por qué mis hallazgos son duplicados?»**. Escala con la
  profundidad del conocimiento de una aplicación y **no** se automatiza.

El indicador que decide en cuál estás es **la tasa de duplicados**. Si tus hallazgos son
duplicados, estás pisando el mapa del tesoro que todos siguen, y más recon empeora el
problema. Si no encuentras superficie que mirar, el recon es tu cuello de botella.

Y convergen en un punto, que es el consejo de **Chackal** ya recogido en
`docs/ELITE-MINDSET.md`: *"I like to stay on the same targets for a long, long time, which
allows me to find bugs that some people won't find because they haven't spent as much time on
the target."* El tiempo sobre un objetivo es un activo que la automatización no compra.

### 1.4 La frontera manual/automático, según Haddix

Su regla de diseño [12:58.840]:

> *"With every tool or method here in my methodology, I like to give you a manual way to do it
> because context is important and getting used to the idea is important. And I like to give
> you an automated way to do it in case you're going to script up your own recon framework."*

**Coste real de su pipeline automatizado** [57:50.860]:

> *"The conglomeration of tools and techniques we've already talked about takes anywhere
> between 5 and 15 minutes, maybe a little bit more if I have a lot of subdomains or it's a big
> project."*

**Los tres puntos donde exige verificación manual, citados:**

1. **Atribución por ASN** [13:58.860]: *"since you're using a keyword here to search, that you
   don't get other IP ranges that are not your targets. You'll have to verify somewhat manually
   there."*
2. **Dominios relacionados por analítica/publicidad** [21:01.860]: *"you'll have to manually
   kind of verify these but the ones I would look at first are the ones that actually have Uber
   in the domain somewhere."*
3. **Priorización visual** — la sección 1.6.

**Y lo que hace a mano mientras la automatización corre** [58:21.520]: *"I do a technique
called GitHub dorking and this has found me many, many great things."*

`# [derivado]` La frontera que traza **no** es "manual bueno, automático malo". Es: automatiza
la recolección en bulk; reserva lo manual para aprender el concepto la primera vez,
desambiguar **propiedad** de un activo, y **priorizar**. Y rellena los tiempos muertos de la
automatización con trabajo manual.

### 1.5 Precondición que Haddix pone ANTES de cualquier herramienta

Esta es la parte de su charla que más se ignora, y la pone primero [02:21.180]:

> *"you have to have a way that jives with you to record your work. Otherwise, you're just
> throwing darts and forgetting what you're doing."*

> *"Recon is the art of finding as many assets as possible related to a target, and it can get
> pretty data-heavy and dense as you do it. So having a way that works for you to track your
> data is the first thing that's going to guide you to success."*

Su sistema concreto, con código de colores [05:30.280]:

> *"everything that is not filled in hasn't been worked on yet... everything in orange means
> I'm currently working on something, and everything in green... I've already done... so I can
> easily put down a project and pick it back up if I want."*

El criterio de diseño es **poder soltar un proyecto y retomarlo**. Encaja con el principio 15
de `ELITE-MINDSET.md` (Inti De Ceukelaire): los escenarios que fallaron son inventario.

### 1.6 Priorización: screenshots

El mecanismo [01:01:26.100]:

> *"I feed it a list of domains. It will take those domains, visit them with the headless
> browser, take a screenshot of the page, and then I will just look at that folder and see,
> okay, which one of these looks like I want to prioritize first? Does it look like it
> redirects to the main site? Well, obviously, I'm not looking for the main site right now.
> It's some kind of back-end admin portal. Okay, I want to prioritize that."*

**Dos heurísticas de priorización más, citadas:**

**Antigüedad** [22:02.010]: *"the more stuff you find that goes back farther in age, the more
likely it is to be vulnerable and less likely to have a lot of security assessment associated
to it."*

**Shadow IT en cloud** [44:29.300]: *"A lot of people are putting shadow IT infrastructure and
registering websites on a credit card or just not paying attention or thinking that anybody
will find their cloud infrastructure... it's been a big part of my research lately is scanning
the cloud ranges and just finding wickedly undersecured stuff because people just don't think
you'll ever find it."*

### 1.7 El recon es un BUCLE, no un pipeline

Ejemplo literal de reentrada [37:26.140]:

> *"there was a whole ASN related to the company I didn't know about that I found out because
> Amass built this table... And then I look at that and I'm like, oh, I wasn't initially looking
> at those ranges. Weird. **Let's go back to the beginning of my workflow** and start enumerating
> those ranges."*

### 1.8 La primera prioridad real: leer el alcance

Antes de cualquier herramienta [10:35.680]:

> *"some of these are explicitly out of scope. So they'll say in the brief, especially for
> Tesla, SolarCity is not in scope of their wide scope bounty... So remember to refer to your
> project page or understand what is okay and what is not okay to hack or do recon on."*

⚠️ **Error en la fuente:** en esa misma frase atribuye SolarCity como adquisición de *Twitch*;
SolarCity es de **Tesla**. El principio es válido, el ejemplo está confundido.

Converge con **Chackal**: *"I start by reading the description very scrupulously, because I know
that many people sometimes go over it quickly."*

---

## 2 — ATAQUE: qué priorizar y cómo encadenar

### 2.1 Entender el negocio antes que la superficie

**NahamSec**, sobre selección de programa:

> *"The most consistent hunters I know focus on programs where they're already power users...
> if you use a platform every day, you understand all its features, quirks, and intended
> behaviors. That knowledge becomes your advantage. If you're interested in a program you don't
> currently use, that's fine, but you need to commit to becoming an expert. For example, if
> you're going to hack on Airbnb, you should understand everything about being a host - how
> listing management works, what automation features are available, how payments flow, every
> single setting and option in a host's dashboard."*

Converge con **Inti De Ceukelaire** (`ELITE-MINDSET.md` §7): *"I try to get in the heads of the
developer... what are the things that they may try to cut corners on because it's not super
relevant to their business?"*

### 2.2 Dos consejos de NahamSec que contradicen la práctica habitual

**Sobre SSRF — el consejo operativo más concreto del conjunto:**

> *"And one critical tip: Stop using Burp Collaborator or Interact for SSRF testing. Companies
> are blocking these services. If you're serious about SSRF in 2025, set up your own interact.sh
> server. That's the difference between landing an SSRF bounty and missing out."*

> *"SSRF is a gold mine. 25% of my total bug bounty earnings last year came from SSRF alone—but
> I'm not talking about basic localhost or metadata tricks."*

Esto tiene consecuencia directa sobre `skills/ssrf-escalation/SKILL.md`: si el colaborador
estándar está bloqueado, el paso 1 de esa skill —confirmar la salida— da un falso negativo.

**Sobre no rendirse en la primera iteración:**

> *"But here's the problem: Most hackers just try `../../../` a few times and give up."*

> *"Don't just throw polyglot payloads at every input—try this instead:"*

**Y sobre reproducir el entorno:**

> *"Make sure you recreate and test the application backend locally or on a staging environment
> with the same configuration as the target by looking into the user agent."*

### 2.3 Un flujo de recon de ataque real, citado

De su writeup de Snapchat ($5.000, Jenkins), los pasos tal como los titula:

> *"Step #1 – Brute forcing for subdomains... unfortunately for me the subdomains I had found
> weren't really interesting and wanted to find something more "fun". Moving on to phase 2."*

> *"Step #3 – Snapchat's disclosed reports on HackerOne. As a part of my recon, I typically like
> to look for known or disclosed vulnerabilities. I took a quick glance at their Hacktivity."*

> *"First reaction was to do a subdomain brute force, but who are we kidding.. These are
> corp/cdn domains and more than likely most of the juicy sub domains would more than likely be
> in a unique pattern."*

> *"Step #4: Censys/Shodan... My usual go-to query on censys looks similar to something like
> this: `443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names:domain.com`"*

**Leer la *hacktivity* del programa es recon.** Los reportes divulgados dicen qué clases ya
pagaron y qué partes de la aplicación tienen historial.

### 2.4 Cuándo NO reportar

> *"Don't spam programs with "publicly accessible Jenkins" reports unless you can possibly
> exploit one or more of the above examples."*

> *"Don't let it scare you away if it requires authentication via Github or Google OAuth."*

El par es instructivo: **no reportes la mera exposición sin impacto, pero no descartes un
objetivo por tener autenticación.** Conecta con el principio 10 de `ELITE-MINDSET.md`: el
impacto necesita un escenario de ataque, no una ejecución.

### 2.5 Encadenamiento

**Kettle** aporta el método general (`ELITE-MINDSET.md` §6, §19): predecir colisiones con tres
preguntas, establecer línea base, y buscar la desviación. Y la heurística que vertebra
`ELITE-CHEATSHEET-BYPASS.md`: buscar los puntos donde **dos componentes leen el mismo dato**.

`# [derivado]` El patrón de encadenamiento que aparece una y otra vez en los 96 writeups del
repo tiene **dos mitades que hay que buscar por separado**:

1. Una **condición**: un token varado, una discrepancia de parser, un sub-estado.
2. Un **gadget**: algo que lea, ejecute o entregue lo que la condición dejó accesible.

La investigación de OAuth de Frans Rosén es el caso canónico: romper el baile deja el token en
la URL, y hace falta un gadget que lo lea. Reportar la mitad como si fuera el todo es el error
de triaje más común.

---

## 3 — REPORTE: escribir para que paguen

### 3.1 La comunicación es parte del resultado

**rabhi**, nº1 histórico de YesWeHack:

> *"The way you write reports and interact with program managers can make all the difference.
> Good communication can strengthen your relationships and increase your opportunities."*

> *"Soft skills are often underestimated, but they are essential in Bug Bounty."*

### 3.2 El control negativo es parte del informe

`# [derivado]` — es la lección más repetida de los 96 writeups del repo, y conviene decirla
como regla de redacción:

**Un informe con un solo payload que funciona es más débil que uno con el par A/B.** El
control negativo demuestra que el control de seguridad **existía y funcionaba**, lo que
convierte el hallazgo en un *bypass* en lugar de una *omisión trivial*.

Ejemplos concretos del repo donde el par cambia la severidad reportable:

| Sin control negativo se lee como… | Con el par A/B es… |
|---|---|
| "la ruta `/admin.php` era pública" | **bypass de ACL**: `/admin.php` da 401, `/admin.php%3Fooo.php` da la página |
| "falta escapado de salida" | **fallo de orden de operaciones**: el carácter crudo *sí* se escapa; el Punycode lo esquiva |
| "la introspección de GraphQL está abierta" | **filtro textual esquivable**: la forma pegada se rechaza, la espaciada pasa |
| "hay inyección CRLF" | **RCE**: el `Content-Type` es un selector de módulo de Apache |

Y el caso límite, de `writeups/cache/`: **pedir el recurso sin la cabecera, después de
enviarla**, es lo que separa "la aplicación refleja una cabecera" (impacto bajo) de "la caché
sirve mi contenido a todos" (crítico). Son órdenes de magnitud y cuesta una petición.

Los autores de WAFFLED lo convierten en instrucción para quien prueba un WAF: *"make sure that
these attack payloads are detected by the WAF when sent in a normal request."*

### 3.3 Completar la frase de impacto

De **Inti De Ceukelaire** (`ELITE-MINDSET.md` §10), sobre sus primeros intentos: *"if I can
only execute cross-site scripting payload for myself and not for somebody else, that won't be
valid"*, y su conclusión: *"a lot of my initial findings were invalid."*

`# [derivado]` La regla operativa: antes de enviar, completar **"un atacante *quién* consigue
*qué* sobre *quién*, haciendo que la víctima *qué*"**. Si no se puede completar, no hay informe
todavía.

### 3.4 Clasificar bien, aunque baje la severidad

`# [derivado]` Tres casos reales del repo donde la clasificación correcta importa más que la
alta:

- Un desync confirmado en un objetivo de **poco tráfico** es el mismo fallo sin ventana
  práctica. Se reporta por la **discrepancia de parser**, no por la explotación lograda (la
  fuente avisa de que el RQP contra GitLab necesitó ~27.000 peticiones).
- Una URL administrativa filtrada que **sí** devuelve 403 es revelación de información, no
  bypass de control de acceso.
- Un `postMessage` con `'*'` sobre un mensaje **sin datos sensibles** es mala práctica, no fuga.

Inflar los tres cuesta credibilidad y no gana dinero.

### 3.5 Estructura de reporte: inventario de la fuente no atribuible

De hackcert.com, **como inventario, no como autoridad** (ver aviso en §0): el artículo
estructura el reporte y nombra un pipeline de recon. Las técnicas que lista son comprobables
por separado; la autoría no lo es. **No se cita aquí como fuente de principio.**

---

## 4 — PRINCIPIOS DE DECISIÓN

### 4.1 Cuándo parar — y qué NO dice Haddix

⚠️ **Corrección a una creencia extendida:** la charla de Haddix **no dice nada** sobre abandonar
un objetivo. Verificado por búsqueda insensible a mayúsculas de `give up|gave up|move on|
abandon|not worth|waste|walk away|bail|dead end|stop looking|drop it`: **cero coincidencias**.
Quien le atribuya un criterio de abandono está inventando.

Lo que sí da son **dos criterios de parada de una técnica**, no de un objetivo:

1. **Agotamiento del spidering** [28:33.130]: *"this until you get kind of spider fatigue"*.
2. **Agotamiento de una fuente** [35:12.760]: *"keep on minusing out domains until Google
   doesn't know anything more about subdomains related to twitch.tv. And that way, we can
   basically get a full inventory of what Google knows."*

La distinción importa: **agotar una técnica no es agotar un objetivo.**

### 4.2 Lo contrario: la persistencia, citada

**rabhi**: *"you should trust your intuition and never give up. I've sometimes found
vulnerabilities after days, even weeks, of painstaking research."*

**Chackal**: *"without passion it would be impossible to stay on these targets for so long."*

### 4.3 Ritmo sostenible

**rabhi**: *"I devote at least two hours a day to Bug Bounty. This keeps me efficient and
responsive, particularly when invitations are extended to new programs."* — Lo vincula a
**eficacia**, no a volumen.

**Inti De Ceukelaire**: *"if you're hacking 100% of your time, you run out of ideas"*, *"when
you're bored, when you don't know what to do, typically you come up with the best solutions"*,
*"People should be more bored often."*

### 4.4 La tasa de duplicados como señal de pivote

`# [derivado]`, derivado de NahamSec: **los duplicados no son mala suerte, son un diagnóstico.**
Significan que estás en la ruta que todos recorren. La respuesta no es más herramientas: es
cambiar de régimen (§1.3).

### 4.5 Criterio económico de selección de programa

**NahamSec**, explícito:

> *"Find a program that pays either: Average of $500 per valid vulnerability [or] The medium
> severity vulnerability will receive a minimum bounty of $500."*

> *"Programs that pay $500 for Mediums will have much more attractive bounties for Highs and
> Criticals."*

> *"The main challenge here is to pick a program, stick to it, and not jump from one program to
> another because you aren't having any immediate success."*

> *"Find a large scope program in a big industry (finance, music, retail, etc): a company that
> has multiple services that you could login to with your account."*

Converge con **Chackal**: *"you need to find a program with a huge number of features, so that
you can stay on it as long as possible."*

### 4.6 Especializar, pero volver

**rabhi**: *"Specialise in a specific area too, such as web, mobile or reverse engineering."*
**Inti**: *"a lot of people only go through one cycle."* Especializarse no es llegar y quedarse.

---

## 5 — LO QUE NO SE PUDO CITAR

Registrado para que nadie rellene estos huecos con material inventado:

| Hueco | Por qué |
|---|---|
| **Hilos de X/Twitter** de los 12 hunters del encargo | `HTTP 402 Payment Required` en los tres perfiles probados. **Inalcanzable.** |
| **Sintaxis de comandos de Haddix** | Las pronuncia en palabras (*"with the dash brute option"*); la sintaxis real estaba en las diapositivas, que son imágenes y no están en la transcripción. **No se reconstruye ninguna invocación.** |
| **Enfoque de XSS ciego de NahamSec** | La palabra "blind" aparece **una sola vez** en todo su sitio sobre XSS, y no da payload ni nombra recolector. |
| **"Modelo de madurez" de recon** | No existe. Haddix presenta *tier lists* de builds de videojuego (C/B/A/S, analogía con Diablo) y las desautoriza dos veces: *"These classifications are not in any way super serious"*. Y clasifica **sus propias herramientas como C tier**. |
| **Criterio de abandono de objetivo** | No existe en la fuente (§4.1). |
| **TBHM v5** | Sin fuente primaria localizable. Lo citado es **4.002**, de agosto de 2020. |
| **Transcripción de Critical Thinking Podcast** | Es audio. Solo notas de episodio. |

---

## 6 — FUENTES

| Fuente | URL | Fecha |
|---|---|---|
| Haddix, TBHM 4.002 — DEF CON 28 Safe Mode, Red Team Village | `media.defcon.org/DEF CON 28/.../the bug hunters methodology-jason haddix.eng.txt` | ago. 2020 |
| NahamSec — 8 posts | `nahamsec.com/posts` | 2018-2025 |
| rabhi — *The rabhi route to root* | `yeswehack.com/community/rabhi-root-bug-bounty-blueprint` | 2025-09-16 |
| Chackal y Serizao | `yeswehack.com/community/bug-bounty-targets-chackal-serizao` | 2024-03-13 |
| Inti De Ceukelaire | `pentest-tools.com/blog/we-think-we-know-inti-de-ceukelaire` | act. 2024-02-28 |
| James Kettle — 11 papers | `portswigger.net/research` | 2017-2025 |
| WAFFLED | `arxiv.org/abs/2503.10846` · `github.com/sa-akhavani/waffled` | 2025-2026 |
| hackcert.com | `hackcert.com/blog/bug-bounty-hunting` | ⚠️ **no atribuible** |

Inventario completo: `docs/ELITE-SOURCES.md`. Rechazos: `_refactor/ELITE-REJECTED.md`.
