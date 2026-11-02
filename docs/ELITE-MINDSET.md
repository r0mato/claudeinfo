# ELITE-MINDSET — Principios de caza con fuente atribuible
**Fecha:** 2026-11-02
**Regla de admisión:** cada principio tiene (1) fuente identificable, (2) cita literal o
procedencia marcada, (3) aplicación accionable. Los principios genéricos ("sé curioso")
quedan fuera por contrato.

**Nota de procedencia general.** Las citas de rabhi, Chackal y Serizao vienen de
artículos de texto y son fiables al nivel de palabra. Las de Inti De Ceukelaire vienen
de una **transcripción de audio** que contiene errores evidentes (la propia página
escribe "using your might" donde el título dice "mind", y "Intigrity" por "Intigriti").
Las marco con `[sic]` donde procede y advierto de que conviene verificar contra el audio
antes de citarlas palabra por palabra en un informe público.

---

## 1 — La metodología es la ventaja, no el conjunto de habilidades

> "If there was one secret, it would be methodology. More than a set of skills, it's this
> ability to structure and perfect your research that will take you far."
> — **rabhi**, hunter nº1 histórico de YesWeHack

**Por qué importa:** la pregunta que se le hizo era sobre *habilidades técnicas*. Contestó
con metodología. El nº1 de una plataforma entera atribuye su posición a la capacidad de
estructurar la investigación, no a saber más.

**Aplicación:** cuando una sesión no produce nada, la pregunta correcta no es "¿qué
técnica me falta?" sino "¿qué parte de mi proceso no es repetible?". Las `skills/` de
este repo son el intento de hacer la metodología explícita y auditable.

**Fuente:** https://www.yeswehack.com/community/rabhi-root-bug-bounty-blueprint (2025-09-16)

---

## 2 — No pruebes el campo evidente; prueba lo que nadie mira

> "For example, on a search page, most bug hunters reflexively test the search field
> directly, because it's the most visible and intuitive element."
> "But I prefer to explore less obvious parameters, such as elements hidden in
> JavaScript. This 'off the beaten track' curiosity often leads to the discovery of
> unique flaws."
> — **rabhi**

**Por qué importa:** es un argumento de **economía**, no de técnica. El campo de búsqueda
ya ha sido probado por todos los que llegaron antes, así que su valor esperado es casi
cero por saturación, no por estar bien protegido. Un parámetro escondido en JS tiene el
valor esperado íntegro.

**Aplicación:** ante un objetivo nuevo, invertir el orden natural. Enumerar primero los
parámetros que no aparecen en la interfaz (bundles de JS, source maps, endpoints de API
sin UI) y dejar los campos visibles para el final.

**Convergencia:** Serizao describe exactamente la misma práctica desde otro ángulo:
> "I search in the JavaScript and in the JavaScript files, looking for new parameters,
> new endpoints… something to build on what I initially saw of interest in the
> application."

**Fuentes:** rabhi (enlace arriba); Serizao en
https://www.yeswehack.com/community/bug-bounty-targets-chackal-serizao (2024-03-13)

---

## 3 — El tiempo sobre el objetivo es un foso defensivo

> "I'd define myself as patient and persistent because I like to stay on the same targets
> for a long, long time, which allows me to find bugs that some people won't find because
> they haven't spent as much time on the target."
> — **Chackal**

**Por qué importa:** nombra el mecanismo, no la virtud. La ventaja no es "ser paciente":
es que el conocimiento acumulado de una aplicación concreta es un activo que los demás no
tienen y no pueden comprar. Y es acumulativo, mientras que rotar de objetivo reinicia el
contador.

**Aplicación:** medir la permanencia en un objetivo como una inversión y no como un coste
hundido. Contrasta con el consejo habitual de rotar cuando bajan los retornos — y la
contradicción es real, no aparente: conviene decidir deliberadamente en qué régimen se
está trabajando.

**Fuente:** Chackal, enlace en el principio 2.

---

## 4 — Elige programas por superficie funcional, no por frescura

> "you need to find a program with a huge number of features, so that you can stay on it
> as long as possible and get to know the application well."
> — **Chackal** (como consejo a quien empieza)

**Por qué importa:** es el criterio de selección que hace viable el principio 3. Un
objetivo pequeño se agota; uno con mucha funcionalidad admite años de permanencia
productiva.

**Aplicación:** al valorar un programa, contar funcionalidades y flujos distintos antes de
mirar el rango de recompensas. Un programa con pagos modestos y cien flujos puede rendir
más, sostenidamente, que uno generoso con tres.

**Fuente:** Chackal, enlace en el principio 2.

---

## 5 — Lee la descripción del programa con cuidado, porque casi nadie lo hace

> "I start by reading the description very scrupulously, because I know that many people
> sometimes go over it quickly – despite the fact you can learn a lot, especially if
> there's a link to the application documentation."
> — **Chackal**

**Por qué importa:** señala una ventaja asimétrica gratuita. Si la mayoría pasa por encima
de la documentación, leerla es una ventaja que cuesta una hora y no requiere ninguna
habilidad.

**Aplicación:** leer la documentación de la aplicación antes de tocarla, y buscar
explícitamente las funciones documentadas que **no** son obvias en la interfaz.

**Fuente:** Chackal, enlace en el principio 2.

---

## 6 — Entiende la aplicación para reconocer lo que es anormal

> "as I'm very focused on vulnerabilities relating to access control, I try to understand
> the application as much as possible, so that I can spot any behaviour that isn't normal
> and could lead to a security problem."
> — **Chackal**

**Por qué importa:** convierte el conocimiento del dominio en un **detector**. No se puede
reconocer una anomalía sin un modelo de lo normal, y ese modelo es precisamente lo que no
tiene un escáner.

**Convergencia con la investigación técnica.** James Kettle llega a lo mismo desde el lado
de las condiciones de carrera:
> "Over time I've begun to regard spotting anomalies as the single most important skill
> for finding race conditions."

Y lo convierte en procedimiento obligatorio:
> "Clues can be subtle and counterintuitive so if you skip the benchmark step, you'll
> miss vulnerabilities."

**Aplicación:** antes de atacar, establecer la línea base. Es exactamente el campo
`control_negativo` de cada writeup de este repo: sin una referencia de lo normal, una
desviación no es información.

**Fuentes:** Chackal (enlace en el principio 2);
https://portswigger.net/research/smashing-the-state-machine (James Kettle, 2023-08-09)

---

## 7 — Piensa como el desarrollador: busca dónde se recortan esquinas

> "I try to get in the heads of the developer."
> "what are the things that they may try to cut corners on because it's not super
> relevant to their business?"
> "it kind of becomes this inheritance that needs to be there, but nobody really likes to
> maintain. That is what I look for."
> — **Inti De Ceukelaire** (transcripción de audio; ver nota de procedencia)

**Por qué importa:** es un modelo predictivo de dónde están los fallos. No los busca por
tecnología sino por **desinterés organizativo**: lo que existe por obligación y nadie
quiere mantener.

**Aplicación:** inventariar lo que el objetivo mantiene sin ganas — funciones heredadas,
integraciones antiguas, cumplimiento normativo, flujos que la empresa no monetiza. Dar
prioridad a eso sobre el producto estrella.

**Fuente:** https://pentest-tools.com/blog/we-think-we-know-inti-de-ceukelaire
(página marcada "Updated at February 28, 2024")

---

## 8 — Pregunta al cliente dónde buscaría él

> "Whenever I arrive at a live hacking event, the first thing I do is to talk to the
> client and ask them where would you look for a vulnerability?"
> "I would say nine out of ten in the exact area that they point to, I do find a
> vulnerability."
> — **Inti De Ceukelaire**

**Por qué importa:** nueve de diez es una tasa de acierto que ninguna técnica de recon
alcanza, y el coste es una conversación. Funciona porque el equipo interno ya sabe dónde
está incómodo: conoce la deuda técnica que no ha podido pagar.

**Aplicación:** en un evento o en una relación directa, preguntar antes de escanear. Sin
acceso al equipo, el equivalente son las fuentes públicas donde esa incomodidad se
filtra: notas de versión, issues abiertos, mensajes de commit con disculpas, y ofertas de
empleo (principio 9).

**Fuente:** enlace en el principio 7.

---

## 9 — Las ofertas de empleo señalan dónde falta personal

> "typically people put out jobs to solve a problem."
> "where are they maybe understaffed because I will be the type of hacker that will take
> advantage of that"
> — **Inti De Ceukelaire**

**Por qué importa:** es inteligencia pública sobre debilidad interna. Una oferta de empleo
es la empresa declarando qué no puede cubrir ahora mismo, y además nombra sus tecnologías.

**Aplicación:** leer las ofertas de seguridad e ingeniería del objetivo. Una vacante de
seguridad sin cubrir en un área concreta indica que ese área está sin revisar. Las
tecnologías que se piden en el anuncio son el stack real, mejor que cualquier
fingerprinting.

**Fuente:** enlace en el principio 7.

---

## 10 — El impacto necesita un escenario de ataque, no una ejecución

> "I need an attack scenario and Google really allowed me to think like an attacker."
> "if I can only execute cross-site scripting payload for myself and not for somebody
> else, that won't be valid."
> — **Inti De Ceukelaire**, sobre sus primeros intentos a los 16 años

Y su propia conclusión sobre aquella etapa: *"a lot of my initial findings were invalid."*

**Por qué importa:** separa "conseguí que se ejecute" de "alguien resulta perjudicado".
Self-XSS ejecuta y no es vulnerabilidad. Es la lección que convierte un tirador de
payloads en un investigador.

**Aplicación:** antes de escribir un informe, completar la frase "un atacante **quién**
consigue **qué** sobre **quién**, haciendo que la víctima **qué**". Si no se puede
completar, no hay informe todavía. Es la razón de que cada writeup de este repo exija
`precondicion` y un apartado de `Impacto` por separado del payload.

**Fuente:** enlace en el principio 7.

---

## 11 — Persigue el dinero y las joyas de la corona

> "And then I try to go for the money scenario. Okay, how could I steal a lot of money
> from this company?"
> "What is some crucial data that maybe is not super clear to everybody, but what are
> their crown jewels?"
> "if that data doesn't relate to any other systems or is not used in a context where it
> actually super matters to the company ... it's not really worth a lot."
> — **Inti De Ceukelaire**

**Por qué importa:** da un criterio de priorización que no depende de la clase técnica.
Una SSRF que no lleva a nada vale menos que un fallo de lógica que mueve dinero.

**Aplicación:** empezar por el modelo de negocio y razonar hacia atrás hasta la
funcionalidad, en lugar de empezar por la superficie técnica y razonar hacia delante
hasta el impacto.

**Fuente:** enlace en el principio 7.

---

## 12 — Los bugs críticos no están en las zonas más miradas

> "typically these critical bugs are not in the most focused areas."
> — **Inti De Ceukelaire**

**Por qué importa:** es el principio 2 generalizado de los parámetros a las *áreas*. La
atención es un recurso que se agota: donde se concentró la revisión, los fallos ya se
encontraron.

**Aplicación:** mapear explícitamente dónde ha mirado todo el mundo (el flujo de login, el
de pago, el campo de búsqueda) y trabajar deliberadamente fuera de ahí.

**Fuente:** enlace en el principio 7.

---

## 13 — Limita el alcance a propósito, sobre todo si es enorme

> "challenge yourself to limit the scope."
> "Everybody loves bug bounty scopes that are extremely wide."
> — **Inti De Ceukelaire**

Y sobre la profundidad que eso permite: un pentester normal *"will only spend a couple of
minutes"*, mientras él dice *"I have to spend at least a full day on this"* para una única
función pequeña.

**Por qué importa:** contradice directamente el instinto de que un alcance amplio es mejor.
Un alcance amplio invita a la exploración superficial, que es el régimen donde las
herramientas automáticas ya ganaron.

**Aplicación:** sobre un alcance grande, elegir un subconjunto de funcionalidades y agotarlo
a profundidad de un día por función antes de ampliar. Encaja con los principios 3 y 4:
alcance estrecho, permanencia larga.

**Fuente:** enlace en el principio 7.

---

## 14 — Las herramientas son el 10%

> "hacking, in my opinion, is 80% to 90% using your might [sic; la página titula "mind"],
> and 10% using the tools or your actual computer keyboard."
> "But some people just expect by running a tool, you will get juicy bugs. No, you have to
> learn how to master that tool, but also when to use it or when to tweak it."
> "I do embrace automation because it can help us get rid of the iterative stuff, things
> that we have to do over and over and over again, and of the boring stuff."
> — **Inti De Ceukelaire**

**Por qué importa:** la postura no es anti-automatización, y ese matiz es lo valioso. La
automatización se queda con lo repetitivo; el juicio decide **cuándo** y **cómo** usarla.

**Aplicación:** automatizar lo que ya se entiende y se ha hecho a mano varias veces. No
automatizar lo que no se sabe interpretar: produce volumen sin señal.

**Nota:** rabhi, por su parte, **no menciona la automatización en ningún momento** de su
entrevista. Su única mención del recon es *"Reconnaissance is the foundation of any
successful test."* Que el nº1 histórico de una plataforma no hable de herramientas al
explicar su éxito es, en sí, un dato.

**Fuente:** enlace en el principio 7; rabhi, enlace en el principio 1.

---

## 15 — Guarda los escenarios que fallaron; son inventario

> "I try, even though if I don't find something, even though if I don't earn any good
> bounties, I still have my notes."
> "there's been many times when a particular attack scenario that I had in mind for a
> specific app didn't work out. I could just recycle that for the next opportunity."
> — **Inti De Ceukelaire**

**Por qué importa:** reencuadra una sesión sin hallazgos como producción de activos en vez
de tiempo perdido. Un escenario que no funcionó aquí es una hipótesis lista para el
siguiente objetivo.

**Aplicación:** es literalmente la razón de existir de `_refactor/ELITE-REJECTED.md` y del
campo `mata` de cada writeup: registrar lo que no funcionó, y **por qué**, para no repetir
el trabajo.

**Fuente:** enlace en el principio 7.

---

## 16 — El aburrimiento produce ideas; no cacéis el 100% del tiempo

> "if you're hacking 100% of your time, you run out of ideas."
> "Because when you're bored, when you don't know what to do, typically you come up with
> the best solutions."
> "People should be more bored often."
> "But it's so refreshing for your mind to just get out of the context and try to take a
> step back."
> — **Inti De Ceukelaire**

**Por qué importa:** trata el tiempo sin trabajar como parte del proceso y no como pérdida.
Es coherente con el principio 14: si el trabajo es mayoritariamente mental, la condición
mental es la condición del trabajo.

**Convergencia con rabhi**, que llega al mismo equilibrio desde la disciplina y no desde el
descanso:
> "And be disciplined. I devote at least two hours a day to Bug Bounty. This keeps me
> efficient and responsive, particularly when invitations are extended to new programs."

Nótese que vincula las dos horas a **eficacia y capacidad de respuesta**, no a volumen.
El nº1 histórico describe un ritmo sostenible, no maratones.

**Aplicación:** cadencia sostenible por encima de ráfagas. Y cuando se agoten las ideas,
tratarlo como señal de salir del contexto, no de insistir más fuerte.

**Fuentes:** enlaces en los principios 7 y 1.

---

## 17 — Explicar el problema en voz alta es parte de resolverlo

> "explaining something that you're struggling with in terms of technology to somebody
> else is sometimes really part of the solution."
> — **Inti De Ceukelaire**

> "it's not unusual for me to talk to [hacker and YesWeHack R&D engineer] BitK about
> certain bugs where I sometimes get stuck, in order to progress and achieve a successful
> exploitation. Sharing is caring!"
> — **Serizao**

> "I started Bug Bounty with a friend, and we spent every evening bug hunting together,
> but we couldn't come up with much because we didn't have a good methodology."
> — **Chackal**

**Por qué importa:** tres hunters independientes señalan la colaboración como mecanismo de
desbloqueo. La cita de Chackal añade el matiz que evita malinterpretarlo: la colaboración
**sin** metodología no bastó. Hacen falta las dos cosas.

**Aplicación:** cuando la explotación se atasca, escribir el problema para otra persona
—aunque no se envíe— fuerza la articulación que suele revelar la pieza que falta.

**Fuentes:** enlaces en los principios 7 y 2.

---

## 18 — Nadie publica sus fracasos; define tú qué es el éxito

> "Everybody can be successful if it's you who determines what success looks like."
> "The problem is that people go on social media and they say, okay, I want to get a
> million dollar bounty ... and they don't see all their failures."
> "nobody is sharing their failures."
> "A lot of people are, once they reach some level of status, they're quite afraid to
> admit that they don't know everything."
> — **Inti De Ceukelaire**

> "be patient and don't get discouraged: results don't come immediately. Duplications or
> low scores are initially part of the process. Set yourself realistic goals and take
> things one step at a time."
> — **rabhi**

**Por qué importa:** describe un sesgo de supervivencia medible. Lo que se ve en redes es
la cola de la distribución, y compararse con ella produce una estimación falsa de lo
normal. Que lo diga el nº1 histórico de una plataforma le da un peso particular.

**Aplicación:** fijar objetivos de proceso (horas de permanencia, superficie cubierta,
hipótesis registradas) y no de resultado (criticals, importes). Los de proceso están bajo
control; los de resultado, no.

**Fuentes:** enlaces en los principios 7 y 1.

---

## 19 — Ante dos lecturas de un mismo dato, rechaza; no reconcilies

> "Treat parser disagreement as a rejection."
> "Reject a URL whose host is not read identically by every parser in play, rather than
> reconciling the readings."
> — **OWASP**, SSRF Prevention Cheat Sheet

**Por qué importa:** es el principio defensivo que explica media docena de writeups de este
repo — SSRF por `\@`, desync HTTP, discrepancias de parseo de correo, Punycode malformado,
`img%2f` contra la CSP. Todos tienen la misma forma: **dos componentes leen la misma
cadena de forma distinta**. La lección general es que intentar reconciliar lecturas crea
el bypass siguiente; rechazar la ambigüedad la cierra.

**Aplicación ofensiva:** buscar activamente los puntos donde dos componentes leen el mismo
dato (validador y cliente, proxy y aplicación, front-end y back-end, aplicación y mailer).
Es el patrón más productivo de este repo.

**Aplicación defensiva:** ante cualquier discrepancia de interpretación, rechazar la
entrada.

**Fuente:**
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

---

## 20 — Especializa, pero reconoce lo que la especialización cuesta

> "Specialise in a specific area too, such as web, mobile or reverse engineering. Even
> within a single category of vulnerabilities, there is always something new to learn and
> master."
> — **rabhi**

> "a lot of people only go through one cycle."
> — **Inti De Ceukelaire**

**Por qué importa:** los dos apuntan a la profundidad, pero la frase de Inti añade el aviso:
mucha gente aprende algo una vez y nunca vuelve a revisarlo. Especializarse no es llegar y
quedarse, es volver al mismo terreno con más contexto.

**Aplicación:** elegir un área y volver sobre ella en ciclos. La `confianza` y el campo
`mata` de cada writeup existen para que el segundo ciclo empiece donde terminó el primero
en lugar de desde cero.

**Fuentes:** enlaces en los principios 1 y 7.

---

## Lo que NO se incluyó, y por qué

Una afirmación de la entrevista de Inti De Ceukelaire sostiene que en Bélgica se puede
atacar cualquier sitio sin permiso siempre que se actúe éticamente. Queda **fuera** de este
documento por tres razones: es una afirmación jurídica específica de una jurisdicción, no
un principio de metodología; no se ha verificado contra la ley belga en esta sesión; y
ponerla en un documento de principios podría llevar a alguien a actuar sin autorización.
La regla operativa de este repo es la contraria y la que siguen las propias fuentes
técnicas que cita — PortSwigger declara en su investigación de desync:
*"All case-studies were identified through authorized testing on targets with
vulnerability disclosure programs (VDPs)."*

Queda registrado en `_refactor/ELITE-REJECTED.md`.

---

## Inventario de fuentes de este documento

| Hunter / fuente | Enlace | Fecha | Tipo |
|---|---|---|---|
| rabhi (nº1 histórico YesWeHack) | https://www.yeswehack.com/community/rabhi-root-bug-bounty-blueprint | 2025-09-16 | texto |
| Chackal y Serizao | https://www.yeswehack.com/community/bug-bounty-targets-chackal-serizao | 2024-03-13 | texto |
| Inti De Ceukelaire | https://pentest-tools.com/blog/we-think-we-know-inti-de-ceukelaire | act. 2024-02-28 | transcripción de audio |
| James Kettle | https://portswigger.net/research/smashing-the-state-machine | 2023-08-09 | investigación |
| OWASP | SSRF Prevention Cheat Sheet | — | cheatsheet |

---

# AMPLIACIÓN (Fase 7) — principios 21 a 30

**Fuentes nuevas de esta tanda:** Jason Haddix (*The Bug Hunter's Methodology* 4.002, DEF CON
28 Safe Mode, Red Team Village, ago. 2020 — **transcripción ASR**, ver aviso) y NahamSec
(Ben Sadeghipour, `nahamsec.com/posts`, texto publicado).

⚠️ **Aviso de procedencia sobre Haddix.** Su material es una **transcripción automática de
audio** con alta tasa de error en nombres propios, un hueco de audio real de 26,4 s, y frases
cortadas por límites de subtítulo. Todas las citas de abajo están **recompuestas uniendo
subtítulos consecutivos**. Los corchetes temporales son las marcas del fichero. **No citar
palabra por palabra en público sin verificar contra el vídeo.**

---

## 21 — El recon es multiplicativo, no aditivo

> "this idea of starting with seeds and then moving to subs really is going to multiply. The
> more seeds you find the more subdomain enumeration you can do. The more subdomains you find
> is related to how many sites you find. The more sites you find, the more successful you'll
> be inside of your red team engagement or bug bounty program."
> — **Jason Haddix** [24:11.210]

**Por qué importa:** nombra la estructura, no la virtud. Una semilla extra no suma un activo:
multiplica la rama entera que cuelga de ella. Eso cambia dónde conviene invertir esfuerzo —
en las fases **tempranas** (adquisiciones, ASN, *reverse whois*), no en exprimir la última
fase.

**Aplicación:** si el inventario final es escaso, el problema casi nunca está en el
fuerza-bruta de subdominios. Está en que faltan semillas.

**Fuente:** `media.defcon.org/DEF CON 28/.../the bug hunters methodology-jason haddix.eng.txt`

---

## 22 — Antes de cualquier herramienta, un sistema de notas que permita soltar y retomar

> "you have to have a way that jives with you to record your work. Otherwise, you're just
> throwing darts and forgetting what you're doing."
> — **Jason Haddix** [02:21.180]

Y el criterio de diseño, que es lo específico [05:30.280]:

> "everything in orange means I'm currently working on something, and everything in green...
> I've already done... so I can easily put down a project and pick it back up if I want."

**Por qué importa:** lo pone **primero**, antes de las decenas de herramientas de su charla. Y
el requisito que impone no es "tomar notas": es que el sistema soporte **interrupción**. Un
objetivo grande se trabaja en sesiones separadas por días, y lo que mata el progreso no es
olvidar lo que encontraste sino olvidar **qué estabas probando**.

**Aplicación:** es la razón de existir del campo `mata` de cada writeup de este repo y de
`_refactor/ELITE-REJECTED.md`. Converge con el principio 15 (Inti De Ceukelaire): los
escenarios que fallaron son inventario.

---

## 23 — Automatiza el bulk; reserva lo manual para atribución y priorización

> "With every tool or method here in my methodology, I like to give you a manual way to do it
> because context is important and getting used to the idea is important. And I like to give
> you an automated way to do it in case you're going to script up your own recon framework."
> — **Jason Haddix** [12:58.840]

Los dos puntos donde **exige** verificación manual, citados:

> "since you're using a keyword here to search, that you don't get other IP ranges that are not
> your targets. You'll have to verify somewhat manually there." [13:58.860]

> "you'll have to manually kind of verify these but the ones I would look at first are the ones
> that actually have Uber in the domain somewhere." [21:01.860]

**Por qué importa:** la frontera que traza no es "manual bueno, automático malo". Es que la
automatización resuelve **recolección** y es incapaz de resolver **atribución de propiedad**.
Un rango de IP que coincide con una palabra clave no es necesariamente del objetivo, y
confundirlo significa atacar infraestructura ajena.

**Aplicación:** automatiza lo que ya has hecho a mano y entiendes. Verifica a mano todo lo que
decida **si un activo pertenece al alcance** — ahí un falso positivo no es ruido, es un
problema de autorización.

**Nota:** reconoce los límites de su propio script [01:03:05.000]: *"I write a horrible bash
script to do my stuff. It works for me, but it could be better."*

---

## 24 — «Dejé el recon»: entender el negocio por encima de ampliar la superficie

> "I was continuously relying too much on automation and recon, until I realized that most of
> my bounties are coming from programs I spent extensive amounts of time understanding their
> core business... It officially pushed me to shift my mindset from **finding bugs through
> automation to looking at the core application** where they deploy new functionality every
> quarter. **I quit recon** and it helped me figure out a new framework that has allowed me to
> exceed my goals for this year."
> — **NahamSec**

El **subrayado es del propio autor** en el HTML original.

**Por qué importa:** contradice frontalmente el principio 21. Las dos posturas vienen de
hunters de primer nivel y **ninguna es un error**: responden a preguntas distintas. El recon
amplio resuelve *«¿dónde hay superficie que nadie ha mirado?»*; esto resuelve *«¿por qué mis
hallazgos son duplicados?»*.

**Aplicación:** ver `docs/ELITE-METHODOLOGY.md` §1.3 para el criterio de decisión. El
indicador que dice en qué régimen estás es el principio 25.

**Fuente:** `nahamsec.com/posts/hacking-full-time`

---

## 25 — Los duplicados son un diagnóstico, no mala suerte

> "When hundreds or thousands of hunters use identical tools and methodologies, they're all
> discovering the same issues. It's like everyone following the same treasure map - the obvious
> spots will be picked clean."
> — **NahamSec**

> "The bug bounty hunters who consistently succeed aren't the ones running the same tools as
> everyone else. They're the ones who develop deep technical knowledge in specific areas."

**Por qué importa:** convierte un resultado frustrante en **información accionable**. Un
duplicado no dice que llegaste tarde: dice que recorriste la ruta estándar. Y la consecuencia
es contraintuitiva — **más herramientas empeoran el problema**, porque son las mismas que usa
todo el mundo.

**Aplicación:** mide tu tasa de duplicados y trátala como la señal de pivote. Si es alta, el
cuello de botella no es cobertura: es diferenciación. Converge con el principio 2 (rabhi:
explorar los parámetros que nadie mira) y el 12 (Inti: los bugs críticos no están en las zonas
más miradas).

**Fuente:** `nahamsec.com/posts/why-bug-bounty-hunters-keep-finding-duplicates-and-how-to-stop`

---

## 26 — Caza donde ya eres usuario avanzado

> "The most consistent hunters I know focus on programs where they're already power users...
> if you use a platform every day, you understand all its features, quirks, and intended
> behaviors. That knowledge becomes your advantage. If you're interested in a program you don't
> currently use, that's fine, but you need to commit to becoming an expert. For example, if
> you're going to hack on Airbnb, you should understand everything about being a host - how
> listing management works, what automation features are available, how payments flow, every
> single setting and option in a host's dashboard."
> — **NahamSec**

**Por qué importa:** da un criterio de selección **gratuito** y difícil de copiar. El
conocimiento de producto no se automatiza ni se comparte en una wordlist, así que es la única
ventaja que no se erosiona cuando mil personas usan tus herramientas.

Y explica por qué la lógica de negocio sigue dando hallazgos tras años de escaneo: reconocer
que un descuento sobrevive a vaciar la cesta exige saber cómo **debería** comportarse la
tienda.

**Aplicación:** antes de elegir programa, pregúntate de qué producto eres usuario real. Si no
lo eres de ninguno, el principio 4 (Chackal) da el siguiente mejor criterio: superficie
funcional amplia.

---

## 27 — Leer los reportes divulgados del programa es recon

> "As a part of my recon, I typically like to look for known or disclosed vulnerabilities. I
> took a quick glance at their Hacktivity and found the following:"
> — **NahamSec**, en su writeup de Snapchat ($5.000, Jenkins)

Y el razonamiento que lo acompaña, que es la parte buena:

> "First reaction was to do a subdomain brute force, but who are we kidding.. These are
> corp/cdn domains and more than likely most of the juicy sub domains would more than likely be
> in a unique pattern."

**Por qué importa:** la *hacktivity* de un programa dice **qué clases ya pagaron** y **qué
partes de la aplicación tienen historial**. Es inteligencia sobre las prioridades del equipo
defensor, publicada por el propio programa, y gratis.

**Aplicación:** antes de la primera petición, leer los reportes divulgados. Converge con el
principio 8 (Inti: preguntar al cliente dónde buscaría él, con 9 aciertos de 10) y con el 9
(las ofertas de empleo señalan dónde falta personal). Los tres son la misma idea: **el objetivo
publica dónde le duele**.

---

## 28 — Si el canal de confirmación está bloqueado, el negativo no significa nada

> "And one critical tip: Stop using Burp Collaborator or Interact for SSRF testing. Companies
> are blocking these services. If you're serious about SSRF in 2025, set up your own interact.sh
> server. That's the difference between landing an SSRF bounty and missing out."
> — **NahamSec**

> "SSRF is a gold mine. 25% of my total bug bounty earnings last year came from SSRF alone—but
> I'm not talking about basic localhost or metadata tricks."

**Por qué importa:** es el principio más concreto de esta tanda y tiene **consecuencia directa
sobre una skill de este repo**. `skills/ssrf-escalation/SKILL.md` empieza confirmando la salida
con un host propio; si el dominio del colaborador estándar está en una lista de bloqueo, ese
paso da un falso negativo y la skill entera se detiene en el peldaño 1.

Generaliza más allá de SSRF: **un instrumento bloqueado produce un negativo indistinguible de
«no vulnerable»**. Es el mismo fallo que escuchar solo HTTP cuando la SSRF por UNC de Apache
habla SMB (`writeups/ssrf/apache-unc-ssrf-cve-2024-38472.md`).

**Aplicación:** antes de concluir «no hay salida», verifica que tu **canal de observación**
funciona contra ese objetivo. Infraestructura propia en lugar de dominios conocidos.

---

## 29 — Lo viejo es más vulnerable, y es buscable

> "One tip here is that you don't just want to target a certain year. Like here I have 2019 but
> you also want to check 2018 and 2017. In fact, the more stuff you find that goes back farther
> in age, the more likely it is to be vulnerable and less likely to have a lot of security
> assessment associated to it."
> — **Jason Haddix** [22:02.010]

**Por qué importa:** da un **eje de priorización ordenable** sobre un inventario grande, que es
exactamente lo que falta cuando tienes miles de hosts y ninguna razón para empezar por uno. La
antigüedad es un proxy medible de «cuánta revisión ha recibido esto».

**Aplicación:** ordena los activos por antigüedad y empieza por el extremo viejo. Converge con
el principio 7 (Inti: lo que existe por obligación y nadie quiere mantener) y con el 12 (los
críticos no están en las zonas más miradas).

---

## 30 — Shadow IT en cloud: infraestructura que nadie cree que vas a encontrar

> "A lot of people are putting shadow IT infrastructure and registering websites on a credit
> card or just not paying attention or thinking that anybody will find their cloud
> infrastructure because they've never published those domains anywhere other than internally.
> And so you can find a lot of things for your target organization that are just sitting in the
> cloud, pretty much unsecured. In fact, it's been a big part of my research lately is scanning
> the cloud ranges and just finding wickedly undersecured stuff because people just don't think
> you'll ever find it."
> — **Jason Haddix** [44:29.300]

**Por qué importa:** identifica una clase de activo cuyo **modelo de seguridad es la
oscuridad**. No está mal configurado por descuido: está sin configurar porque quien lo levantó
asumió que nadie lo encontraría. Eso predice no solo *dónde* buscar sino *qué* esperar.

**Aplicación:** enumerar rangos de cloud además de DNS. Y la lección de modelo de amenaza que
generaliza, y que el repo documenta en
`writeups/info-disclosure/apache-documentroot-confusion-local-gadgets.md`: **hay que saber qué
sirve tu servidor, no solo qué escribió tu equipo.** Los gadgets locales de `/usr/share` los
instaló la distribución; la infraestructura en la sombra la levantó alguien con una tarjeta de
crédito. Ninguna de las dos aparece en el inventario oficial.

---

## Corrección a una creencia extendida sobre Haddix

Se le atribuye a menudo un **«modelo de madurez» de frameworks de recon**. **No existe.** Nunca
usa el término. Presenta *tier lists* de builds de videojuego (C / B / A / S, con analogía
explícita a Diablo) y las desautoriza **dos veces**:

> "Let me put out a big disclaimer here. My tools that I use personally on all bug hunts are C
> tier tools. And they work for what I want and they do. And they're great. So there's nothing
> bad to say about a C tier tool." [01:05:53.560]

> "Warning... I am scaling some tools and giving them grades. It's not serious. It's my rough
> experience. My gut feel. All these tools are wonderful and I respect the authors of them so
> darn much." [01:07:28.900]

Y duda de su propio esquema: *"I wonder if I should even really have like an S tier and an A
tier."*

**Clasifica sus propias herramientas como C tier** y dice que le funcionan. Citarlo como un
modelo de madurez invierte su mensaje: el suyo es que **la herramienta buena es la que te
funciona**, no la que tiene más características.

También se le atribuye un criterio de **cuándo abandonar un objetivo**. Tampoco existe:
búsqueda insensible a mayúsculas de `give up|gave up|move on|abandon|not worth|waste|walk
away|bail|dead end|stop looking|drop it` → **cero coincidencias**. Solo da criterios de parada
de una **técnica** (*"spider fatigue"*, agotar lo que Google sabe), que no es lo mismo.
