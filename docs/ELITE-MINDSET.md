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
