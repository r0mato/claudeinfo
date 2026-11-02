---
clase: auth
tech: rfc2047-encoded-word
cwe: CWE-290
cvss: 8.8 # [derivado] sin CVE para estos casos; acceso no autorizado a organizaciones por dominio
payload: |
  # Sonda de confirmacion: la direccion se envia con un encoded-word y se observa
  # el RCPT TO real en Burp Collaborator. Resultado observado LITERAL de la fuente:
  abccollab@psres.net
  # (es decir, el parser decodifico '=41=42=43' -> 'ABC' dentro de la direccion)
  #
  # ZENDESK - par entrada/salida LITERAL de la fuente:
  Input:   =?x?q?=41=42=43collab=40psres.net=3e=20?=@psres.net
  Output:  RCPT TO:<"ABCcollab@psres.net> "@psres.net>
  #
  # GITHUB - ilustracion LITERAL del concepto (la fuente la marca como ilustracion,
  # no como payload funcional; el vector final de GitHub solo aparece en captura):
  RCPT TO:<"collab@psres.net>collab"@psres.net>
  #
  # Fragmentos de codificacion que la fuente nombra en prosa por objetivo:
  #   GitHub: charset 'x', '=40', '=3e', '=00', local part 'foo'
  #   Zendesk: '=3c22', '=3e=00'
  #   GitLab Enterprise: '_' (subrayado) o '=20' para el espacio
  #   GitLab web: espacio codificado; 'iso-8859-1' en un ataque real
precondicion: "(1) El parser de correo decodifica encoded-word (RFC 2047) DENTRO de la direccion. (2) El mailer acepta la division de la direccion (mediante nulos u otros caracteres). (3) El control de acceso se basa en el DOMINIO del correo. La fuente documenta tres escenarios reales: GitHub como IdP de Cloudflare Zero Trust usando el dominio para decidir acceso; GitLab Enterprise con restriccion de registro por dominio; y centro de soporte Zendesk con registro habilitado y dominios permitidos."
como_se_descubre: |
  Metodologia LITERAL de la fuente: 'Probe, Observe, Encode and Exploit'.
  1. SONDA: registrar una direccion que contenga un encoded-word y un dominio de
     Burp Collaborator.
  2. OBSERVA: mirar la interaccion SMTP en Collaborator. Si el RCPT TO llega
     DECODIFICADO (p.ej. 'abccollab@psres.net' desde '=41=42=43'), el parser decodifica
     encoded-word dentro de la direccion: precondicion (1) confirmada.
  3. CODIFICA: construir la direccion que, al decodificarse, parta en dos.
  4. EXPLOTA.
  Truco operativo de la fuente para Zendesk: usar DOS dominios Collaborator duplicados
  para garantizar que siempre se reciba una interaccion.
control_negativo: |
  # [derivado] diseño de test A/B, construido sobre la sonda literal de la fuente
  # A: direccion con encoded-word ('=41=42=43' + dominio Collaborator)
  #    -> RCPT TO llega DECODIFICADO = el parser decodifica
  # B: la misma direccion con el texto ya en claro ('ABC' + dominio Collaborator)
  #    -> RCPT TO identico al enviado
  # Si A y B llegan iguales (ambos sin decodificar), NO hay decodificacion de
  # encoded-word y toda la clase muere aqui: no merece la pena seguir.
  # El par separa 'el parser decodifica' de 'el correo simplemente llega'.
mata: |
  - El parser no decodifica encoded-word dentro de la direccion (control A == B) -> muere.
  - El mailer no permite partir la direccion con nulos ni otros caracteres.
  - El control de acceso NO usa el dominio del correo -> aunque se falsifique, no hay
    escalada de privilegio.
  - Objetivos ya parcheados: GitHub (2024-05-09), Zendesk (2024-05-09),
    GitLab (2024-04-25).
fuente: "https://portswigger.net/research/splitting-the-email-atom (Gareth Heyes, publicado 2024-08-07, actualizado 2025-06-27). Objetivos y fechas de correccion segun la cronologia del articulo. ADVERTENCIA: los vectores finales de GitHub, Zendesk y GitLab aparecen SOLO en capturas de pantalla; el texto da el par entrada/salida de Zendesk y fragmentos de codificacion, que es lo reproducido aqui."
confianza: media
fecha: 2026-11-02
---
# [AUTH] Encoded-word (RFC 2047) para falsificar el dominio del correo — GitHub, GitLab y Zendesk

## Principio
Una dirección de correo pasa por varios parsers antes de llegar al buzón: el de la
aplicación que valida el registro, y el del mailer que entrega. RFC 2047 permite
codificar texto (`=?charset?q?=41=42=43?=`) y algunos parsers lo decodifican **dentro de
la dirección**. Si la aplicación valida la forma codificada y el mailer entrega la
decodificada, las dos no están mirando la misma dirección — y el atacante elige qué ve
cada una.

El impacto llega porque mucho control de acceso cuelga del dominio: "quien tenga un
correo `@empresa.com` pertenece a la empresa". Esa inferencia es la que se rompe.

## Payload
La sonda de confirmación, con su resultado literal observado en Collaborator:

```
abccollab@psres.net
```

Ver esa dirección decodificada en el `RCPT TO` prueba que el parser decodifica
encoded-word. Es el hecho que habilita todo lo demás.

El par entrada/salida de **Zendesk**, literal de la fuente:

```
Input:   =?x?q?=41=42=43collab=40psres.net=3e=20?=@psres.net
Output:  RCPT TO:<"ABCcollab@psres.net> "@psres.net>
```

La idea aplicada a **GitHub**, que la fuente marca explícitamente como ilustración del
concepto y no como vector funcional:

```
RCPT TO:<"collab@psres.net>collab"@psres.net>
```

## Advertencia de procedencia
Los vectores finales y funcionales de GitHub, Zendesk y GitLab aparecen en el artículo
**solo como capturas de pantalla**. El texto da el par de Zendesk, la sonda y
fragmentos de codificación por objetivo (`=40`, `=3e`, `=00`, `=3c22`, `iso-8859-1`).
No reconstruyo los que faltan: una dirección de este tipo depende de cada carácter, y
una reconstrucción a ojo sería un payload inventado. De ahí `confianza: media`.

## Metodología
La fuente la formula como *"Probe, Observe, Encode and Exploit"*, y lo valioso es que
el paso 2 es un **corte temprano**: si el `RCPT TO` no llega decodificado, la clase
entera está descartada con una sola sonda. Vale la pena hacerla antes de invertir en
construir direcciones.

## Impacto
Verificar una dirección de un dominio ajeno y, con ello, entrar en la organización que
confía en ese dominio. El autor verificó en una cuenta de prueba direcciones de
`microsoft.com`, `mozilla.com` y `github.com`. El caso más agudo es GitHub como
proveedor de identidad de Cloudflare Zero Trust: el control de acceso corporativo
termina apoyado en una inferencia de dominio que se puede falsificar.

## Remediación
Citas literales: *"I recommend you disable 'encoded-word' when using an email parsing
library."* Como último recurso la fuente da un regex para bloquearlo: `=[?].+[?]=`.
Y la conclusión de fondo, que es la que de verdad importa: *"Never use the email domain
as a sole means of authorisation, because it can be easily spoofed as we've seen."* Con
el cierre: *"it's never safe to use email domains for access control enforcement"*.

Añade además: *"You should always validate an email address even when it comes from a
SSO provider such as Github."*
