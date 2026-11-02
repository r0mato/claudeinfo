---
name: ssrf-escalation
description: Escalada de una SSRF confirmada hacia metadata cloud, servicios internos y lectura de ficheros, con enfasis en discrepancias de parser de URL.
model: claude-opus-5
---

# 0 — SEÑAL CITADA

> OWASP SSRF Prevention Cheat Sheet.

Las dos citas que ordenan toda la skill:

> "Treat parser disagreement as a rejection."
> "Reject a URL whose host is not read identically by every parser in play, rather than
> reconciling the readings."

Y el payload literal que las motiva, con su comportamiento documentado en Python:

```
http://example.com\@evil.com
```
```python
urlsplit("http://example.com\@evil.com").hostname
# -> 'evil.com'      (la fuente cita el mecanismo: netloc.rpartition('@'))
```

**El patron generalizable:** un validador lee un host y el cliente HTTP conecta a otro.
Es la misma forma que el desync HTTP, las discrepancias de parseo de correo y el bypass
de CSP por `img%2f`. Buscar los puntos donde **dos componentes leen el mismo dato** es
la heuristica mas productiva de este repo.

La recomendacion de raiz de la fuente:
> "Do not accept complete URLs from the user... Match the host against an allowlist,
> and build the request yourself."

---

# 1 — Arbol de decision (coste creciente)

## Paso 1 — Confirmar que hay salida (coste: 1 peticion)
Dirigir la SSRF a un host propio y comprobar que llega la peticion.

- **No llega nada** -> parar aqui. Sin confirmar la salida, todo lo que sigue produce
  silencio ambiguo que se interpreta mal.

## Paso 2 — ¿Es ciega o devuelve respuesta? (coste: 2 peticiones)
Decide todo el resto. Comparar la respuesta ante un host propio que devuelve contenido
conocido frente a uno que no existe.

- **Ciega** -> el canal es la peticion saliente y los tiempos. Util para confirmar
  alcance, insuficiente para leer datos.

## Paso 3 — Probar la discrepancia de parser (coste: 3 peticiones)
```
http://DOMINIO-PERMITIDO\@HOST-PROPIO/
```
**Control obligatorio:** enviar tambien `http://HOST-PROPIO/` a pelo y comprobar que
**se bloquea**. Eso demuestra que el validador existe y funciona, lo que convierte el
hallazgo en un bypass y no en una omision trivial. Es la diferencia entre un informe
que se prioriza y uno que se archiva.

## Paso 4 — Probar esquemas no HTTP (coste: 5 peticiones)
```
file://   phar://   gopher://   data://   dict://
```
Cada uno que funcione **cambia la clase** de vulnerabilidad: `file://` la convierte en
lectura de ficheros, `phar://` en deserializacion, `gopher://` en interaccion con
servicios internos no HTTP.

Control: apuntar `file://` a un fichero que existe y a otro que no, y comparar los
errores. Si son iguales, el esquema esta bloqueado — no es que falte el fichero.

NOTA: la fuente da los **nombres** de esquema y ninguna URL de ejemplo. No inventar la
forma concreta: consultar la documentacion del protocolo.

## Paso 5 — Metadata cloud (coste: 3 peticiones)
```
169.254.169.254              # misma IP en AWS, GCP y Azure
metadata.google.internal     # GCP, por nombre
metadata.amazonaws.com       # AWS, por nombre
```
Probar **IP y nombre** por separado: un filtro puede bloquear una forma y no la otra.

**Determinar IMDSv1 frente a IMDSv2 antes de escribir el informe.** IMDSv1 responde a
una GET simple. IMDSv2 exige un token obtenido por PUT con cabecera, fuera del alcance
de la mayoria de SSRF. Una SSRF contra IMDSv2 obligatorio sigue siendo SSRF, pero **no
es robo de credenciales**, y afirmarlo sin comprobarlo invalida el informe.

La fuente solo da hosts e IPs: no da rutas ni cabeceras. Para esas, documentacion del
proveedor.

## Paso 6 — Red interna (coste: alto)
Rangos que la fuente dice bloquear como minimo, utiles como mapa de lo que buscar:
```
127.0.0.0/8   0.0.0.0/8      ::1/128
10.0.0.0/8    172.16.0.0/12  192.168.0.0/16
fc00::/7      fe80::/10      224.0.0.0/4    ff00::/8
```
Con su advertencia: *"Deny-lists are bypass-prone. Prefer allow-lists."*

## Paso 7 — Cadenas de redireccion y DNS rebinding (coste: muy alto)
Cita literal: *"Domain allowlisting alone does not prevent DNS rebinding."* La fuente
**no da payloads** para esto; describe el mecanismo en prosa.

---

# 2 — Trampas de falso positivo

**1. Filtro confundido con SSRF que no funciona.** Los dos producen el mismo sintoma:
silencio. Señal de muerte: no se ha hecho el paso 1 (salida a un host propio
confirmada). Sin esa referencia, un bloqueo de metadata y una SSRF inexistente son
indistinguibles y llevan a conclusiones opuestas.

**2. Resolucion DNS tomada por conexion.** Una peticion DNS a un host propio prueba que
algo resolvio el nombre, no que se estableciera una conexion HTTP. Señal de muerte:
llega la consulta DNS pero **no** la peticion HTTP. Es resolucion, no SSRF explotable.

**3. IMDSv2 reportado como robo de credenciales.** Señal de muerte: no se obtuvo ningun
contenido de credencial, solo se alcanzo la IP. Alcanzar `169.254.169.254` no es lo
mismo que leer un rol.

---

# 3 — Cuándo esta skill NO es la correcta

- La SSRF viene de un `jku` de JWT y lo que interesa es la suplantacion de identidad
  -> `skill:jwt-attack-tree` (pero reportar la SSRF **aparte**: son dos hallazgos)
- El destino lo controla un argumento de linea de comando (`curl`, `wget`) y no una URL
  parseada -> `writeups/inyeccion/` (argument injection). Recordatorio literal de la
  fuente: *"Argument separation does not validate the destination; apply SSRF
  protections."*
- Lo que ocurre es que dos capas HTTP discrepan al parsear una peticion, no una URL
  -> `skill:desync-triage`
- El fetch lo hace el navegador de la victima y no el servidor: es CSRF o un problema
  de origen, no SSRF.

---

# 4 — Output

Escribir en `evidencias/ssrf-escalation-<slug>.md`:

- confirmacion del paso 1: peticion saliente recibida, con marca de tiempo
- ciega o con respuesta, y en qué se basa esa conclusion
- resultado de la discrepancia de parser **con** su control de bloqueo
- esquemas probados, uno por uno, con el control de fichero inexistente
- metadata: IP y nombre por separado; **version de IMDS determinada**
- qué se obtuvo exactamente: ¿contenido de credencial, o solo alcance de IP?
- las tres trampas, con resultado
