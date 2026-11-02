---
clase: ssrf
tech: aws-gcp-azure-imds
cwe: CWE-918
cvss: 9.1 # [derivado] robo de credenciales de rol de instancia
payload: |
  # Destinos LITERALES de la fuente (los lista en su tabla de denegacion):
  #
  # AWS IMDS:
  169.254.169.254
  metadata.amazonaws.com
  #
  # GCP Metadata:
  metadata.google.internal
  169.254.169.254
  #
  # Azure IMDS:
  169.254.169.254
  #
  # ADVERTENCIA DE PROCEDENCIA: la fuente da UNICAMENTE estos hosts e IPs. NO contiene
  # rutas completas de URL, NO contiene cabeceras (ni token de IMDSv2 ni
  # Metadata-Flavor) y NO tiene entradas de DigitalOcean, Oracle ni Alibaba.
  # No las añado de memoria: un endpoint de metadata inventado es exactamente el tipo
  # de payload que este catalogo no debe contener. Para las rutas y cabeceras hay que
  # ir a la documentacion del proveedor.
  #
  # Rangos minimos a bloquear - LITERALES de la fuente ('When unavoidable, block these
  # minimum ranges:'):
  127.0.0.0/8
  0.0.0.0/8
  ::1/128
  10.0.0.0/8
  172.16.0.0/12
  192.168.0.0/16
  fc00::/7
  fe80::/10
  224.0.0.0/4
  ff00::/8
precondicion: "La aplicacion corre en una instancia cloud con servicio de metadata accesible y existe una SSRF que permite dirigir una peticion a una IP arbitraria. Para AWS, el impacto depende criticamente de la version: IMDSv1 responde a una GET simple; IMDSv2 exige un token obtenido por PUT, lo que lo hace mucho mas dificil de alcanzar via SSRF."
como_se_descubre: |
  Una vez confirmada una SSRF, 169.254.169.254 es el primer destino a probar en
  cualquier objetivo alojado en cloud: es la misma IP en AWS, GCP y Azure, asi que una
  sola peticion cubre los tres proveedores.
  Los nombres DNS (metadata.google.internal, metadata.amazonaws.com) importan aparte
  porque un filtro que bloquee la IP literal puede no resolver y bloquear el nombre, y
  viceversa. Hay que probar AMBAS formas.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: SSRF dirigida a 169.254.169.254  -> respuesta del servicio de metadata
  # B: SSRF dirigida a una IP publica controlada -> respuesta normal (confirma que la
  #    SSRF funciona y hay salida de red)
  # C: SSRF dirigida a 169.254.169.254 por NOMBRE (metadata.google.internal)
  #    -> comparar con A: si A se bloquea y C no (o al contrario), el filtro actua
  #       sobre una sola de las dos formas
  # El par A/B separa 'el filtro bloquea la metadata' de 'la SSRF no funciona', que
  # producen el mismo sintoma (sin respuesta) y llevan a conclusiones opuestas.
mata: |
  - IMDSv2 obligatorio: requiere un PUT con cabecera de token, que una SSRF de GET
    simple no puede hacer. Es la mitigacion que la fuente recomienda.
  - Segmentacion de red que bloquee el enlace local desde la carga de trabajo.
  - El filtro bloquea tanto la IP como los nombres DNS (ver control C).
  - La aplicacion no corre en cloud o no tiene rol de instancia asociado.
fuente: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html. Hosts, IPs y rangos CIDR literales de la pagina. Sobre IMDS la pagina dice unicamente: 'To leverage this protection migrate to IMDSv2 and disable old IMDSv1. Check out AWS documentation for more details.' La documentacion de AWS enlazada NO se consulto en esta sesion."
confianza: media
fecha: 2026-11-02
---
# [SSRF] Servicios de metadata cloud — `169.254.169.254` y por qué IMDSv2 cambia el juego

## Principio
Las instancias cloud exponen un servicio de metadata en una IP de enlace local que
entrega, entre otras cosas, credenciales temporales del rol de la instancia. Para ese
servicio, cualquier petición que venga de la instancia **es** la instancia: no hay
autenticación porque la ubicación de red *es* la autenticación. Una SSRF rompe
exactamente esa premisa, porque permite a un atacante externo originar peticiones desde
dentro.

## Payload
Destinos literales de la fuente:

```
# AWS IMDS
169.254.169.254
metadata.amazonaws.com

# GCP Metadata
metadata.google.internal
169.254.169.254

# Azure IMDS
169.254.169.254
```

La misma IP sirve para los tres proveedores, así que una sola petición cubre los tres.
Pero conviene probar **también los nombres DNS**: un filtro que bloquee la IP literal
puede no resolver el nombre antes de decidir, y al contrario.

## Advertencia de procedencia
La fuente da **únicamente** estos hosts e IPs. No contiene rutas completas de URL, ni
cabeceras (ni el token de IMDSv2 ni `Metadata-Flavor`), ni entradas de DigitalOcean,
Oracle o Alibaba. No las añado de memoria: un endpoint de metadata inventado es
precisamente el tipo de contenido que este catálogo no debe tener, porque parece
reproducible y no lo es. Para las rutas y cabeceras hay que ir a la documentación del
proveedor. De ahí `confianza: media`.

## IMDSv1 frente a IMDSv2
Esta distinción decide el impacto real y conviene establecerla antes de escribir el
informe. IMDSv1 responde a una `GET` simple, que es justo lo que una SSRF típica puede
hacer. IMDSv2 exige obtener antes un token mediante un `PUT` con cabecera, lo que
está fuera del alcance de la mayoría de SSRF, que solo controlan la URL de una petición
`GET`. Una SSRF contra una instancia con IMDSv2 obligatorio sigue siendo una SSRF, pero
no es un robo de credenciales.

## Rangos que la fuente dice bloquear como mínimo
```
127.0.0.0/8    0.0.0.0/8      ::1/128
10.0.0.0/8     172.16.0.0/12  192.168.0.0/16
fc00::/7       fe80::/10      224.0.0.0/4     ff00::/8
```

Con su advertencia por delante: *"Deny-lists are bypass-prone. Prefer allow-lists."*

## Impacto
Credenciales temporales del rol de la instancia, con los permisos que ese rol tenga
sobre la cuenta cloud. Es el techo habitual de una SSRF y la razón de que la clase se
trate como crítica aunque el fallo nazca de una función de "previsualizar un enlace".

## Remediación
De la fuente: *"To leverage this protection migrate to IMDSv2 and disable old IMDSv1."*
Y, como capa independiente: *"Network segregation ... is highly recommended in order to
block illegitimate calls directly at network level itself"*, bajo el principio que la
propia página enuncia: *"To apply the defense in depth principle, both layers will be
hardened against such attacks."*
