---
clase: auth
tech: jwt-hs256
cwe: CWE-521
cvss: 9.1 # [derivado] con el secreto se firman tokens arbitrarios: suplantacion total
payload: |
  # Comando LITERAL de la fuente:
  hashcat -a 0 -m 16500 <jwt> <wordlist>
  #
  # Formato de salida literal:
  #   <jwt>:<identified-secret>
  #
  # Nota literal de la fuente:
  #   'If you run the command more than once, you need to include the --show flag
  #    to output the results.'
  #
  # Wordlist que la fuente enlaza expresamente:
  #   https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list
precondicion: "El token usa HS256 (HMAC con clave simetrica) y el secreto es debil: por defecto, de ejemplo, de marcador de posicion, o copiado de un tutorial. La fuente añade que si el secreto es extremadamente debil puede llegar a romperse caracter a caracter."
como_se_descubre: |
  Señal en recon: cabecera con alg HS256. La ventaja operativa decisiva, literal de la
  fuente: hashcat 'doesn't rely on sending requests to the server'. El ataque es
  OFFLINE — un solo token capturado basta y no se genera trafico ni ruido en el
  objetivo, lo que lo hace seguro respecto a limites de peticiones y deteccion.
  Por eso es la via preferente cuando hay HS256: coste cero en el objetivo.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: hashcat sobre el token con la wordlist de secretos JWT conocidos
  #    -> si encuentra el secreto, firmar un token nuevo y comprobar que se acepta
  # B: firmar un token con un secreto INVENTADO y enviarlo
  #    -> debe ser rechazado
  # El par B es necesario: confirma que el servidor SI verifica la firma, y por tanto
  # que la aceptacion del token de A se debe al secreto correcto y no a que la firma
  # se ignore (que seria el otro writeup, 'firma no verificada').
mata: |
  - El secreto es largo y aleatorio -> la fuerza bruta por diccionario fracasa.
  - El token usa RS256 u otro algoritmo asimetrico -> este vector no aplica
    (ver skill:jwt-attack-tree -> confusion de algoritmos).
  - La firma no se verifica en absoluto -> no hace falta el secreto (otro writeup).
fuente: "https://portswigger.net/web-security/jwt (seccion 'Brute-forcing secret keys'). Comando, formato de salida, nota de --show y enlace a wordlist, literales de la pagina."
confianza: alta
fecha: 2026-11-02
---
# [AUTH] Fuerza bruta offline del secreto HS256 de un JWT

## Principio
HS256 firma con un secreto compartido. Si ese secreto es una palabra —y lo es con
frecuencia, porque sale de un tutorial, de un valor por defecto o de un marcador que
nadie cambió— el token capturado contiene todo lo necesario para probar candidatos
localmente. La firma es el oráculo: un candidato correcto reproduce la firma observada.

## Payload
```bash
hashcat -a 0 -m 16500 <jwt> <wordlist>
```

Formato de salida:

```
<jwt>:<identified-secret>
```

La fuente añade una nota práctica que ahorra confusión: *"If you run the command more
than once, you need to include the `--show` flag to output the results."* Y enlaza una
lista específica de secretos JWT conocidos:
`https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list`

## Lo que hace a este vector distinto
Cita literal de la fuente: hashcat *"doesn't rely on sending requests to the server"*.
El ataque es **completamente offline**. Un único token capturado es todo el material
necesario, y el objetivo no recibe ni una petición durante el proceso. Eso tiene tres
consecuencias operativas: no hay límite de intentos que agotar, no hay ruido que
detectar, y no hay riesgo de bloqueo de cuenta. Cuando el algoritmo es HS256, esta es
la línea de ataque de menor coste y menor riesgo.

## Impacto
Con el secreto en mano el atacante firma tokens arbitrarios: cualquier identidad,
cualquier claim, con firma válida. Equivale a tener la clave maestra de la
autenticación, y es indistinguible de tráfico legítimo en los registros del servidor.

## Remediación
`# [derivado]`, porque la fuente no da remediación específica para esta sección: usar
secretos de alta entropía generados aleatoriamente (no palabras, no valores de
ejemplo), gestionarlos como secretos de infraestructura y rotarlos. La mitigación
estructural es preferir algoritmos asimétricos, de modo que el servidor que valida no
posea la clave con la que se firma. De las buenas prácticas que sí da la fuente,
aplican aquí: *"Always set an expiration date for any tokens that you issue."* y
*"Enable the issuing server to revoke tokens (on logout, for example)."*
