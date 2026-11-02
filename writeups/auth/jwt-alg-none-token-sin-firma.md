---
clase: auth
tech: jwt
cwe: CWE-347
cvss: 9.1 # [derivado] suplantacion total de identidad
payload: |
  # Cabecera normal, literal de la fuente:
  { "alg": "HS256", "typ": "JWT" }
  #
  # Para un JWT no asegurado (unsecured JWT) el parametro alg se pone a 'none'.
  { "alg": "none", "typ": "JWT" }
  #
  # DETALLE CRITICO, cita literal de la fuente:
  #   'Even if the token is unsigned, the payload part must still be terminated
  #    with a trailing dot.'
  # Es decir, el token termina en punto y la tercera seccion queda vacia:
  #   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<payload-base64url>.
  #                                                          ^ el punto final es obligatorio
  #
  # La fuente NO proporciona un token de ejemplo completo: la cabecera de arriba y la
  # regla del punto final son lo literal; la forma del token es reconstruccion mia.
  #
  # Bypass de filtros, segun la fuente: los filtros que rechazan 'none' por
  # comparacion de cadenas se pueden esquivar a veces con 'mixed capitalization
  # and unexpected encodings' (la fuente no da las variantes concretas).
precondicion: "El servidor confia en el valor de 'alg' que viene DENTRO del token. La fuente advierte que los servidores 'usually reject tokens with no signature', asi que la variante directa suele estar cubierta y el interes esta en los filtros mal hechos."
como_se_descubre: |
  Segunda prueba del arbol, despues de la de firma no verificada. Enviar alg=none con
  el punto final y observar. Si se rechaza, probar variantes de capitalizacion
  (`None`, `NONE`, `nOnE`) para distinguir un filtro por comparacion de cadenas de una
  validacion real por allowlist: un filtro que acepte `None` pero rechace `none` es
  un hallazgo en si mismo, porque demuestra que la comprobacion es textual.
control_negativo: |
  # [derivado] diseño de test A/B
  # A: alg=none CON el punto final                 -> probar aceptacion
  # B: alg=none SIN el punto final                 -> debe fallar por formato, no por politica
  # El par B importa para no concluir 'no vulnerable' cuando el rechazo se debe a un
  # token mal formado. Es el error de triaje mas comun en este vector.
  # C: variantes de capitalizacion (None/NONE) -> distingue filtro textual de allowlist
mata: |
  - El servidor valida 'alg' contra una allowlist de algoritmos esperados -> muere.
  - Se rechazan todas las variantes de capitalizacion y codificacion.
  - La firma se verifica siempre con la clave del servidor sin leer 'alg' del token
    (el diseño correcto).
fuente: "https://portswigger.net/web-security/jwt (seccion 'Accepting tokens with no signature'). La fuente no muestra un token alg=none completo; muestra la cabecera normal y enuncia la regla del punto final."
confianza: media
fecha: 2026-11-02
---
# [AUTH] JWT `alg: none` — el token sin firma y el punto final obligatorio

## Principio
El propio token declara con qué algoritmo fue firmado, y `none` es un valor válido de
la especificación (*unsecured JWT*). Si el servidor obedece ese campo, el atacante le
está diciendo "no compruebes nada" y el servidor cumple. El defecto de diseño está en
la especificación: el dato que decide cómo validar viaja dentro del dato a validar.

## Payload
Cabecera normal, tal como la muestra la fuente:

```json
{ "alg": "HS256", "typ": "JWT" }
```

Cabecera del ataque:

```json
{ "alg": "none", "typ": "JWT" }
```

## El detalle que hace fallar la mayoría de intentos
Cita literal: *"Even if the token is unsigned, the payload part must still be terminated
with a trailing dot."* El token tiene tres secciones y la tercera queda **vacía pero
presente**:

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<payload-base64url>.
```

Ese punto final es la causa habitual de un falso negativo: sin él el token está mal
formado, el servidor lo rechaza por formato, y el tester concluye que el objetivo no es
vulnerable cuando en realidad no ha llegado a probarlo. Por eso el control negativo de
este writeup incluye explícitamente la variante sin punto.

## Bypass de filtros
La fuente señala que los filtros que rechazan `none` mediante comparación de cadenas
pueden esquivarse a veces con *"mixed capitalization and unexpected encodings"*. No da
las variantes concretas, así que `None`, `NONE` y similares son extrapolación razonable
pero **no están literales en la fuente**. Un objetivo que acepte `None` y rechace `none`
confirma que la comprobación es textual, lo que suele implicar que hay más huecos.

## Impacto
Suplantación de identidad arbitraria, igual que el vector de firma no verificada. La
fuente matiza que los servidores suelen rechazar tokens sin firma, así que el valor
práctico de este vector está hoy menos en la forma directa y más en destapar filtros
implementados por comparación de cadenas.

## Remediación
Validar `alg` contra una allowlist de algoritmos esperados, y mejor aún: no leer el
algoritmo del token en absoluto, sino fijarlo en el servidor según la clave que le
corresponde. `# [derivado]`: rechazar por defecto cualquier token cuyo `alg` no sea
exactamente uno de los valores previstos, con comparación exacta y sin normalización
de mayúsculas — la normalización es justo lo que habilita el bypass.
