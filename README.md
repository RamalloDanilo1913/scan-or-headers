# Analizador de sitios — headers de seguridad y candidatos a open redirect

Herramienta de reconocimiento **pasivo** en Python: toma un listado de URLs (incluso la salida con ruido de otras herramientas como `httpx`, `gau`, `ffuf` o `waybackurls`) y para cada una:

- Revisa qué headers de seguridad le faltan (`Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`).
- Prueba la versión `http://` de cada sitio `https://` para ver si redirige solo a HTTPS y si ya manda HSTS en texto plano (protección contra downgrade).
- Detecta parámetros con nombres típicos de redirect (`url`, `redirect`, `next`, `return`, `continue`, etc.) cuyo valor es, a su vez, otra URL, y los deja listados aparte como **candidatos a revisar a mano**.

## Por qué es pasivo y no un exploit

La herramienta hace únicamente las mismas peticiones HTTP que haría un navegador al visitar cada URL. **Nunca sigue la URL embebida de un parámetro sospechoso ni intenta confirmar el redirect por su cuenta** — eso queda a propósito como un paso manual.

## Instalación

```bash
pip install -r requirements.txt
```

## Uso

```bash
python3 analizador.py -i urls.txt -o resultado.csv
```

También acepta la entrada por `stdin`, así que se puede encadenar directo con otra herramienta:

```bash
cat salida_httpx.txt | python3 analizador.py -o resultado.csv
```

### Opciones

| Opción | Qué hace |
|---|---|
| `-i / --input` | Archivo con URLs o salida de otra herramienta. Si se omite, lee de `stdin`. |
| `-o / --output` | CSV de salida (obligatorio). |
| `--candidatos` | Archivo de texto con los candidatos a open redirect (por defecto `<output>.candidatos.txt`). |
| `--concurrencia` | Peticiones en paralelo (default: 10). |
| `--timeout` | Timeout por petición en segundos (default: 10). |
| `--pausa` | Pausa entre el lanzamiento de cada petición, para no saturar el sitio objetivo (default: 0). |

## Salidas

**`resultado.csv`** — una fila por URL, con columnas: `url`, `status`, `headers_faltantes`, `https_ok`, `redirige_a_https`, `hsts_en_http`, `parametro_sospechoso`, `url_embebida`, `error`.

**`resultado.csv.candidatos.txt`** — la lista corta de URLs con un parámetro sospechoso, lista para revisar a mano.

## Ejemplo de entrada tolerante a ruido

El parser ignora todo lo que no sea una URL http(s) válida, así que esta entrada (salida cruda de otra herramienta) funciona sin limpiarla primero:

```
[200] https://ejemplo.com [title: Ejemplo]
https://ejemplo.com/ir?redirect=https://otro-sitio.com [302]
```

## Cómo verificar un candidato a mano

Una vez que tengas la lista de candidatos, para confirmar si realmente es un open redirect en un sitio que tengas autorizado:

1. Abrí la URL completa en el navegador (con el parámetro apuntando a un dominio propio de prueba).
2. Fijate si la respuesta es un 3xx con el header `Location` apuntando a ese dominio.
3. Si el sitio valida el dominio de destino (lista blanca, mismo origen, etc.), no es vulnerable.

## Limitaciones conocidas

- La detección de parámetro sospechoso se basa en nombres comunes y en que el valor "parezca" una URL; un sitio puede usar un nombre de parámetro distinto y no se detectaría.
- No seguir la URL embebida es una decisión de diseño, no una limitación técnica: es lo que mantiene la herramienta del lado del reconocimiento pasivo.
- No respeta `robots.txt` ni aplica límites de velocidad por dominio más allá de `--pausa`; en un listado con muchas URLs del mismo sitio, usar `--pausa` y una concurrencia baja para no generar carga innecesaria.

## Stack

Python 3.10+ · `requests`

## Autor

**Danilo Ramallo** — Estudiante de Ingeniería Electrónica · Desarrollo web y ciberseguridad

[LinkedIn](https://www.linkedin.com/in/danilo-ramallo-9877a6289)
