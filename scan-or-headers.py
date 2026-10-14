#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Headers de seguridad que busca:
HEADERS_ESPERADOS = {
    "Strict-Transport-Security": "fuerza HTTPS en visitas futuras",
    "X-Content-Type-Options": "evita que el navegador adivine el tipo de archivo",
    "X-Frame-Options": "evita que el sitio se embeba en un iframe ajeno",
    "Content-Security-Policy": "limita qué recursos puede cargar la página",
    "Referrer-Policy": "controla qué URL se filtra al navegar a otro sitio",
}

# Nombres de parámetro típicos de open redirect:
PARAMETROS_SOSPECHOSOS = {
    "url", "u", "redirect", "redirect_uri", "redirecturl", "next", "return",
    "returnurl", "return_to", "continue", "dest", "destination", "target",
    "go", "goto", "out", "link", "callback", "callback_url", "forward",
    "forward_url", "r", "view",
}

USER_AGENT_DEFAULT = "scan-or-headers, herramienta de escaneo pasivo"

URL_REGEX = re.compile(r"https?://[^\s\"'<>\]\)\[]+", re.IGNORECASE)
# Detecta un valor de parámetro que es, a su vez, una URL (embebida o codificada con %-escapes / doble codificación básica).
VALOR_URL_REGEX = re.compile(
    r"^(https?%3a%2f%2f|https?://|%68%74%74%70)", re.IGNORECASE
)


@dataclass
class Resultado:
    url: str
    status: str = ""
    headers_faltantes: str = ""
    https_ok: str = ""
    redirige_a_https: str = ""
    hsts_en_http: str = ""
    parametro_sospechoso: str = ""
    url_embebida: str = ""
    error: str = ""


# Parseo de entrada:

def extraer_urls(lineas: list[str]) -> list[str]:
    # Extrae URLs http(s) válidas de texto arbitrario
    vistas: set[str] = set()
    urls: list[str] = []
    for linea in lineas:
        for match in URL_REGEX.findall(linea):
            url = match.rstrip(".,;")  # basura de puntuación al final
            if url not in vistas:
                vistas.add(url)
                urls.append(url)
    return urls


# Detección de URL embebida en parámetros:

def detectar_parametro_sospechoso(url: str) -> tuple[str, str]:
    """Devuelve (nombre_de_parametro, valor) si la URL tiene un parámetro de
    nombre típico de redirect cuyo valor parece ser otra URL"""
    partes = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(partes.query, keep_blank_values=True)
    for nombre, valor in query:
        if nombre.lower() in PARAMETROS_SOSPECHOSOS and valor:
            valor_decodificado = urllib.parse.unquote(valor)
            if VALOR_URL_REGEX.match(valor_decodificado) or valor_decodificado.startswith("//"):
                return nombre, valor_decodificado
    return "", ""


# Peticiones HTTP:

def armar_sesion(timeout: float, user_agent: str) -> requests.Session:
    sesion = requests.Session()
    reintentos = Retry(total=2, backoff_factor=0.5, status_forcelist=[502, 503, 504])
    adaptador = HTTPAdapter(max_retries=reintentos)
    sesion.mount("http://", adaptador)
    sesion.mount("https://", adaptador)
    sesion.headers.update({"User-Agent": user_agent})
    return sesion


def analizar_url(sesion: requests.Session, url: str, timeout: float) -> Resultado:
    resultado = Resultado(url=url)

    # Parámetro sospechoso (no depende de la red)
    nombre, valor = detectar_parametro_sospechoso(url)
    if nombre:
        resultado.parametro_sospechoso = nombre
        resultado.url_embebida = valor

    # Petición principal: seguimos redirects para ver el estado final y los headers de la respuesta real.
    try:
        resp = sesion.get(url, timeout=timeout, allow_redirects=True)
        resultado.status = str(resp.status_code)
        faltantes = [h for h in HEADERS_ESPERADOS if h not in resp.headers]
        resultado.headers_faltantes = ", ".join(faltantes) if faltantes else "ninguno"
    except requests.RequestException as e:
        resultado.error = f"fallo petición principal: {e.__class__.__name__}"
        return resultado

    # Si la URL era https, probamos también la versión http para ver si
    # el sitio redirige solo hacia https (protección contra downgrade) y
    # si ya manda HSTS desde la respuesta en texto plano.
    partes = urllib.parse.urlsplit(url)
    if partes.scheme == "https":
        url_http = urllib.parse.urlunsplit(("http",) + partes[1:])
        try:
            resp_http = sesion.get(url_http, timeout=timeout, allow_redirects=False)
            resultado.https_ok = "si"
            ubicacion = resp_http.headers.get("Location", "")
            resultado.redirige_a_https = "si" if ubicacion.startswith("https://") else "no"
            resultado.hsts_en_http = "si" if "Strict-Transport-Security" in resp_http.headers else "no"
        except requests.RequestException as e:
            resultado.https_ok = "no"
            resultado.error = (resultado.error + "; " if resultado.error else "") + \
                f"fallo prueba http: {e.__class__.__name__}"
    else:
        # La URL ya vino en http: lo dejamos anotado, es en sí mismo un hallazgo.
        resultado.https_ok = "url_original_es_http"

    return resultado


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analiza headers de seguridad, HTTP vs HTTPS y candidatos "
        "a open redirect sobre un listado de URLs. Uso pasivo únicamente.",
    )
    parser.add_argument("-i", "--input", help="Archivo con URLs (o salida de otra herramienta). "
                         "Si se omite, lee de stdin.")
    parser.add_argument("-u", "--url", help="Analiza una sola URL suelta, sin necesidad de archivo. "
                     "Si se pasa, se ignoran -i y stdin.")
    parser.add_argument("-o", "--output", required=True, help="CSV de salida con todos los resultados.")
    parser.add_argument("--candidatos", help="Archivo de texto con la lista corta de candidatos a "
                         "open redirect para revisión manual (por defecto: <output>.candidatos.txt).")
    parser.add_argument("--concurrencia", type=int, default=10, help="Peticiones en paralelo (default: 10).")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout por petición en segundos (default: 10).")
    parser.add_argument("--pausa", type=float, default=0.0, help="Pausa en segundos entre el lanzamiento de cada "
                         "petición, para no saturar el sitio objetivo (default: 0).")
    parser.add_argument("--user-agent", default=USER_AGENT_DEFAULT, help="User-Agent a enviar en cada petición. "
                     f"autorizados. Default: {USER_AGENT_DEFAULT!r}")
    args = parser.parse_args()

    if args.url:
        lineas = [args.url]
    
    elif args.input:
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
          lineas = f.readlines()
    else:
        lineas = sys.stdin.readlines()

    urls = extraer_urls(lineas)
    if not urls:
        print("No se encontraron URLs http(s) válidas en la entrada.", file=sys.stderr)
        return 1

    print(f"[info] {len(urls)} URLs únicas detectadas. Analizando con concurrencia={args.concurrencia}...",
          file=sys.stderr)

    sesion = armar_sesion(args.timeout, args.user_agent)
    resultados: list[Resultado] = []

    with ThreadPoolExecutor(max_workers=args.concurrencia) as pool:
        futuros = {}
        for url in urls:
            if args.pausa:
                time.sleep(args.pausa)
            futuros[pool.submit(analizar_url, sesion, url, args.timeout)] = url

        completados = 0
        for futuro in as_completed(futuros):
            resultados.append(futuro.result())
            completados += 1
            if completados % 20 == 0 or completados == len(urls):
                print(f"[info] {completados}/{len(urls)} analizadas", file=sys.stderr)

    # Orden estable por URL original
    orden = {url: i for i, url in enumerate(urls)}
    resultados.sort(key=lambda r: orden.get(r.url, 0))

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "url", "status", "headers_faltantes", "https_ok", "redirige_a_https",
            "hsts_en_http", "parametro_sospechoso", "url_embebida", "error",
        ])
        writer.writeheader()
        for r in resultados:
            writer.writerow(r.__dict__)

    candidatos_path = args.candidatos or (args.output + ".candidatos.txt")
    candidatos = [r for r in resultados if r.parametro_sospechoso]
    with open(candidatos_path, "w", encoding="utf-8") as f:
        f.write("# Candidatos a open redirect (DETECCIÓN PASIVA, sin confirmar).\n")
        f.write("# Revisar a mano, solo en sitios propios o autorizados.\n")
        f.write("# No se siguió ninguna de estas URLs para comprobar el redirect.\n\n")
        for r in candidatos:
            f.write(f"{r.url}\n    parametro={r.parametro_sospechoso!r} valor={r.url_embebida!r}\n\n")

    print(f"[ok] Resultados completos: {args.output}", file=sys.stderr)
    print(f"[ok] Candidatos a open redirect: {candidatos_path} ({len(candidatos)} encontrados)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
