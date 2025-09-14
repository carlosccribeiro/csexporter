#!/usr/bin/env python3
"""
Exporta a lista de IOCs criados do CrowdStrike para Excel.
Cada type = uma aba no Excel (ex.: hash, url),
coluna 1 = value (hash ou url),
coluna 2 = original_filename,
coluna 3 = action,
coluna 4 = platforms.
Lê credenciais do arquivo .env.
O nome do cliente é adicionado ao nome do arquivo exportado.
"""

import os, sys
import pandas as pd
from datetime import datetime, timezone
import requests
import json
from dotenv import load_dotenv

# Carrega as variáveis do arquivo .env
load_dotenv()
FALCON_CLIENT_ID = os.getenv("FALCON_CLIENT_ID")
FALCON_CLIENT_SECRET = os.getenv("FALCON_CLIENT_SECRET")
FALCON_BASE_URL = os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com")
CLIENT_NAME = os.getenv("CLIENT_NAME")

def get_bearer_token():
    if not all([FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, CLIENT_NAME]):
        raise RuntimeError("FALCON_CLIENT_ID, FALCON_CLIENT_SECRET ou CLIENT_NAME não encontrados no .env")

    auth_url = f"{FALCON_BASE_URL}/oauth2/token"
    data = {"client_id": FALCON_CLIENT_ID, "client_secret": FALCON_CLIENT_SECRET, "grant_type": "client_credentials"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    print(f"Requisição de autenticação - URL: {auth_url}, Data: {data}, Headers: {headers}")  # Depuração
    resp = requests.post(auth_url, data=data, headers=headers)
    print(f"Resposta bruta da autenticação: {resp.text}")  # Depuração
    if resp.status_code != 201:
        raise RuntimeError(f"Falha na autenticação: {resp.status_code} - {resp.text}")
    try:
        return resp.json()["access_token"], FALCON_BASE_URL, CLIENT_NAME
    except ValueError:
        raise RuntimeError(f"Resposta de autenticação inválida: {resp.text}")

def fetch_iocs(token, base_url):
    url = f"{base_url}/iocs/combined/indicator/v1"
    headers = {"Authorization": f"Bearer {token}"}
    all_resources = []
    offset = 0
    limit = 2000  # Máximo permitido

    while True:
        params = {"limit": limit, "offset": offset}
        resp = requests.get(url, headers=headers, params=params)
        print(f"Resposta da API (offset {offset}): {resp.text}")  # Depuração
        if resp.status_code != 200:
            raise RuntimeError(f"Falha ao buscar IOCs: {resp.status_code} - {resp.text}")
        try:
            data = resp.json()
            resources = data.get("resources", [])
            all_resources.extend(resources)
            if not resources or len(resources) < limit:  # Se não houver mais recursos, termina
                break
            offset += limit
        except ValueError:
            raise RuntimeError(f"Resposta da API inválida: {resp.text}")

    return all_resources

def transform_iocs(iocs):
    """
    Retorna dict: {type: DataFrame}, onde:
    - coluna 1 = value (hash ou url)
    - coluna 2 = original_filename (dentro de metadata)
    - coluna 3 = action
    - coluna 4 = platforms
    """
    per_type = {}
    for ioc in iocs:
        ioc_type = ioc.get("type", "Unknown")
        if ioc_type not in per_type:
            per_type[ioc_type] = []
        value = ioc.get("value", "")
        original_filename = ioc.get("metadata", {}).get("original_filename", "")
        action = ioc.get("action", "")
        platforms = ", ".join(ioc.get("platforms", [])) if isinstance(ioc.get("platforms"), list) else ioc.get("platforms", "")
        per_type[ioc_type].append([value, original_filename, action, platforms])

    # Transformar em DataFrame por type
    result = {}
    for ioc_type, ioc_list in per_type.items():
        df = pd.DataFrame(ioc_list, columns=["value", "original_filename", "action", "platforms"])
        result[ioc_type] = df
    return result

def save_to_excel(per_type, outfile="crowdstrike_iocs.xlsx"):
    if not outfile.lower().endswith(".xlsx"):
        outfile += ".xlsx"

    meta = pd.DataFrame([{
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tipos_iocs": ", ".join(per_type.keys()),
        "total_abas": len(per_type)
    }])

    with pd.ExcelWriter(outfile) as writer:
        for ioc_type, df in per_type.items():
            sheet_name = ioc_type if len(ioc_type) <= 31 else ioc_type[:31]
            df.to_excel(writer, sheet_name=sheet_name, index=False)
        meta.to_excel(writer, sheet_name="Meta", index=False)

    print(f"✅ Exportado para {outfile} com {len(per_type)} abas (tipos de IOC)")

def main():
    try:
        token, base_url, client_name = get_bearer_token()
        outfile = f"crowdstrike_iocs_{client_name.replace(' ', '_')}.xlsx"
        iocs = fetch_iocs(token, base_url)
        per_type = transform_iocs(iocs)
        if not per_type:
            print("Nenhum IOC encontrado.")
            return
        save_to_excel(per_type, outfile)
    except Exception as e:
        print(f"Erro ao executar o script: {e}")

if __name__ == "__main__":
    main()