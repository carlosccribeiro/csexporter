#!/usr/bin/env python3
"""
Exporta todas as exclusões criadas do CrowdStrike para Excel.
Cada tipo de exclusão = uma aba no Excel (ex.: Certificate Based Exclusion, ML Exclusion, IOA Exclusion, Sensor Visibility Exclusion),
colunas específicas por tipo, com created_by e created_timestamp nas penúltima e última colunas.
Lê credenciais do arquivo .env.
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

def fetch_ids(token, base_url, query_endpoint):
    url = f"{base_url}{query_endpoint}"
    headers = {"Authorization": f"Bearer {token}"}
    all_ids = []
    offset = 0
    limit = 100  # Ajustado para o máximo permitido

    while True:
        params = {"limit": limit, "offset": offset}
        resp = requests.get(url, headers=headers, params=params)
        print(f"Resposta da API (IDs for {query_endpoint}, offset {offset}): {resp.text}")  # Depuração
        if resp.status_code != 200:
            raise RuntimeError(f"Falha ao buscar IDs: {resp.status_code} - {resp.text}")
        try:
            data = resp.json()
            resources = data.get("resources", [])
            all_ids.extend(resources)
            if not resources or len(resources) < limit:  # Se não houver mais recursos, termina
                break
            offset += limit
        except ValueError:
            raise RuntimeError(f"Resposta da API inválida: {resp.text}")

    return all_ids

def fetch_details(token, base_url, details_endpoint, ids):
    url = f"{base_url}{details_endpoint}"
    headers = {"Authorization": f"Bearer {token}"}
    all_details = []
    
    # Processar IDs em lotes de 1 pra respeitar o limite de 32 caracteres por ID
    for id_val in ids:
        params = {"ids": id_val}  # Passa um ID por vez
        resp = requests.get(url, headers=headers, params=params)
        print(f"Resposta da API (details for {details_endpoint}, ID: {id_val}): {resp.text}")  # Depuração
        if resp.status_code != 200:
            print(f"Erro ao buscar detalhes para ID {id_val}: {resp.status_code} - {resp.text}")
            continue
        try:
            data = resp.json()
            resources = data.get("resources", [])
            all_details.extend(resources)
        except ValueError:
            print(f"Resposta da API inválida para ID {id_val}: {resp.text}")
            continue

    return all_details

def transform_certificate_exclusions(details):
    data = []
    for exclusion in details:
        issuer = exclusion.get("issuer", "")
        serial = exclusion.get("serial", "")
        created_by = exclusion.get("created_by", "")
        created_timestamp = exclusion.get("created_on", "")
        data.append([issuer, serial, created_by, created_timestamp])
    df = pd.DataFrame(data, columns=["issuer", "serial", "created_by", "created_timestamp"])
    return df

def transform_exclusions(details, type_name):
    data = []
    for exclusion in details:
        value = exclusion.get("value", "")  # Trata como string para ML e SV
        created_by = exclusion.get("created_by", "")
        created_timestamp = exclusion.get("created_on", "")
        data.append([value, created_by, created_timestamp])
    df = pd.DataFrame(data, columns=["value", "created_by", "created_timestamp"])
    return df

def transform_ioa_exclusions(details):
    data = []
    for exclusion in details:
        name = exclusion.get("name", "")
        ifn_regex = exclusion.get("ifn_regex", "")
        cl_regex = exclusion.get("cl_regex", "")
        created_by = exclusion.get("created_by", "")
        created_timestamp = exclusion.get("created_on", "")
        data.append([name, ifn_regex, cl_regex, created_by, created_timestamp])
    df = pd.DataFrame(data, columns=["name", "ifn_regex", "cl_regex", "created_by", "created_timestamp"])
    return df

def save_to_excel(per_type, outfile="crowdstrike_exclusions.xlsx"):
    if not outfile.lower().endswith(".xlsx"):
        outfile += ".xlsx"

    meta = pd.DataFrame([{
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tipos_exclusoes": ", ".join(per_type.keys()),
        "total_abas": len(per_type)
    }])

    with pd.ExcelWriter(outfile) as writer:
        for exclusion_type, df in per_type.items():
            sheet_name = exclusion_type if len(exclusion_type) <= 31 else exclusion_type[:31]
            df.to_excel(writer, sheet_name=sheet_name, index=False)
        meta.to_excel(writer, sheet_name="Meta", index=False)

    print(f"✅ Exportado para {outfile} com {len(per_type)} abas (tipos de exclusão)")

def main():
    try:
        token, base_url, client_name = get_bearer_token()
        outfile = f"crowdstrike_exclusions_{client_name.replace(' ', '_')}.xlsx"

        per_type = {}

        # 1 - Certificate Based Exclusion
        cert_ids = fetch_ids(token, base_url, "/exclusions/queries/cert-based-exclusions/v1")
        if cert_ids:
            cert_details = fetch_details(token, base_url, "/exclusions/entities/cert-based-exclusions/v1", cert_ids)
            per_type["Certificate Based Exclusion"] = transform_certificate_exclusions(cert_details)

        # 2 - ML Exclusion
        ml_ids = fetch_ids(token, base_url, "/policy/queries/ml-exclusions/v1")
        if ml_ids:
            ml_details = fetch_details(token, base_url, "/policy/entities/ml-exclusions/v1", ml_ids)
            per_type["ML Exclusion"] = transform_exclusions(ml_details, "ML Exclusion")

        # 3 - IOA Exclusion
        ioa_ids = fetch_ids(token, base_url, "/policy/queries/ioa-exclusions/v1")
        if ioa_ids:
            ioa_details = fetch_details(token, base_url, "/policy/entities/ioa-exclusions/v1", ioa_ids)
            per_type["IOA Exclusion"] = transform_ioa_exclusions(ioa_details)

        # 4 - Sensor Visibility Exclusion
        sv_ids = fetch_ids(token, base_url, "/policy/queries/sv-exclusions/v1")
        if sv_ids:
            sv_details = fetch_details(token, base_url, "/policy/entities/sv-exclusions/v1", sv_ids)
            per_type["Sensor Visibility Exclusion"] = transform_exclusions(sv_details, "Sensor Visibility Exclusion")

        if not per_type:
            print("Nenhuma exclusão encontrada.")
            return
        save_to_excel(per_type, outfile)
    except Exception as e:
        print(f"Erro ao executar o script: {e}")

if __name__ == "__main__":
    main()