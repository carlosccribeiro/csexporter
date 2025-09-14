#!/usr/bin/env python3
"""
Exporta a lista de host groups criados do CrowdStrike para Excel.
Coluna 1 = nome do host group (name),
coluna 2 = regra de atribuição (assignment_rule),
linha final = total geral de hosts instalados.
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

def fetch_host_groups(token, base_url):
    url = f"{base_url}/devices/combined/host-groups/v1"
    headers = {"Authorization": f"Bearer {token}"}
    all_resources = []
    offset = 0
    limit = 100  # Ajustado para valor válido (máximo 500)

    while True:
        params = {"limit": limit, "offset": offset}
        resp = requests.get(url, headers=headers, params=params)
        print(f"Resposta da API (host groups, offset {offset}): {resp.text}")  # Depuração
        if resp.status_code != 200:
            raise RuntimeError(f"Falha ao buscar host groups: {resp.status_code} - {resp.text}")
        try:
            data = resp.json()
            resources = data.get("resources", [])
            all_resources.extend(resources)
            pagination = data.get("meta", {}).get("pagination", {})
            total = pagination.get("total", 0)
            if offset + len(resources) >= total:
                break
            offset += limit
        except ValueError:
            raise RuntimeError(f"Resposta da API inválida: {resp.text}")

    return all_resources

def fetch_total_hosts(token, base_url):
    url = f"{base_url}/devices/combined/devices/v1"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"limit": 1}  # Apenas para obter o total
    resp = requests.get(url, headers=headers, params=params)
    print(f"Resposta da API (total hosts): {resp.text}")  # Depuração
    if resp.status_code != 200:
        raise RuntimeError(f"Falha ao buscar total de hosts: {resp.status_code} - {resp.text}")
    try:
        data = resp.json()
        return data.get("meta", {}).get("pagination", {}).get("total", 0)
    except ValueError:
        raise RuntimeError(f"Resposta da API inválida: {resp.text}")

def transform_host_groups(host_groups, total_hosts):
    data = []
    for group in host_groups:
        name = group.get("name", "Unnamed")
        assignment_rule = group.get("assignment_rule", "")
        data.append([name, assignment_rule])
    
    # Adicionar linha de total geral
    data.append(["Total Geral de Hosts Instalados", total_hosts])
    
    df = pd.DataFrame(data, columns=["Host Group", "Assignment Rule"])
    return df

def save_to_excel(df, outfile="crowdstrike_hostgroups.xlsx"):
    if not outfile.lower().endswith(".xlsx"):
        outfile += ".xlsx"

    meta = pd.DataFrame([{
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_host_groups": len(df) - 1,  # Exclui a linha de total geral
        "total_hosts_instalados": df.iloc[-1]["Assignment Rule"]
    }])

    with pd.ExcelWriter(outfile) as writer:
        df.to_excel(writer, sheet_name="HostGroups", index=False)
        meta.to_excel(writer, sheet_name="Meta", index=False)

    print(f"✅ Exportado para {outfile} com {len(df) - 1} host groups e total de hosts")

def main():
    try:
        token, base_url, client_name = get_bearer_token()
        outfile = f"crowdstrike_hostgroups_{client_name.replace(' ', '_')}.xlsx"
        host_groups = fetch_host_groups(token, base_url)
        total_hosts = fetch_total_hosts(token, base_url)
        df = transform_host_groups(host_groups, total_hosts)
        if not host_groups:
            print("Nenhum host group encontrado.")
            return
        save_to_excel(df, outfile)
    except Exception as e:
        print(f"Erro ao executar o script: {e}")

if __name__ == "__main__":
    main()