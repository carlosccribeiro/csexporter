#!/usr/bin/env python3
"""
Exporta políticas de resposta do CrowdStrike para Excel.
A primeira coluna = nomes dos motores (extraídos de settings.settings.name),
cada política = uma coluna com os valores de enabled (de value.enabled).
O nome da política é extraído do atributo name (abaixo de cid).
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

def fetch_policies(token, base_url):
    url = f"{base_url}/policy/combined/response/v1"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"limit": 5000}
    resp = requests.get(url, headers=headers, params=params)
    print(f"Resposta da API (status: {resp.status_code}): {resp.text}")  # Depuração
    if resp.status_code != 200:
        raise RuntimeError(f"Falha ao buscar políticas: {resp.status_code} - {resp.text}")
    try:
        data = resp.json()
        return data.get("resources", [])
    except ValueError:
        raise RuntimeError(f"Resposta da API inválida: {resp.text}")

def transform_policies(policies):
    """
    Retorna dict: {SO: DataFrame}, onde:
    - primeira coluna = nomes dos motores (de settings.settings.name)
    - colunas seguintes = políticas com valores de enabled (de value.enabled)
    - ignora plataformas Mobile e Meta
    """
    per_so_policy_configs = {}
    for pol in policies:
        so = pol.get("platform_name", "Unknown")
        if so in ["Mobile", "Meta"]:
            continue  # ignora plataformas Mobile e Meta

        if so not in per_so_policy_configs:
            per_so_policy_configs[so] = {}

        policy_name = pol.get("name", "Unnamed")  # Nome da política vem do atributo name
        settings = pol.get("settings", [])
        config_values = {}
        for setting_group in settings:
            for setting in setting_group.get("settings", []):
                motor_name = setting.get("name", "")
                enabled = setting.get("value", {}).get("enabled", False)
                if isinstance(enabled, dict):
                    enabled = enabled.get("enabled", False)
                config_values[motor_name] = "Enabled" if enabled else "Disabled"
        per_so_policy_configs[so][policy_name] = config_values

    # Criar DataFrame por SO
    per_os = {}
    for so, policy_configs in per_so_policy_configs.items():
        motors = set()
        for config_dict in policy_configs.values():
            motors.update(config_dict.keys())
        data = {policy_name: [config_dict.get(motor, "") for motor in motors] for policy_name, config_dict in policy_configs.items()}
        df = pd.DataFrame(data, index=list(motors))
        per_os[so] = df

    return per_os

def save_to_excel(per_os, outfile="crowdstrike_response_policies.xlsx"):
    if not outfile.lower().endswith(".xlsx"):
        outfile += ".xlsx"

    meta = pd.DataFrame([{
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sistemas_operacionais": ", ".join(per_os.keys()),
        "total_abas": len(per_os)
    }])

    with pd.ExcelWriter(outfile) as writer:
        for so, df in per_os.items():
            sheet_name = so if len(so) <= 31 else so[:31]
            df.to_excel(writer, sheet_name=sheet_name, index=True)
        meta.to_excel(writer, sheet_name="Meta", index=False)

    print(f"✅ Exportado para {outfile} com {len(per_os)} abas (SO)")

def main():
    try:
        token, base_url, client_name = get_bearer_token()
        outfile = f"crowdstrike_response_policies_{client_name.replace(' ', '_')}.xlsx"
        policies = fetch_policies(token, base_url)
        per_os = transform_policies(policies)
        if not per_os:
            print("Nenhuma política de resposta encontrada com configuração disponível.")
            return
        save_to_excel(per_os, outfile)
    except Exception as e:
        print(f"Erro ao executar o script: {e}")

if __name__ == "__main__":
    main()