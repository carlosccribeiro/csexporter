#!/usr/bin/env python3
"""
Exporta políticas de controle de USB do CrowdStrike para Excel.
Coluna 1 = nome do motor/configuração,
colunas 2 em diante = cada política encontrada.
Primeira linha = enforcement_mode,
segunda linha = end_user_notification,
terceira linha em diante = motores de classes (id) com ação (action).
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
    url = f"{base_url}/policy/combined/device-control/v1"
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
    - coluna 1 = nome do motor/configuração (enforcement_mode, end_user_notification, classes.id)
    - colunas 2 em diante = políticas com valores de configuração (action ou valor do atributo)
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
        settings = pol.get("settings", {})
        config_values = {}

        # Primeira linha: enforcement_mode (valor direto do atributo)
        enforcement_mode = settings.get("enforcement_mode", "")
        config_values["enforcement_mode"] = str(enforcement_mode) if enforcement_mode else ""

        # Segunda linha: end_user_notification (valor direto do atributo)
        end_user_notification = settings.get("end_user_notification", "")
        config_values["end_user_notification"] = str(end_user_notification) if end_user_notification else ""

        # Terceira linha em diante: classes (id como motor, action como valor)
        classes = settings.get("classes", [])
        for cls in classes:
            motor_id = cls.get("id", "")
            action = cls.get("action", "")
            if motor_id and action:
                config_values[motor_id] = action

        per_so_policy_configs[so][policy_name] = config_values

    # Criar DataFrame por SO
    per_os = {}
    for so, policy_configs in per_so_policy_configs.items():
        configs = ["enforcement_mode", "end_user_notification"]
        for config_dict in policy_configs.values():
            configs.extend([k for k in config_dict.keys() if k not in configs])
        data = {policy_name: [config_dict.get(config, "") for config in configs] for policy_name, config_dict in policy_configs.items()}
        df = pd.DataFrame(data, index=configs)
        per_os[so] = df

    return per_os

def save_to_excel(per_os, outfile="crowdstrike_usb_policies.xlsx"):
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
        outfile = f"crowdstrike_usb_policies_{client_name.replace(' ', '_')}.xlsx"
        policies = fetch_policies(token, base_url)
        per_os = transform_policies(policies)
        if not per_os:
            print("Nenhuma política de USB encontrada com configuração disponível.")
            return
        save_to_excel(per_os, outfile)
    except Exception as e:
        print(f"Erro ao executar o script: {e}")

if __name__ == "__main__":
    main()