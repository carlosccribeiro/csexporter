#!/usr/bin/env python3
"""
Exporta as regras IOA do CrowdStrike para Excel.
Cada regra em uma linha,
coluna 1 = name (de rules),
coluna 2 = description,
coluna 3 = pattern_severity,
coluna 4 = action_label,
coluna 5 = ruletype_name,
coluna 6 = ImageFilename (valor de value de values),
coluna 7 = CommandLine (valor de value de values),
coluna 8 = ParentImageFilename (valor de value de values),
coluna 9 = ParentCommandLine (valor de value de values),
coluna 10 = GrandparentImageFilename (valor de value de values),
coluna 11 = GrandparentCommandLine (valor de value de values).
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

def fetch_rule_group_ids(token, base_url):
    url = f"{base_url}/ioarules/queries/rule-groups/v1"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"limit": 500}
    resp = requests.get(url, headers=headers, params=params)
    print(f"Resposta da API (rule group IDs): {resp.text}")  # Depuração
    if resp.status_code != 200:
        raise RuntimeError(f"Falha ao buscar IDs de grupos: {resp.status_code} - {resp.text}")
    try:
        data = resp.json()
        return data.get("resources", [])
    except ValueError:
        raise RuntimeError(f"Resposta da API inválida: {resp.text}")

def fetch_rule_details(token, base_url, rule_group_id):
    url = f"{base_url}/ioarules/entities/rule-groups/v1"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"ids": rule_group_id}
    resp = requests.get(url, headers=headers, params=params)
    print(f"Resposta da API (rule details for {rule_group_id}): {resp.text}")  # Depuração
    if resp.status_code != 200:
        raise RuntimeError(f"Falha ao buscar detalhes da regra: {resp.status_code} - {resp.text}")
    try:
        data = resp.json()
        return data.get("resources", [])
    except ValueError:
        raise RuntimeError(f"Resposta da API inválida: {resp.text}")

def transform_rules(rule_details):
    data = []
    for rule_group in rule_details:
        for rule in rule_group.get("rules", []):
            name = rule.get("name", "")
            description = rule.get("description", "")
            pattern_severity = rule.get("pattern_severity", "")
            action_label = rule.get("action_label", "")
            ruletype_name = rule.get("ruletype_name", "")

            # Extrair field_values
            field_values = rule.get("field_values", [])
            image_filename = next((fv.get("values", [{}])[0].get("value", "") for fv in field_values if fv.get("name") == "ImageFilename"), "")
            command_line = next((fv.get("values", [{}])[0].get("value", "") for fv in field_values if fv.get("name") == "CommandLine"), "")
            parent_image_filename = next((fv.get("values", [{}])[0].get("value", "") for fv in field_values if fv.get("name") == "ParentImageFilename"), "")
            parent_command_line = next((fv.get("values", [{}])[0].get("value", "") for fv in field_values if fv.get("name") == "ParentCommandLine"), "")
            grandparent_image_filename = next((fv.get("values", [{}])[0].get("value", "") for fv in field_values if fv.get("name") == "GrandparentImageFilename"), "")
            grandparent_command_line = next((fv.get("values", [{}])[0].get("value", "") for fv in field_values if fv.get("name") == "GrandparentCommandLine"), "")

            data.append([name, description, pattern_severity, action_label, ruletype_name, image_filename, command_line, parent_image_filename, parent_command_line, grandparent_image_filename, grandparent_command_line])

    df = pd.DataFrame(data, columns=["name", "description", "pattern_severity", "action_label", "ruletype_name", "ImageFilename", "CommandLine", "ParentImageFilename", "ParentCommandLine", "GrandparentImageFilename", "GrandparentCommandLine"])
    return df

def save_to_excel(df, outfile="crowdstrike_ioa_rules.xlsx"):
    if not outfile.lower().endswith(".xlsx"):
        outfile += ".xlsx"

    meta = pd.DataFrame([{
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_rules": len(df)
    }])

    with pd.ExcelWriter(outfile) as writer:
        df.to_excel(writer, sheet_name="IOARules", index=False)
        meta.to_excel(writer, sheet_name="Meta", index=False)

    print(f"✅ Exportado para {outfile} com {len(df)} regras")

def main():
    try:
        token, base_url, client_name = get_bearer_token()
        outfile = f"crowdstrike_ioa_rules_{client_name.replace(' ', '_')}.xlsx"
        rule_group_ids = fetch_rule_group_ids(token, base_url)
        all_rule_details = []
        for rule_group_id in rule_group_ids:
            rule_details = fetch_rule_details(token, base_url, rule_group_id)
            all_rule_details.extend(rule_details)
        df = transform_rules(all_rule_details)
        if not df.empty:
            save_to_excel(df, outfile)
        else:
            print("Nenhuma regra IOA encontrada.")
    except Exception as e:
        print(f"Erro ao executar o script: {e}")

if __name__ == "__main__":
    main()