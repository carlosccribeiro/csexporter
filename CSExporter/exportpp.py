#!/usr/bin/env python3
"""
Exporta políticas de prevenção do CrowdStrike para Excel.
Cada aba = SO, cada coluna = política, cada linha = motor (name dentro de settings).
Valores = ON/OFF ou detection/prevention, sem 'enabled:' ou 'configured:'.
Motores com detection/prevention são divididos em duas linhas: (Detection) e (Prevention).
Remove a linha 'Extended User Mode Data (Prevention)' da saída.
Inclui coluna 'Recomended' após 'Motor/Configuração' com valores sugeridos por SO.
Inclui linha 'Host Count' com o número de hosts por política (exceto na coluna Recomended).
Carrega FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_BASE_URL e CLIENT_NAME do .env.
O nome do cliente é adicionado ao nome do arquivo exportado.
"""

import os
import pandas as pd
from datetime import datetime, timezone
import requests
from dotenv import load_dotenv

# Carrega variáveis do .env
load_dotenv()

def get_bearer_token():
    client_id = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")
    base_url = os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com")
    client_name = os.getenv("CLIENT_NAME") or input("Digite o nome do cliente: ")

    if not client_id or not client_secret:
        raise RuntimeError("FALCON_CLIENT_ID e FALCON_CLIENT_SECRET devem estar definidos no arquivo .env")

    auth_url = f"{base_url}/oauth2/token"

    data = {"client_id": client_id, "client_secret": client_secret, "grant_type": "client_credentials"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(auth_url, data=data, headers=headers)
    if resp.status_code != 201:
        raise RuntimeError(f"Falha na autenticação: {resp.status_code} {resp.text}")
    return resp.json()["access_token"], base_url, client_name

def fetch_policies(token, base_url):
    # Busca políticas de prevenção
    url = f"{base_url}/policy/combined/prevention/v1"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"limit": 5000}
    resp = requests.get(url, headers=headers, params=params)
    if resp.status_code != 200:
        raise RuntimeError(f"Falha ao buscar políticas: {resp.status_code} {resp.text}")
    policies = resp.json().get("resources", [])

    # Busca hosts e suas políticas de prevenção
    url = f"{base_url}/policy/combined/prevention-members/v1"
    host_counts = {}
    resp = requests.get(url, headers=headers, params={"limit": 5000})
    if resp.status_code != 200:
        print(f"Aviso: Falha ao buscar hosts: {resp.status_code} {resp.text}")
        return policies, host_counts

    hosts = resp.json().get("resources", [])
    for host in hosts:
        prevention_policy = host.get("device_policies", {}).get("prevention", {})
        policy_id = prevention_policy.get("policy_id")
        if policy_id:
            # Encontrar o nome da política correspondente ao policy_id
            for policy in policies:
                if policy.get("id") == policy_id:
                    pol_name = policy.get("name", policy_id)
                    host_counts[pol_name] = host_counts.get(pol_name, 0) + 1
                    break

    return policies, host_counts

def transform_policies(policies, host_counts):
    """
    Retorna dict: {SO: DataFrame}, onde:
    - linhas = motores (name dentro de settings) + 'Host Count'
    - colunas = políticas
    - valores = ON/OFF ou valores de detection/prevention
    - ignora políticas Mobile e Meta
    - motores com detection/prevention são divididos em duas linhas
    - remove 'Extended User Mode Data (Prevention)' da saída
    - adiciona coluna 'Recomended' com valores sugeridos
    - adiciona linha 'Host Count' com contagem de hosts por política (exceto Recomended)
    """
    # Valores recomendados por SO
    recommended = {
        "Windows": {
            "Notify End Users": "ON",
            "Unknown Detection-Related Executables": "ON",
            "Unknown Executables": "ON",
            "Sensor Tampering Protection": "ON",
            "Additional User Mode Data": "ON",
            "Interpreter-Only": "ON",
            "Engine (Full Visibility)": "ON",
            "Script-Based Execution Monitoring": "ON",
            "HTTP Detections": "ON",
            "Redact HTTP Detection Details": "ON",
            "Hardware-Enhanced Exploit Detection": "ON",
            "Enhanced Exploitation Visibility": "ON",
            "Extended User Mode Data (Detection)": "MODERATE",
            "Enhanced DLL Load Visibility": "OFF",
            "WSL2 Visibility": "OFF",
            "Memory Scanning": "ON",
            "Scan with CPU": "ON",
            "BIOS Deep Visibility": "ON",
            "Cloud Anti-malware (Detection)": "AGGRESSIVE",
            "Cloud Anti-malware (Prevention)": "AGGRESSIVE",
            "Adware & PUP (Detection)": "AGGRESSIVE",
            "Adware & PUP (Prevention)": "AGGRESSIVE",
            "Sensor Anti-malware (Detection)": "AGGRESSIVE",
            "Sensor Anti-malware (Prevention)": "AGGRESSIVE",
            "Enhanced ML for larger files": "ON",
            "Sensor Anti-malware for End-User Initiated Scans (Detection)": "AGGRESSIVE",
            "Sensor Anti-malware for End-User Initiated Scans (Prevention)": "AGGRESSIVE",
            "Cloud Anti-malware for End-User Initiated Scans (Detection)": "AGGRESSIVE",
            "Cloud Anti-malware for End-User Initiated Scans (Prevention)": "AGGRESSIVE",
            "Cloud PUP/Adware for End-User Initiated Scans (Detection)": "DISABLED",
            "Cloud PUP/Adware for End-User Initiated Scans (Prevention)": "DISABLED",
            "USB Insertion Triggered Scan": "ON",
            "Detect on Write": "ON",
            "Quarantine on Write": "ON",
            "On Write Script File Visibility": "ON",
            "Quarantine & Security Center Registration": "ON",
            "Quarantine on Removable Media": "ON",
            "Cloud Anti-malware For Microsoft Office Files (Detection)": "AGGRESSIVE",
            "Cloud Anti-malware For Microsoft Office Files (Prevention)": "AGGRESSIVE",
            "Microsoft Office File Malicious Macro Removal": "ON",
            "Custom Blocking": "ON",
            "Suspicious Processes": "ON",
            "Suspicious Registry Operations": "ON",
            "Boot Configuration Database Protection": "OFF",
            "File System Containment": "OFF",
            "Suspicious Scripts and Commands": "ON",
            "Intelligence-Sourced Threats": "ON",
            "Driver Load Prevention": "ON",
            "Vulnerable Driver Protection": "ON",
            "Force ASLR": "ON",
            "Force DEP": "OFF",
            "Heap Spray Preallocation": "ON",
            "NULL Page Allocation": "ON",
            "SEH Overwrite Protection": "ON",
            "Backup Deletion": "ON",
            "Cryptowall": "ON",
            "File Encryption": "ON",
            "Locky": "ON",
            "File System Access": "ON",
            "Volume Shadow Copy - Audit": "ON",
            "Volume Shadow Copy - Protect": "ON",
            "Application Exploitation Activity": "ON",
            "Chopper Webshell": "ON",
            "Drive-by Download": "ON",
            "Code Injection": "ON",
            "JavaScript Execution Via Rundll32": "ON",
            "Windows Logon Bypass (\"Sticky Keys\")": "ON",
            "Credential Dumping": "ON",
            "Advanced Remediation": "ON"
        },
        "Linux": {
            "Unknown Detection-Related Executables": "ON",
            "Unknown Executables": "ON",
            "Sensor Tampering Protection": "ON",
            "Script-Based Execution Monitoring": "ON",
            "Filesystem Visibility": "ON",
            "Network Visibility": "ON",
            "Http Visibility": "ON",
            "FTP Visibility": "ON",
            "TLS Visibility": "ON",
            "Extended Command Line Visibility": "ON",
            "Email Protocol Visibility": "ON",
            "Memory Visibility": "ON",
            "D-Bus Visibility": "ON",
            "Enhance PHP Visibility": "ON",
            "Cloud Anti-malware (Detection)": "AGGRESSIVE",
            "Cloud Anti-malware (Prevention)": "AGGRESSIVE",
            "Sensor Anti-malware (Detection)": "AGGRESSIVE",
            "Sensor Anti-malware (Prevention)": "AGGRESSIVE",
            "Quarantine": "ON",
            "On Write Script File Visibility": "ON",
            "Custom Blocking": "ON",
            "Suspicious Processes": "ON",
            "Drift Prevention": "ON"
        },
        "Mac": {
            "Notify End Users": "ON",
            "Unknown Detection-Related Executables": "ON",
            "Sensor Tampering Protection": "ON",
            "Unknown Executables": "ON",
            "Script-Based Execution Monitoring": "ON",
            "Cloud Anti-malware (Detection)": "AGGRESSIVE",
            "Cloud Anti-malware (Prevention)": "AGGRESSIVE",
            "Adware & PUP (Detection)": "AGGRESSIVE",
            "Adware & PUP (Prevention)": "AGGRESSIVE",
            "Sensor Anti-malware (Detection)": "AGGRESSIVE",
            "Sensor Anti-malware (Prevention)": "AGGRESSIVE",
            "Quarantine": "ON",
            "Detect on Write": "ON",
            "Quarantine on Write": "ON",
            "Custom Blocking": "ON",
            "Suspicious Processes": "ON",
            "Intelligence-Sourced Threats": "ON",
            "XPCOM Shell": "ON",
            "Chopper Webshell": "ON",
            "Empyre Backdoor": "ON",
            "KcPassword Decoded": "ON",
            "Hash Collector": "ON"
        }
    }

    per_os = {}
    for pol in policies:
        so = pol.get("platform_name", "Unknown")
        if so in ["Mobile", "Meta"]:
            continue  # ignora plataformas Mobile e Meta

        pol_name = pol.get("name", pol.get("id"))
        prevention_settings = pol.get("prevention_settings", [])
        if so not in per_os:
            per_os[so] = {}
        for ps in prevention_settings:
            settings_list = ps.get("settings", [])
            for s in settings_list:
                motor_name = s.get("name")
                value = s.get("value")
                if isinstance(value, dict):
                    value_str = "/".join(f"{k}:{v}" for k, v in value.items())
                else:
                    value_str = str(value)  # True/False

                # Substituir 'enabled:True' por 'True' e 'enabled:False' por 'False'
                if "enabled:True" in value_str:
                    value_str = value_str.replace("enabled:True", "True")
                if "enabled:False" in value_str:
                    value_str = value_str.replace("enabled:False", "False")
                # Substituir 'configured:True/True' por 'True' e 'configured:False/False' por 'False'
                if "configured:True/True" in value_str:
                    value_str = value_str.replace("configured:True/True", "True")
                if "configured:False/False" in value_str:
                    value_str = value_str.replace("configured:False/False", "False")
                # Substituir 'configured:True' por 'True' e 'configured:False' por 'False'
                if "configured:True" in value_str:
                    value_str = value_str.replace("configured:True", "True")
                if "configured:False" in value_str:
                    value_str = value_str.replace("configured:False", "False")

                # Dividir valores com detection/prevention em duas linhas
                if "detection:" in value_str and "prevention:" in value_str:
                    parts = value_str.split("/")
                    detection_value = next((part.split(":")[1] for part in parts if part.startswith("detection:")), "")
                    prevention_value = next((part.split(":")[1] for part in parts if part.startswith("prevention:")), "")
                    if detection_value:
                        detection_motor = f"{motor_name} (Detection)"
                        if detection_motor not in per_os[so]:
                            per_os[so][detection_motor] = {}
                        per_os[so][detection_motor][pol_name] = detection_value
                    if prevention_value:
                        prevention_motor = f"{motor_name} (Prevention)"
                        # Ignorar 'Extended User Mode Data (Prevention)'
                        if prevention_motor == "Extended User Mode Data (Prevention)":
                            continue
                        if prevention_motor not in per_os[so]:
                            per_os[so][prevention_motor] = {}
                        per_os[so][prevention_motor][pol_name] = prevention_value
                else:
                    if motor_name not in per_os[so]:
                        per_os[so][motor_name] = {}
                    per_os[so][motor_name][pol_name] = value_str

        # Adicionar contagem de hosts para esta política
        if pol_name in host_counts:
            if "Host Count" not in per_os[so]:
                per_os[so]["Host Count"] = {}
            per_os[so]["Host Count"][pol_name] = str(host_counts[pol_name])

    # Transformar dict em DataFrame e adicionar coluna Recomended
    result = {}
    for so, motors in per_os.items():
        df = pd.DataFrame.from_dict(motors, orient="index").reset_index()
        df.rename(columns={"index": "Motor/Configuração"}, inplace=True)
        # Adicionar coluna Recomended como segunda coluna
        recommended_values = [recommended.get(so, {}).get(motor, "") for motor in df["Motor/Configuração"]]
        df.insert(1, "Recomended", recommended_values)
        # Substituir True por ON e False por OFF em todas as colunas exceto as primeiras duas
        for col in df.columns[2:]:
            df[col] = df[col].replace({"True": "ON", "False": "OFF"})
        result[so] = df
    return result

def save_to_excel(per_os, outfile="crowdstrike_policies.xlsx"):
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
            df.to_excel(writer, sheet_name=sheet_name, index=False)
        meta.to_excel(writer, sheet_name="Meta", index=False)

    print(f"✅ Exportado para {outfile} com {len(per_os)} abas (SO)")

def main():
    try:
        token, base_url, client_name = get_bearer_token()
        outfile = f"crowdstrike_policies_{client_name.replace(' ', '_')}.xlsx"  # Substitui espaços por underscores
        policies, host_counts = fetch_policies(token, base_url)
        per_os = transform_policies(policies, host_counts)
        if not per_os:
            print("Nenhuma política encontrada com configuração disponível.")
            return
        save_to_excel(per_os, outfile)
    except Exception as e:
        print(f"Erro ao executar o script: {e}")

if __name__ == "__main__":
    main()